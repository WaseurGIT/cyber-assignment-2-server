const express = require("express");
const cors = require("cors");
const port = process.env.PORT || 5000;
const dotenv = require("dotenv");
dotenv.config();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const app = express();
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

const MIN_PASSWORD_LENGTH = 8;
const MAX_LOGIN_ATTEMPTS = 3;
const LOCK_TIME_MS = 15 * 60 * 1000; // 15 minutes
const OTP_EXPIRY_MS = 10 * 60 * 1000; // 10 minutes
const RESET_TOKEN_EXPIRY_MS = 60 * 60 * 1000; // 1 hour

function isStrongPassword(password) {
  return (
    typeof password === "string" &&
    password.length >= MIN_PASSWORD_LENGTH &&
    /[a-z]/.test(password) &&
    /[A-Z]/.test(password) &&
    /\d/.test(password) &&
    /[@$!%*?&]/.test(password)
  );
}

function hashText(text) {
  return crypto.createHash("sha256").update(text).digest("hex");
}

function generateOtp() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function getDeviceFingerprint(req) {
  const userAgent = req.headers["user-agent"] || "unknown";
  const acceptLanguage = req.headers["accept-language"] || "unknown";
  return hashText(`${userAgent}|${acceptLanguage}`);
}

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

async function sendMail(to, subject, html) {
  return transporter.sendMail({
    from: process.env.EMAIL_USER,
    to,
    subject,
    html,
  });
}

// Middleware
app.use(cookieParser());
app.use(
  cors({
    origin: ["http://localhost:5173"],
    credentials: true,
  }),
);
app.use(express.json());

const uri = `mongodb+srv://${process.env.DB_USERNAME}:${process.env.DB_PASSWORD}@cluster0.febqytm.mongodb.net/?appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const verifyToken = (req, res, next) => {
  const token =
    req.cookies.access_token || req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ message: "No token provided" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "Invalid token" });
    }
    req.user = decoded;
    next();
  });
};

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();

    const usersCollection = client
      .db("cyber-assignment-2")
      .collection("users");

    app.get("/me", verifyToken, async (req, res) => {
      const user = await usersCollection.findOne({ email: req.user.email });
      res.json({ id: user._id, email: user.email, name: user.name });
    });

    app.post("/forget-password", async (req, res) => {
      try {
        const { email } = req.body;

        if (!email) {
          return res.status(400).json({ message: "Email is required" });
        }

        const user = await usersCollection.findOne({ email });
        if (!user) {
          return res.status(400).json({ message: "User not found" });
        }

        const resetToken = crypto.randomBytes(32).toString("hex");
        const resetTokenHash = hashText(resetToken);

        await usersCollection.updateOne(
          { _id: user._id },
          {
            $set: {
              resetToken: resetTokenHash,
              resetTokenExpiry: Date.now() + RESET_TOKEN_EXPIRY_MS,
            },
          },
        );

        const resetUrl = `http://localhost:5173/reset-password/${resetToken}`;

        await sendMail(
          email,
          "Password Reset",
          `
        <p>Click the link below to reset your password:</p>
        <a href="${resetUrl}">${resetUrl}</a>
        <p>This link expires in 1 hour.</p>
      `,
        );

        res.json({ message: "Reset link sent to email" });
      } catch (error) {
        res
          .status(500)
          .json({ message: "Error sending reset link", error: error.message });
      }
    });

    app.post("/reset-password/:token", async (req, res) => {
      try {
        const { token } = req.params;
        const { password, confirmPassword } = req.body;

        if (!password || !confirmPassword) {
          return res.status(400).json({ message: "All fields are required" });
        }

        if (password !== confirmPassword) {
          return res.status(400).json({ message: "Passwords do not match" });
        }

        if (!isStrongPassword(password)) {
          return res.status(400).json({
            message:
              "Password must be at least 8 characters and include uppercase, lowercase, number, and special character.",
          });
        }

        const resetTokenHash = hashText(token);

        const user = await usersCollection.findOne({
          resetToken: resetTokenHash,
          resetTokenExpiry: { $gt: Date.now() },
        });

        if (!user) {
          return res
            .status(400)
            .json({ message: "Invalid or expired reset token" });
        }

        const hashedPassword = await bcrypt.hash(password, 12);

        await usersCollection.updateOne(
          { _id: user._id },
          {
            $set: {
              password: hashedPassword,
              resetToken: null,
              resetTokenExpiry: null,
              failedLoginAttempts: 0,
              lockUntil: null,
              passwordChangedAt: new Date(),
            },
          },
        );

        res.json({ message: "Password reset successfully" });
      } catch (error) {
        res
          .status(500)
          .json({ message: "Error resetting password", error: error.message });
      }
    });

    app.post("/users", async (req, res) => {
      try {
        const { name, email, password, confirmPassword } = req.body;

        if (!name || !email || !password || !confirmPassword) {
          return res.status(400).json({ message: "All fields are required" });
        }

        if (password !== confirmPassword) {
          return res.status(400).json({ message: "Passwords do not match" });
        }

        if (!isStrongPassword(password)) {
          return res.status(400).json({
            message:
              "Password must be at least 8 characters and include uppercase, lowercase, number, and special character.",
          });
        }

        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) {
          return res.status(400).json({ message: "User already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 12);

        const newUser = {
          name,
          email,
          password: hashedPassword,
          createdAt: new Date(),
          failedLoginAttempts: 0,
          lockUntil: null,
          resetToken: null,
          resetTokenExpiry: null,
          loginOtpHash: null,
          loginOtpExpiry: null,
          pendingDeviceFingerprint: null,
          knownDevices: [],
        };

        const result = await usersCollection.insertOne(newUser);

        res.status(201).json({
          message: "User created successfully",
          user: { id: result.insertedId, email, name },
        });
      } catch (error) {
        res
          .status(500)
          .json({ message: "Error creating user", error: error.message });
      }
    });

    app.post("/login", async (req, res) => {
      try {
        const { email, password } = req.body;

        if (!email || !password) {
          return res
            .status(400)
            .json({ message: "Email and password required" });
        }

        const user = await usersCollection.findOne({ email });
        if (!user) {
          return res.status(400).json({ message: "Invalid email or password" });
        }

        if (user.lockUntil && user.lockUntil > Date.now()) {
          const remainingMinutes = Math.ceil(
            (user.lockUntil - Date.now()) / 60000,
          );
          return res.status(423).json({
            message: `Account locked. Try again after ${remainingMinutes} minute(s).`,
          });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
          const failedAttempts = (user.failedLoginAttempts || 0) + 1;

          const updateData = {
            failedLoginAttempts: failedAttempts,
          };

          if (failedAttempts >= MAX_LOGIN_ATTEMPTS) {
            updateData.lockUntil = Date.now() + LOCK_TIME_MS;
            updateData.failedLoginAttempts = 0;
          }

          await usersCollection.updateOne(
            { _id: user._id },
            { $set: updateData },
          );

          if (failedAttempts >= MAX_LOGIN_ATTEMPTS) {
            return res.status(423).json({
              message:
                "Too many failed attempts. Account locked for 15 minutes.",
            });
          }

          return res.status(400).json({ message: "Invalid email or password" });
        }

        const deviceFingerprint = getDeviceFingerprint(req);
        const knownDevices = user.knownDevices || [];
        const isNewDevice = !knownDevices.includes(deviceFingerprint);

        const otp = generateOtp();
        const otpHash = hashText(otp);

        await usersCollection.updateOne(
          { _id: user._id },
          {
            $set: {
              failedLoginAttempts: 0,
              lockUntil: null,
              loginOtpHash: otpHash,
              loginOtpExpiry: Date.now() + OTP_EXPIRY_MS,
              pendingDeviceFingerprint: deviceFingerprint,
            },
          },
        );

        await sendMail(
          user.email,
          "Your login verification code",
          `
        <p>Your 2FA code is:</p>
        <h2>${otp}</h2>
        <p>This code will expire in 10 minutes.</p>
      `,
        );

        if (isNewDevice) {
          await sendMail(
            user.email,
            "New device login detected",
            `
          <p>A new device/browser tried to log in to your account.</p>
          <p>If this was not you, change your password immediately.</p>
          <p>User-Agent: ${req.headers["user-agent"] || "unknown"}</p>
        `,
          );
        }

        return res.json({
          requiresTwoFactor: true,
          email: user.email,
          message: "Verification code sent to your email",
        });
      } catch (error) {
        res
          .status(500)
          .json({ message: "Error logging in", error: error.message });
      }
    });

    app.post("/logout", (req, res) => {
      res.clearCookie("access_token", {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
      });
      res.json({ message: "Logged out" });
    });

    app.post("/verify-2fa", async (req, res) => {
      try {
        const { email, otp } = req.body;

        if (!email || !otp) {
          return res
            .status(400)
            .json({ message: "Email and OTP are required" });
        }

        const user = await usersCollection.findOne({ email });
        if (!user) {
          return res
            .status(400)
            .json({ message: "Invalid verification request" });
        }

        if (!user.loginOtpHash || !user.loginOtpExpiry) {
          return res
            .status(400)
            .json({ message: "No active verification code" });
        }

        if (user.loginOtpExpiry < Date.now()) {
          return res.status(400).json({ message: "Verification code expired" });
        }

        if (hashText(otp) !== user.loginOtpHash) {
          return res.status(400).json({ message: "Invalid verification code" });
        }

        const deviceFingerprint = user.pendingDeviceFingerprint;
        const knownDevices = user.knownDevices || [];
        const updatedDevices = knownDevices.includes(deviceFingerprint)
          ? knownDevices
          : [...knownDevices, deviceFingerprint];

        await usersCollection.updateOne(
          { _id: user._id },
          {
            $set: {
              loginOtpHash: null,
              loginOtpExpiry: null,
              pendingDeviceFingerprint: null,
              knownDevices: updatedDevices,
              lastLoginAt: new Date(),
            },
          },
        );

        const token = jwt.sign(
          { userId: user._id, email: user.email },
          process.env.JWT_SECRET,
          {
            expiresIn: "1h",
          },
        );

        res.cookie("access_token", token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "lax",
          maxAge: 3600000,
        });

        return res.json({
          user: { id: user._id, email: user.email, name: user.name },
          message: "Login successful",
        });
      } catch (error) {
        res
          .status(500)
          .json({ message: "Error verifying code", error: error.message });
      }
    });

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!",
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send(`Cyber Security Assignment Backend is running on port ${port}`);
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});