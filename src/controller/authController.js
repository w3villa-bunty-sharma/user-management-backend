const bcrypt = require("bcrypt");
const { pool } = require("../config/db");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const transporter = require("../config/email");

// SIGNUP
const signup = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "Name, email and password are required",
      });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        message: "Please enter a valid email address",
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 8 characters long",
      });
    }

    if (typeof name !== "string" || !name.trim()) {
      return res.status(400).json({
        success: false,
        message: "Please enter a valid name",
      });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const normalizedName = name.trim();

    // password ko scramble karo
    const hash = await bcrypt.hash(password, 10);

    // Generate secure verification token
    const verificationToken = crypto.randomBytes(32).toString("hex");

    const verificationTokenHash = crypto
      .createHash("sha256")
      .update(verificationToken)
      .digest("hex");

    const verificationTokenExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);

    // Save the user and verification token in the database
    await pool.query(
      `INSERT INTO users
   (name, email, password_hash, email_verification_token_hash, email_verification_expires_at)
   VALUES ($1, $2, $3, $4, $5)`,
      [
        normalizedName,
        normalizedEmail,
        hash,
        verificationTokenHash,
        verificationTokenExpiry,
      ],
    );

    // Create the email verification link
    const verificationLink = `http://localhost:5000/api/auth/verify-email?token=${verificationToken}`;

    // Send the verification email
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: normalizedEmail,
      subject: "Verify Your Email Address",
      html: `
    <h2>Welcome to User Management!</h2>
    <p>Please click the link below to verify your email address:</p>
    <a href="${verificationLink}">Verify Email</a>
    <p>This link will expire in 24 hours.</p>
  `,
    });

    return res.status(201).json({
      success: true,
      message: "Signup successful. Please check your email for verification.",
    });
  } catch (error) {
    console.error("Signup error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Signup failed. Please try again.",
    });
  }
};

// VERIFY EMAIL
const verifyEmail = async (req, res) => {
  try {
    const { token } = req.query;

    if (!token) {
      return res.status(400).json({
        success: false,
        message: "Verification token is required",
      });
    }

    // Generate hash from the received token
    const verificationTokenHash = crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");

    // Find the user with a valid verification token
    const result = await pool.query(
      `SELECT id FROM users
       WHERE email_verification_token_hash = $1
       AND email_verification_expires_at > NOW()`,
      [verificationTokenHash],
    );

    if (result.rows.length === 0) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired verification link",
      });
    }

    // Mark the user's email as verified
    await pool.query(
      `UPDATE users
       SET is_email_verified = TRUE,
           email_verification_token_hash = NULL,
           email_verification_expires_at = NULL
       WHERE id = $1`,
      [result.rows[0].id],
    );

    return res.status(200).json({
      success: true,
      message: "Email verified successfully",
    });
  } catch (error) {
    console.error("Email verification error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

// LOGIN
const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required",
      });
    }

    if (typeof password !== "string") {
      return res.status(400).json({
        success: false,
        message: "Password must be a valid string",
      });
    }

    if (!password.trim()) {
      return res.status(400).json({
        success: false,
        message: "Password cannot be empty",
      });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (typeof email !== "string" || !emailRegex.test(email.trim())) {
      return res.status(400).json({
        success: false,
        message: "Please enter a valid email address",
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    // search the user in the database with the provided email
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [
      normalizedEmail,
    ]);
    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "User not found",
      });
    }

    // password matched
    const isMatch = await bcrypt.compare(password, user.password_hash);

    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: "Password incorrect",
      });
    }

    // Check whether the user's email is verified
    if (!user.is_email_verified) {
      return res.status(403).json({
        success: false,
        message: "Please verify your email before logging in",
      });
    }

    // JWT token generate
    const token = jwt.sign(
      {
        id: user.id,
        name: user.name,
        role: user.role,
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || "1d" },
    );

    res.json({
      success: true,
      message: "Login successful",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error("Login error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Login failed. Please try again.",
    });
  }
};

const getMe = async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, email, role, is_email_verified, created_at
        FROM users
        WHERE id = $1`,
      [req.user.id],
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    return res.status(200).json({
      success: true,
      user: result.rows[0],
    });
  } catch (error) {
    console.error("Get profile error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

module.exports = { signup, verifyEmail, login, getMe };
