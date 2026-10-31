require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const { pool, connectDB } = require("./config/db"); 
const authRoutes = require("./routes/authRoutes");
const adminMiddleware = require("./middleware/adminMiddleware");
const authMiddleware = require("./middleware/authMiddleware");

const app = express();

// Middleware
app.use(helmet());
app.use(
  cors({
    origin: [
      "http://localhost:3000",
      "http://127.0.0.1:3000",
      "http://localhost:5173",
    ],
  }),
);
app.use(express.json());

// Routes
app.use("/api/auth", authRoutes);

// Check whether the server is running
app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    message: "User Management API is running",
  });
});

app.get(
  "/api/admin/dashboard",
  authMiddleware,
  adminMiddleware,
  (req, res) => {
    res.json({
      success: true,
      message: "Welcome to Admin Dashboard",
      user: req.user,
    });
  }
);

// Start server
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});