require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const { pool, connectDB } = require("./config/db"); 
const authRoutes = require("./routes/authRoutes");

const app = express();

// Middleware
app.use(helmet());
app.use(cors({ origin: "http://localhost:5173" }));
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

// Start server
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});