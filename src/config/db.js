
require("dotenv").config();

const { Pool } = require("pg");
const pool = new Pool({
  host: process.env.DB_HOST || "localhost",
  port: Number(process.env.DB_PORT) || 5432,
  database: process.env.DB_NAME || "user_management_db",
  user: process.env.DB_USER || "user_management",
  password: process.env.DB_PASSWORD,
});

pool.on("error", (error) => {
  console.error("PostgreSQL error:", error.message);
});

const connectDB = async () => {
  try {
    const result = await pool.query("SELECT NOW() AS server_time");
    console.log("Database connected at:", result.rows[0].server_time);
  } catch (error) {
    console.error("Database connection failed:", error.message);
    process.exit(1); // stop the app, because it can't work without the database
  }
};

connectDB();

module.exports = { pool, connectDB };
