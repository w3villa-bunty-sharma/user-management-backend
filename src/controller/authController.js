const bcrypt = require('bcrypt');
const {pool} = require('../config/db');
const jwt = require('jsonwebtoken');

// SIGNUP
const signup = async (req, res) => {
  const { name, email, password } = req.body;

  // password ko scramble karo
  const hash = await bcrypt.hash(password, 10);

  // database me save karo
  await pool.query(
    'INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3)',
    [name, email, hash]
  );

  res.json({ message: 'Signup successful' });
};

// LOGIN
const login = async (req, res) => {
  const { email, password } = req.body;

  // email se user dhundo
  const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  const user = result.rows[0];

  if (!user) {
    return res.status(401).json({ message: 'User not found' });
  }

  // password match karo
  const isMatch = await bcrypt.compare(password, user.password_hash);

  if (!isMatch) {
    return res.status(401).json({ message: 'Password incorrect' });
  }

  // JWT token generate 
  const token = jwt.sign(
    { id: user.id, name: user.name },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '1d' }
  );

  res.json({ message: 'Login successful', token, user: { id: user.id, name: user.name } });
};



const getMe = async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, email, is_email_verified, created_at
       FROM users
       WHERE id = $1`,
      [req.user.id]
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


module.exports = { signup, login , getMe };