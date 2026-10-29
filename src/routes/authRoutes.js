const express = require('express');
const router = express.Router();
const { signup, login, getMe } = require('../controller/authController');
const authMiddleware = require('../middleware/authMiddleware');


router.post('/signup', signup);
router.post('/login', login);
router.get('/me',authMiddleware, getMe);

module.exports = router;
