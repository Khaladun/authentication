// routes/auth.js
const express = require('express');
const {
  register, verifyOTP, login, logout, forgotPassword, resetPassword,
  getProfile, updateProfile, changePassword
} = require('../controllers/authController');
const auth = require('../middleware/auth');

const router = express.Router();

// Public Routes
router.post('/register', register);
router.post('/verify-otp', verifyOTP);
router.post('/login', login);
router.post('/forgot-password', forgotPassword);
router.post('/reset-password/:token', resetPassword);

// Protected Routes
router.post('/logout', auth, logout);
router.get('/profile', auth, getProfile);
router.put('/profile', auth, updateProfile);
router.put('/change-password', auth, changePassword);

module.exports = router;