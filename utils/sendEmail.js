const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// OTP পাঠানো
const sendOTP = async (email, otp) => {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Your OTP for Verification',
    text: `Your OTP is: ${otp}. It expires in 10 minutes.`
  };
  await transporter.sendMail(mailOptions);
};

// Reset Password Email
const sendResetPasswordEmail = async (email, token) => {
  const resetUrl = `http://localhost:3000/reset-password/${token}`;  // Frontend URL পরিবর্তন করুন
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Password Reset',
    text: `Reset your password: ${resetUrl}. It expires in 10 minutes.`
  };
  await transporter.sendMail(mailOptions);
};

module.exports = { sendOTP, sendResetPasswordEmail };