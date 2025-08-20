const { createClient } = require('@supabase/supabase-js');
const nodemailer = require('nodemailer');
const express = require('express');
const cors = require('cors');
require('dotenv').config();
const crypto = require('crypto'); // Built-in crypto module

const app = express();
const port = process.env.PORT || 4000;

// ✅ Correct CORS setup
app.use(cors({
  origin: ["http://localhost:3000", "https://sprintifyhq.com"], // Allow frontend
  methods: ["GET", "POST", "PUT", "DELETE"],
  credentials: true,
}));

app.use(express.json());

// ✅ Initialize Supabase client
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// ✅ Setup Nodemailer transport
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: 465, // Secure SMTP port
  secure: true,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// ✅ Function to hash a password using Node.js `crypto` (instead of `crypto.subtle`)
function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

// ✅ Function to send reset password email
async function sendResetPasswordEmail(userEmail, resetToken) {
  const resetLink = `${process.env.BASE_URL}/reset-password?token=${resetToken}`;
  const mailOptions = {
    from: `"Sprintify" <${process.env.EMAIL_USER}>`,
    to: userEmail,
    subject: 'Reset Your Password',
    text: `You requested a password reset. Click the link below to reset your password:\n\n${resetLink}\n\nIf you did not request this, ignore this email.`,
  };

  try {
    const info = await transporter.sendMail(mailOptions);
    console.log('Password reset email sent:', info.response);
  } catch (error) {
    console.error('Error sending password reset email:', error);
  }
}

// ✅ Forgot Password Endpoint
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;

  if (!email || typeof email !== 'string') {
    return res.status(400).json({ message: 'Valid email is required' });
  }

  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('id, email')
      .eq('email', email.trim().toLowerCase())
      .single();

    if (error || !user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Generate reset token and expiry time (2 hours)
    const resetToken = crypto.randomBytes(32).toString('hex');
    const tokenExpiry = new Date(Date.now() + 2 * 3600000).toISOString();

    const { error: updateError } = await supabase
      .from('users')
      .update({
        reset_token: resetToken,
        token_expiry: tokenExpiry,
      })
      .eq('id', user.id);

    if (updateError) {
      console.error('Error updating reset token:', updateError);
      return res.status(500).json({ message: 'Error updating reset token' });
    }

    await sendResetPasswordEmail(email, resetToken);
    res.status(200).json({ message: 'Password reset email sent' });
  } catch (err) {
    console.error('Internal server error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// ✅ Reset Password Endpoint
app.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;

  if (!token || !newPassword) {
    return res.status(400).json({ message: 'Token and new password are required' });
  }

  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('id, token_expiry')
      .eq('reset_token', token)
      .single();

    if (error || !user) {
      return res.status(400).json({ message: 'Invalid or expired token' });
    }

    if (new Date(user.token_expiry) < new Date()) {
      return res.status(400).json({ message: 'Token has expired' });
    }

    const hashedPassword = hashPassword(newPassword);

    const { error: updateError } = await supabase
      .from('users')
      .update({
        password: hashedPassword,
        reset_token: null,
        token_expiry: null,
      })
      .eq('id', user.id);

    if (updateError) {
      return res.status(500).json({ message: 'Failed to reset password' });
    }

    res.status(200).json({ message: 'Password reset successful' });
  } catch (err) {
    console.error('Internal server error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// ✅ Root endpoint for server health check
app.get('/', (req, res) => {
  res.send('Server is running!');
});

// ✅ Start the server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
