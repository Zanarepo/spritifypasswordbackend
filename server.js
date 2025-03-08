const { createClient } = require('@supabase/supabase-js');
const nodemailer = require('nodemailer');
const express = require('express');
const cors = require('cors');
require('dotenv').config();
const crypto = require('crypto'); // Built-in crypto module

// Async function to hash a password with SHA-256 using the Web Crypto API.
async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  // Convert bytes to a hex string.
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

const app = express();
const port = process.env.PORT || 4000;

app.use(express.json());
app.use(cors());

// Initialize Supabase client.
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// Setup Nodemailer transport.
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: 465, // Secure SMTP port
  secure: true,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Function to send a reset password email.
async function sendResetPasswordEmail(userEmail, resetToken) {
  const resetLink = `${process.env.BASE_URL}/reset-password?token=${resetToken}`;
  const mailOptions = {
    from: `"SprintifyHq" <${process.env.EMAIL_USER}>`,
    to: userEmail,
    subject: 'Reset Your Password',
    text: `Hello Sprinter! You requested a password reset. Please click the link below to reset your password:\n\n${resetLink}\n\nIf you did not request this, please ignore this email, Thank you.`,
  };

  try {
    const info = await transporter.sendMail(mailOptions);
    console.log('Password reset email sent:', info.response);
  } catch (error) {
    console.error('Error sending password reset email:', error);
  }
}




// Endpoint to handle forgot password requests.
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
  
    // Check if email is provided
    if (!email || typeof email !== 'string') {
      return res.status(400).json({ message: 'Valid email is required' });
    }
  
    try {
      // Check if the user exists in the "users" table.
      const { data: user, error } = await supabase
        .from('users')
        .select('id, email')
        .eq('email', email.trim().toLowerCase()) 
        .single();
  
      if (error || !user) {
        return res.status(404).json({ message: 'User not found' });
      }










    // Generate a reset token and expiry time (2 hours from now).
    const resetToken = crypto.randomBytes(32).toString('hex');
    const tokenExpiry = new Date(Date.now() + 2 * 3600000); // 2 hours in milliseconds

    // Update the user's record with the reset token and expiry.
    const { error: updateError } = await supabase
      .from('users')
      .update({
        reset_token: resetToken,
        token_expiry: tokenExpiry.toISOString(),
      })
      .eq('email', email.trim().toLowerCase());

    if (updateError) {
      console.error('Error updating reset token:', updateError);
      return res.status(500).json({ message: 'Error updating reset token' });
    }

    // Send the password reset email.
    await sendResetPasswordEmail(email, resetToken);
    res.status(200).json({ message: 'Password reset email sent' });
  } catch (err) {
    console.error('Internal server error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Endpoint to handle password reset.
app.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  try {
    // Verify the token by fetching the user.
    const { data: user, error } = await supabase
      .from('users')
      .select('id, token_expiry')
      .eq('reset_token', token)
      .single();

    if (error || !user) {
      return res.status(400).json({ message: 'Invalid or expired token' });
    }

    // Check if the token has expired.
    if (new Date(user.token_expiry) < new Date()) {
      return res.status(400).json({ message: 'Token has expired' });
    }

    // Hash the new password.
    const hashedPassword = await hashPassword(newPassword);

    // Update the user's password and clear the reset token and expiry.
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

// Start the server.
app.get('/', (req, res) => {
    res.send('Server is running!');
  });
  
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
