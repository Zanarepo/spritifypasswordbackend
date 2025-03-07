// index.js
require('dotenv').config(); // loads environment variables from a .env file if available

const express = require('express');
const app = express();

// Middleware to parse JSON bodies
app.use(express.json());

// Define a test route
app.get('/', (req, res) => {
  res.send('Forgot Password API is running!');
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
