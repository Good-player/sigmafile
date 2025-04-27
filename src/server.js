const express = require('express');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const { D1Database } = require('@cloudflare/d1');
const dotenv = require('dotenv');
dotenv.config();

const app = express();
const port = 3000;

// Initialize D1 Database connection
const db = new D1Database(process.env.D1_CONNECTION);

// Middleware for parsing JSON
app.use(express.json());
app.use(express.static('public'));

// Set up file upload limit (15MB)
const upload = multer({
  limits: { fileSize: 15 * 1024 * 1024 }, // 15MB limit
}).single('file');

// Utility function for running SQL queries
async function query(sql, params) {
  const result = await db.prepare(sql).bind(...params).all();
  return result;
}

// Registration Endpoint
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  // Hash the password before storing
  const hashedPassword = await bcrypt.hash(password, 10);
  const timestamp = Date.now();

  // Insert new user into the database
  await query(
    `INSERT INTO users (username, password, last_interaction) VALUES (?, ?, ?)`,
    [username, hashedPassword, timestamp]
  );

  res.status(200).send({ message: 'User registered successfully' });
});

// Login Endpoint
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const user = await query('SELECT * FROM users WHERE username = ?', [username]);
  if (user.length === 0) return res.status(400).send('User not found');

  const isMatch = await bcrypt.compare(password, user[0].password);
  if (!isMatch) return res.status(400).send('Incorrect password');

  // Update last interaction time
  const timestamp = Date.now();
  await query('UPDATE users SET last_interaction = ? WHERE id = ?', [timestamp, user[0].id]);

  res.status(200).send({ message: 'Logged in successfully' });
});

// File Upload Endpoint
app.post('/upload', upload, async (req, res) => {
  const userId = req.user.id; // Get user ID from session or token
  const fileName = req.file.originalname;
  const fileSize = req.file.size;
  const timestamp = Date.now();

  // Check if the user has uploaded more than 15 files
  const fileCount = await query('SELECT COUNT(*) FROM files WHERE user_id = ?', [userId]);
  if (fileCount[0]['COUNT(*)'] >= 15) {
    return res.status(400).send('You can only upload up to 15 files.');
  }

  // Insert file info into the database
  await query('INSERT INTO files (user_id, file_name, file_size, upload_date) VALUES (?, ?, ?, ?)', [userId, fileName, fileSize, timestamp]);

  res.status(200).send('File uploaded successfully');
});

// File Deletion Endpoint
app.delete('/delete/:fileId', async (req, res) => {
  const { fileId } = req.params;
  const userId = req.user.id;

  const file = await query('SELECT * FROM files WHERE id = ? AND user_id = ?', [fileId, userId]);
  if (file.length === 0) return res.status(400).send('File not found');

  await query('DELETE FROM files WHERE id = ?', [fileId]);

  res.status(200).send('File deleted successfully');
});

// Server listen
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});

