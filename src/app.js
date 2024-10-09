const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bodyParser = require('body-parser');

const app = express();

// Initialize SQLite Database
const db = new sqlite3.Database(':memory:');

// Create Users and Submissions Tables
db.serialize(() => {
  db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
      )
    `);

  // Insert a default user
  db.run(`
      INSERT INTO users (username, password)
      VALUES ('user1', 'password1')
    `);

  // Update the submissions table schema
  db.run(`
      CREATE TABLE IF NOT EXISTS submissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        name TEXT,
        email TEXT,
        phone TEXT,
        country TEXT,
        gender TEXT,
        qualification TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
      )
    `);
});

// Middleware Setup
app.use(bodyParser.urlencoded({ extended: false }));
app.use(
  session({
    secret: process.env.SESSION_SECRET ?? 'your_secret_key',
    resave: false,
    saveUninitialized: true,
  })
);

// Redirect root URL to login page
app.get('/', (req, res) => {
  res.redirect('/login');
});

// Authentication Middleware
function requireLogin(req, res, next) {
  if (!req.session.userId) {
    res.redirect('/login');
  } else {
    next();
  }
}

// Routes

// Login Page
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'views/login.html'));
});

// Handle Login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get(
    `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`,
    // `SELECT * FROM users WHERE username = ? AND password = ?`,
    // [username, password],
    (err, user) => {
      if (user) {
        req.session.userId = user.id;
        res.redirect('/form');
      } else {
        res.send('Invalid credentials. <a href="/login">Try again</a>');
      }
    }
  );
});

// Form Submission Page
app.get('/form', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'views/form.html'));
});

// Handle Form Submission
app.post('/form', requireLogin, (req, res) => {
  const { name, email, phone, country, gender, qualification } = req.body;
  const userId = req.session.userId;
  db.run(
    `
      INSERT INTO submissions (user_id, name, email, phone, country, gender, qualification)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `,
    [userId, name, email, phone, country, gender, qualification],
    function (err) {
      if (err) {
        console.error(err);
        res.send('Error saving data.');
      } else {
        res.redirect('/thankyou');
      }
    }
  );
});

// Thank You Page with Logout Feature
app.get('/thankyou', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'views/thankyou.html'));
});

// Handle Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// Start the Server
app.listen(3000, () => {
  console.log('App running on http://localhost:3000');
});
