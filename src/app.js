const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');

const app = express();

// Initialize SQLite Database with a file for persistence
const db = new sqlite3.Database('database.sqlite');

// Create Users, Submissions, and Login Attempts Tables
db.serialize(() => {
  // Create Users Table with Salt Column
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      salt TEXT,
      password TEXT
    )
  `);

  // Create Submissions Table
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

  // Create Login Attempts Table
  db.run(`
    CREATE TABLE IF NOT EXISTS login_attempts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT,
      success INTEGER,  -- 1 for success, 0 for failure
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Check if the users table is empty
  db.get(`SELECT COUNT(*) as count FROM users`, (err, row) => {
    if (err) {
      console.error('Error checking users table:', err);
    } else if (row.count === 0) {
      console.log('Users table is empty. Inserting default users.');
      insertDefaultUsers();
    } else {
      console.log('Users table already has data. Skipping default user insertion.');
    }
  });
});

// Function to insert default users
function insertDefaultUsers() {
  const insertUser = db.prepare(`INSERT INTO users (username, salt, password) VALUES (?, ?, ?)`);

  const users = [
    { username: 'user1', password: 'password1' },
    { username: 'user2', password: 'password2' },
    // Add more users if needed
  ];

  users.forEach(user => {
    // Generate a unique salt for each user
    const salt = bcrypt.genSaltSync(10);
    // Hash the password with the generated salt
    const hashedPassword = bcrypt.hashSync(user.password, salt);
    // Insert the user into the database
    insertUser.run(user.username, salt, hashedPassword, (err) => {
      if (err) {
        console.error('Error inserting user:', err);
      } else {
        console.log(`User ${user.username} inserted successfully.`);
      }
    });
  });

  insertUser.finalize();
}

// Middleware Setup
app.use(bodyParser.urlencoded({ extended: false }));

// Check environment and set SESSION_SECRET accordingly
let sessionSecret = process.env.SESSION_SECRET;

if (process.env.NODE_ENV !== 'production') {
  // In non-production environments, use a default secret if SESSION_SECRET is not set
  sessionSecret = sessionSecret ?? 'default_secret_key_for_non_production'; // Default secret for development
} else {
  // In production, throw an error and exit the application if SESSION_SECRET is not set
  if (!sessionSecret) {
    console.error('Error: SESSION_SECRET must be set in the environment variables in production.');
    process.exit(1);
  }
}

app.use(
  session({
    secret: sessionSecret,
    resave: false,
    saveUninitialized: true,
  })
);

// Authentication Middleware
function requireLogin(req, res, next) {
  if (!req.session.userId) {
    res.redirect('/login');
  } else {
    next();
  }
}

// Helper Function to Record Login Attempts
function recordLoginAttempt(username, success) {
  db.run(
    `INSERT INTO login_attempts (username, success) VALUES (?, ?)`,
    [username, success ? 1 : 0],
    (err) => {
      if (err) {
        console.error('Error recording login attempt:', err);
      }
    }
  );
}

// Routes

// Redirect root URL to login page
app.get('/', (req, res) => {
  res.redirect('/login');
});

// Login Page
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'views/login.html'));
});

// Handle Login
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.get(
    `SELECT * FROM users WHERE username = ?`,
    [username],
    (err, user) => {
      if (err) {
        console.error('Database error:', err);
        recordLoginAttempt(username, false);
        return res.send('Error logging in.');
      }
      if (user) {
        // Retrieve the stored salt
        const salt = user.salt;
        // Hash the input password with the stored salt
        const hashedInputPassword = bcrypt.hashSync(password, salt);
        // Compare the hashed input password with the stored hashed password
        if (hashedInputPassword === user.password) {
          req.session.userId = user.id;
          recordLoginAttempt(username, true);
          res.redirect('/form');
        } else {
          recordLoginAttempt(username, false);
          res.send('Invalid credentials. <a href="/login">Try again</a>');
        }
      } else {
        recordLoginAttempt(username, false);
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
    `INSERT INTO submissions (user_id, name, email, phone, country, gender, qualification)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [userId, name, email, phone, country, gender, qualification],
    function (err) {
      if (err) {
        console.error('Error saving submission:', err);
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
