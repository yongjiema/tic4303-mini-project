const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const morgan = require('morgan');
const csrf = require('csurf');

const app = express();

// ---------------------
// Security Middleware
// ---------------------
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: [], // Upgrade HTTP to HTTPS
      },
    },
  })
);

// ---------------------
// Logging Middleware
// ---------------------
app.use(morgan('combined')); // Logs all HTTP requests

// ---------------------
// View Engine Setup
// ---------------------
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ---------------------
// Serve Static Files
// ---------------------
app.use(express.static(path.join(__dirname, 'public')));

// ---------------------
// Initialize SQLite Database
// ---------------------
const db = new sqlite3.Database('database.sqlite', (err) => {
  if (err) {
    console.error('Error opening database:', err);
    process.exit(1);
  } else {
    console.log('Connected to SQLite database.');
  }
});

// ---------------------
// Create Tables
// ---------------------
db.serialize(() => {
  // Create Users Table with Salt and Role Columns
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      salt TEXT,
      password TEXT,
      role TEXT DEFAULT 'user'
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

// ---------------------
// Function to Insert Default Users
// ---------------------
function insertDefaultUsers() {
  const insertUser = db.prepare(`INSERT INTO users (username, salt, password, role) VALUES (?, ?, ?, ?)`);

  const users = [
    { username: 'admin', password: 'Adm!n$tr0ngP@ssw0rd123', role: 'admin' },
    { username: 'user1', password: 'Us3r#Secure2024!@#', role: 'user' },
    { username: 'user2', password: 'P@ssw0rd!_Ex@mple#456', role: 'user' },
    // Add more users if needed
  ];

  users.forEach(user => {
    const salt = bcrypt.genSaltSync(12);
    const hashedPassword = bcrypt.hashSync(user.password, salt);
    insertUser.run(user.username, salt, hashedPassword, user.role, (err) => {
      if (err) {
        console.error(`Error inserting user ${user.username}:`, err);
      } else {
        console.log(`User ${user.username} with role ${user.role} inserted successfully.`);
      }
    });
  });

  insertUser.finalize();
}

// ---------------------
// Middleware Setup
// ---------------------
app.use(bodyParser.urlencoded({ extended: false }));

// ---------------------
// Session Configuration with Security Enhancements
// ---------------------

// Retrieve SESSION_SECRET from environment variables
const sessionSecret = process.env.SESSION_SECRET;

// Check if SESSION_SECRET is set
if (process.env.NODE_ENV === 'production' && !sessionSecret) {
  console.error('Error: SESSION_SECRET must be set in the environment variables in production.');
  process.exit(1);
}

if (process.env.NODE_ENV !== 'production' && !sessionSecret) {
  console.warn('Warning: SESSION_SECRET is not set. Using default secret for development.');
}

// Configure session middleware
app.use(
  session({
    secret: sessionSecret || 'default_secret_key_for_non_production', // Replace with a strong secret in production
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true, // Prevents client-side JavaScript from accessing the cookie
      secure: process.env.NODE_ENV === 'production', // Ensures the browser only sends the cookie over HTTPS
      maxAge: 1000 * 60 * 60 * 24, // 1 day
      sameSite: 'lax', // Helps protect against CSRF
    },
  })
);

// ---------------------
// CSRF Protection Middleware
// ---------------------
const csrfProtection = csrf();

// Apply CSRF protection to all POST routes
app.use(csrfProtection);

// Pass CSRF token to all views
app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken();
  next();
});

// ---------------------
// Rate Limiting Middleware
// ---------------------
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 10 login requests per windowMs
  message: 'Too many login attempts from this IP, please try again after 15 minutes.',
});

const generalLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
});

// Apply general rate limiter to all requests
app.use(generalLimiter);

// Error-Handling Middleware
app.use((err, req, res, next) => {
  // Log error details to the console
  console.error(err); // You can customize the log format as needed

  // Handle CSRF Token Errors
  if (err.code === 'EBADCSRFTOKEN') {
    // Render a specific CSRF error page with a 403 status
    return res.status(403).send('Forbidden');
  }

  // Handle Other Errors
  if (process.env.NODE_ENV === 'production') {
    // In Production, send a generic error message
    return res.status(500).send('An unexpected error occurred. Please try again later.');
  } else {
    // In Development, send detailed error information
    throw err;
  }
});

// ---------------------
// Helper Functions for Authentication and Authorization
// ---------------------

// Authentication Middleware: Ensures the user is logged in
function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  next();
}

// Authorization Middleware: Checks if the user has the required role
function requireRole(roles) {
  return function (req, res, next) {
    if (!req.session.userRole || !roles.includes(req.session.userRole)) {
      return res.status(403).send('Access denied.');
    }
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

// ---------------------
// HTTPS Enforcement Middleware
// ---------------------
function enforceHTTPS(req, res, next) {
  if (process.env.NODE_ENV === 'production' && req.headers['x-forwarded-proto'] !== 'https') {
    // Redirect to HTTPS
    return res.redirect(`https://${req.headers.host}${req.url}`);
  }
  next();
}

app.use(enforceHTTPS);

// ---------------------
// Routes
// ---------------------

// Redirect root URL to login page
app.get('/', (req, res) => {
  res.redirect('/login');
});

// ---------------------
// Login Routes
// ---------------------

// Login Page
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

// Handle Login with Input Validation and Rate Limiting
app.post('/login', loginLimiter, [
  body('username')
    .trim()
    .isAlphanumeric().withMessage('Username must be alphanumeric.')
    .isLength({ min: 3, max: 20 }).withMessage('Username must be between 3 and 20 characters.'),
  body('password')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters long.')
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    // If validation errors exist, render the login page with errors
    return res.status(400).render('login', { error: errors.array()[0].msg });
  }

  const { username, password } = req.body;

  db.get(
    `SELECT * FROM users WHERE username = ?`,
    [username],
    (err, user) => {
      if (err) {
        console.error('Database error:', err);
        recordLoginAttempt(username, false);
        return res.status(500).render('login', { error: 'Internal server error.' });
      }
      if (user) {
        // Retrieve the stored salt
        const salt = user.salt;
        // Hash the input password with the stored salt
        const hashedInputPassword = bcrypt.hashSync(password, salt);
        // Compare the hashed input password with the stored hashed password
        if (hashedInputPassword === user.password) {
          // Store user ID and role in the session
          req.session.userId = user.id;
          req.session.userRole = user.role;
          recordLoginAttempt(username, true);
          return res.redirect('/form');
        } else {
          recordLoginAttempt(username, false);
          return res.status(401).render('login', { error: 'Invalid credentials.' });
        }
      } else {
        recordLoginAttempt(username, false);
        return res.status(401).render('login', { error: 'Invalid credentials.' });
      }
    }
  );
});

// ---------------------
// Form Submission Routes
// ---------------------

// Form Submission Page
app.get('/form', requireLogin, (req, res) => {
  res.render('form', { role: req.session.userRole, error: null });
});

// Handle Form Submission with Input Validation and Sanitization
app.post('/form', requireLogin, [
  body('name').trim().notEmpty().withMessage('Name is required.'),
  body('email').isEmail().withMessage('Invalid email address.').normalizeEmail(),
  body('phone').trim().optional({ checkFalsy: true }).isMobilePhone().withMessage('Invalid phone number.'),
  body('country').trim().notEmpty().withMessage('Country is required.'),
  body('gender').isIn(['Male', 'Female', 'Other']).withMessage('Invalid gender selection.'),
  body('qualification').trim().notEmpty().withMessage('Qualification is required.')
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    // If validation errors exist, render the form page with errors
    return res.status(400).render('form', { role: req.session.userRole, error: errors.array()[0].msg });
  }

  const { name, email, phone, country, gender, qualification } = req.body;
  const userId = req.session.userId;

  db.run(
    `INSERT INTO submissions (user_id, name, email, phone, country, gender, qualification)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [userId, name, email, phone, country, gender, qualification],
    function (err) {
      if (err) {
        console.error('Error saving submission:', err);
        return res.status(500).send('Error saving data.');
      } else {
        return res.redirect('/thankyou');
      }
    }
  );
});

// ---------------------
// Admin Routes
// ---------------------

// Admin Dashboard Route (Accessible only to admins)
app.get('/admin', requireLogin, requireRole(['admin']), (req, res) => {
  // Fetch all users as an example
  db.all(`SELECT id, username, role FROM users`, (err, users) => {
    if (err) {
      console.error('Error fetching users:', err);
      return res.status(500).send('Internal server error.');
    }
    res.render('admin', { users });
  });
});

// ---------------------
// Thank You Routes
// ---------------------

// Thank You Page
app.get('/thankyou', requireLogin, (req, res) => {
  res.render('thankyou', { role: req.session.userRole });
});

// ---------------------
// Logout Routes
// ---------------------

// Handle Logout
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session:', err);
      return res.status(500).send('Error logging out.');
    }
    res.redirect('/login');
  });
});

// ---------------------
// Start the Server
// ---------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`App running on http://localhost:${PORT}`);
});
