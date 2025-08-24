const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const authRoutes = require('./routes/auth');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const rateLimit = require('express-rate-limit');
const sanitizeFilename = require('sanitize-filename');
const moment = require('moment-timezone');
const timetableRoutes = require('./routes/timetable');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const { nanoid } = require('nanoid');
require('dotenv').config();
const materialRoutes = require('./routes/material');
const admin = require('firebase-admin');
const app = express();
const Joi = require('joi');
const { ref, uploadBytes, getDownloadURL } = require('firebase/storage');

const upload = multer({ storage: multer.memoryStorage() });


// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false, // required for Render external DBs
  },
});

const schema = fs.readFileSync("./schema.sql", "utf8");
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';


async function initDB() {
  try {
    await pool.query(schema);
    console.log("✅ Database schema ensured");
  } catch (err) {
    console.error("❌ Error initializing DB:", err);
  }
}

initDB();

let materials = [
  { id: 1, filename: 'Lecture Notes Week 1.pdf', subject_id: 1, subject_name: 'Mathematics', category_id: 1, uploaded_by: 1, created_at: '2025-06-01' },
  { id: 2, filename: 'ML Assignment 1.pdf', subject_id: 'elective_1', subject_name: 'Machine Learning', category_id: 2, uploaded_by: 2, created_at: '2025-06-02', elective_id: 1 }
];

//Firebase
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n')
    })
  });
  console.log('Firebase Admin SDK initialized');
}

if (!process.env.FIREBASE_PROJECT_ID || !process.env.FIREBASE_CLIENT_EMAIL || !process.env.FIREBASE_PRIVATE_KEY) {
  console.error('Missing Firebase environment variables. Please check your .env file.');
  process.exit(1);
}

//Authentication
const authMiddleware = async (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '') || req.cookies['user-token'];
  if (!token) {
    console.log('No token provided');
    return res.status(401).json({ error: 'Unauthorized: No token provided' });
  }
  try {
    const decodedToken = await admin.auth().verifyIdToken(token);
    console.log('Decoded token:', decodedToken);
    req.user = {
      id: decodedToken.sub || decodedToken.uid,
      ...decodedToken
    };
    console.log('Set req.user with id:', req.user.id);
    if (!req.user.id) {
      console.log('User ID not found in decoded token');
      return res.status(401).json({ error: 'Unauthorized: User ID not found in token' });
    }
    next();
  } catch (error) {
    console.error('Firebase token verification error:', error.message);
    return res.status(401).json({ error: 'Unauthorized: Invalid or expired token' });
  }
};

const restrictTo = (roles) => (req, res, next) => {
  if (!req.user) {
    console.log('No user in request');
    return res.status(401).json({ error: 'Unauthorized: No user authenticated' });
  }
  const userRole = req.user.role?.toUpperCase();
  if (!userRole) {
    console.log('No role defined for user:', req.user);
    return res.status(403).json({ error: 'Unauthorized: User role not defined' });
  }
  // Convert roles to array if string
  const allowedRoles = Array.isArray(roles) ? roles : [roles];
  if (!allowedRoles.map(r => r.toUpperCase()).includes(userRole)) {
    console.log(`Role ${userRole} not authorized for roles: ${allowedRoles}`);
    return res.status(403).json({ error: `Unauthorized: Only ${allowedRoles.join(' or ')} can access this route` });
  }
  next();
};


const runMigrations = async (client) => {
  const migrationSQL = `
-- -----------------------------
-- Users table
-- -----------------------------
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(50),
    roll_no VARCHAR(20),
    class_code VARCHAR(10),
    college VARCHAR(100),
    branch VARCHAR(50),
    section VARCHAR(10),
    semester VARCHAR(20),
    password TEXT,
    role VARCHAR(20) DEFAULT 'STUDENT',
    is_cr BOOLEAN DEFAULT FALSE,
    cr_type VARCHAR(20),
    cr_elective_id INTEGER,
    reset_password_token VARCHAR(100),
    reset_password_expires BIGINT,
    semester_start_date DATE,
    semester_end_date DATE
);

-- -----------------------------
-- Add missing columns to users
-- -----------------------------
ALTER TABLE users
ADD COLUMN IF NOT EXISTS college VARCHAR(100),
ADD COLUMN IF NOT EXISTS branch VARCHAR(50),
ADD COLUMN IF NOT EXISTS section VARCHAR(10),
ADD COLUMN IF NOT EXISTS semester VARCHAR(20),
ADD COLUMN IF NOT EXISTS is_cr BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS cr_elective_id INTEGER;

-- -----------------------------
-- Class codes table
-- -----------------------------
CREATE TABLE IF NOT EXISTS class_codes (
    id SERIAL PRIMARY KEY,
    code VARCHAR(6) UNIQUE NOT NULL,
    college VARCHAR(100) NOT NULL,
    branch VARCHAR(50) NOT NULL,
    section VARCHAR(10) NOT NULL,
    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- -----------------------------
-- Subjects table
-- -----------------------------
CREATE TABLE IF NOT EXISTS subjects (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    classcode VARCHAR(10) NOT NULL
);

-- -----------------------------
-- Professors table
-- -----------------------------
CREATE TABLE IF NOT EXISTS professors (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    created_by INTEGER REFERENCES users(id)
);

-- -----------------------------
-- Subject_Professors table
-- -----------------------------
CREATE TABLE IF NOT EXISTS subject_professors (
    subject_id INTEGER REFERENCES subjects(id),
    professor_id INTEGER REFERENCES professors(id),
    PRIMARY KEY (subject_id, professor_id)
);

-- -----------------------------
-- Electives table
-- -----------------------------
CREATE TABLE IF NOT EXISTS electives (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    is_open BOOLEAN NOT NULL,
    branch VARCHAR(50),
    cr_id INTEGER REFERENCES users(id),
    semester VARCHAR(20) NOT NULL,
    college VARCHAR(100),
    professor VARCHAR(100),
    schedule JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_cr_per_elective UNIQUE (cr_id)
);

-- -----------------------------
-- Student electives table
-- -----------------------------
CREATE TABLE IF NOT EXISTS student_electives (
    id SERIAL PRIMARY KEY,
    student_id INTEGER REFERENCES users(id),
    elective_id INTEGER REFERENCES electives(id),
    status VARCHAR(20) DEFAULT 'enrolled',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (student_id, elective_id)
);

-- -----------------------------
-- Categories table
-- -----------------------------
CREATE TABLE IF NOT EXISTS categories (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    subject_id INTEGER REFERENCES subjects(id),
    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
ALTER TABLE categories
ADD COLUMN IF NOT EXISTS elective_id INTEGER REFERENCES electives(id);

-- -----------------------------
-- Materials table
-- -----------------------------
CREATE TABLE IF NOT EXISTS materials (
    id SERIAL PRIMARY KEY,
    filename VARCHAR(255),
    path VARCHAR(255),
    url TEXT,
    classcode VARCHAR(10),
    elective_id INTEGER REFERENCES electives(id),
    subject_id INTEGER REFERENCES subjects(id),
    category_id INTEGER REFERENCES categories(id),
    uploaded_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- -----------------------------
-- Class schedules table
-- -----------------------------
CREATE TABLE IF NOT EXISTS class_schedules (
    id SERIAL PRIMARY KEY,
    class_code VARCHAR(10),
    subject_id INTEGER REFERENCES subjects(id),
    elective_id INTEGER REFERENCES electives(id),
    specific_date DATE,
    time_slot_id INTEGER,
    repeat_option VARCHAR(20),
    canceled BOOLEAN DEFAULT FALSE,
    day_of_week VARCHAR(20),
    start_date DATE,
    end_date DATE
);

-- -----------------------------
-- Time slots table
-- -----------------------------
CREATE TABLE IF NOT EXISTS time_slots (
    id SERIAL PRIMARY KEY,
    class_code VARCHAR(10),
    start_time TIME,
    end_time TIME
);

-- -----------------------------
-- Holidays table
-- -----------------------------
CREATE TABLE IF NOT EXISTS holidays (
    id SERIAL PRIMARY KEY,
    class_code VARCHAR(10),
    holiday_date DATE,
    description TEXT,
    created_by INTEGER REFERENCES users(id)
);

-- -----------------------------
-- Attendance table
-- -----------------------------
CREATE TABLE IF NOT EXISTS attendance (
    id SERIAL PRIMARY KEY,
    student_id INTEGER REFERENCES users(id),
    class_id INTEGER REFERENCES class_schedules(id),
    date DATE,
    status VARCHAR(20),
    reason TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
`;

  await client.query(migrationSQL);
  console.log('✅ All tables and columns ensured successfully!');
};

export const connectWithRetry = async (retries = 5, delay = 5000) => {
  for (let i = 0; i < retries; i++) {
    try {
      const client = await pool.connect();
      await client.query("SET TIME ZONE 'Asia/Kolkata'");
      await runMigrations(client); // run migrations on startup
      client.release();
      console.log('✅ Successfully connected to PostgreSQL and ensured tables exist');
      return pool; // return the pool for further queries
    } catch (err) {
      console.error(`Failed to connect to PostgreSQL (attempt ${i + 1}/${retries}):`, err);
      if (i === retries - 1) {
        console.error('❌ Max retries reached. Exiting...');
        process.exit(1);
      }
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
};

connectWithRetry();

let messages = [
  { message: 'Welcome to the class chat!', timestamp: '2025-06-03T12:00:00Z', classcode: 'CS101' }
];

let subjects = [{ id: 1, name: 'Mathematics' }, { id: 'elective_1', name: 'Machine Learning', isElective: true, elective_id: 1 }];
let categories = [
  { id: 1, name: 'Lecture Notes', subject_id: '1' },
  { id: 2, name: 'Assignments', subject_id: 'elective_1' }
];

// Middleware
app.use(cors({
  origin: function (origin, callback) {
    const allowedOrigins = [
      'http://localhost:3000',
      'https://prezzattendance.netlify.app'
    ];
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());
app.use(passport.initialize());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500,
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api', limiter);

// Public routes
app.get("/", (req, res) => {
  res.send("✅ Prezz Backend is live!");
});
app.use('/api/auth', authRoutes);
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get(
  '/auth/google/callback',
  passport.authenticate('google', { session: false }),
  (req, res) => {
    const token = jwt.sign(
      {
        id: req.user.id,
        email: req.user.email,
        role: req.user.role.toUpperCase(),
        class_code: req.user.class_code,
        branch: req.user.branch,
        semester: req.user.semester,
        is_cr: req.user.is_cr,
        cr_type: req.user.cr_type,
        cr_elective_id: req.user.cr_elective_id
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    res.cookie('user-token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 3600 * 1000
    });

    // Redirect based on role
    const role = req.user.role.toUpperCase();
    const crType = req.user.cr_type?.toLowerCase(); // ✅ safer
        if (role === 'CR') {
      if (crType === 'regular') {
        res.redirect(`${FRONTEND_URL}/regular-cr-dashboard`);
      } else if (crType === 'elective') {
        res.redirect(`${FRONTEND_URL}/elective-cr-dashboard`);
      } else {
        res.redirect(`${FRONTEND_URL}/dashboard`); // Fallback
      }
    } else {
      res.redirect(`${FRONTEND_URL}/student-dashboard`);
    }
  }
);


// Nodemailer setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});



// Protected routes
app.use('/api/materials', authMiddleware, materialRoutes);
app.use('/api/timetable', authMiddleware, timetableRoutes);



// Register endpoint
app.post('/api/register', async (req, res) => {
  const { email, username, roll_no, class_code, section, semester, password } = req.body;
  try {
    if (!email || !username || !roll_no || !class_code || !section || !semester || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    const codeResult = await pool.query('SELECT college, branch, section FROM class_codes WHERE code = $1', [class_code]);
    if (codeResult.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid class code' });
    }
    const { college, branch } = codeResult.rows[0];
    if (codeResult.rows[0].section !== section) {
      return res.status(400).json({ error: 'Section does not match the class code' });
    }
    const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await pool.query(
      'INSERT INTO users (email, username, roll_no, class_code, college, branch, section, semester, password, role) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *',
      [email, username, roll_no, class_code, college, branch, section, semester, hashedPassword, 'STUDENT']
    );

    

    const token = jwt.sign(
      {
        id: newUser.rows[0].id,
        email: newUser.rows[0].email,
        role: newUser.rows[0].role.toUpperCase(),
        class_code: newUser.rows[0].class_code,
        college: newUser.rows[0].college,
        branch: newUser.rows[0].branch,
        section: newUser.rows[0].section,
        semester: newUser.rows[0].semester,
        is_cr: newUser.rows[0].is_cr,
        cr_type: newUser.rows[0].cr_type,
        cr_elective_id: newUser.rows[0].cr_elective_id
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    res.cookie('user-token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 3600 * 1000
    });
    res.status(201).json({
      token,
      role: newUser.rows[0].role.toUpperCase(),
      user_id: newUser.rows[0].id,
      classcode: newUser.rows[0].class_code,
      cr_type: newUser.rows[0].cr_type,
      cr_elective_id: cr_elective_id
    });
  } catch (error) {
    console.error('Error during registration:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// CR Register endpoint
app.post('/api/cr-register', async (req, res) => {
  const { email, username, roll_no, college, branch, section, semester, password, cr_type, elective_name, elective_professor, elective_type, elective_college, elective_branch } = req.body;
  try {
    if (!email || !username || !roll_no || !password || !cr_type) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    if (!['regular', 'elective'].includes(cr_type)) {
      return res.status(400).json({ error: 'Invalid CR type. Must be "regular" or "elective".' });
    }
    if (cr_type === 'regular') {
      if (!college || !branch || !section || !semester) {
        return res.status(400).json({ error: 'All fields are required' });
      }
    } else {
      if (!elective_name || !elective_professor || !elective_type) {
        return res.status(400).json({ error: 'All fields are required' });
      }
      if (elective_type === 'open') {
        if (!elective_college) {
          return res.status(400).json({ error: 'College name is required for an open elective' });
        }
      } else {
        if (!elective_college || !elective_branch) {
          return res.status(400).json({ error: 'College and branch are required for a core elective' });
        }
      }
    }
    const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query('BEGIN');
    let class_code = null;
    let cr_elective_id = null;
    if (cr_type === 'regular') {
      let isUnique = false;
      while (!isUnique) {
        class_code = nanoid(6);
        const existing = await pool.query('SELECT id FROM class_codes WHERE code = $1', [class_code]);
        if (existing.rows.length === 0) {
          isUnique = true;
        }
      }
    }
    const newUser = await pool.query(
      'INSERT INTO users (email, username, roll_no, class_code, college, branch, section, semester, password, role, is_cr, cr_type) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING *',
      [email, username, roll_no, class_code, college || null, branch || null, section || null, semester || null, hashedPassword, 'CR', true, cr_type]
    );

    await admin.auth().setCustomUserClaims(newUser.rows[0].id.toString(), {
      role: 'CR',
      class_code: class_code
    });

    if (cr_type === 'regular') {
      await pool.query(
        'INSERT INTO class_codes (code, college, branch, section, created_by) VALUES ($1, $2, $3, $4, $5)',
        [class_code, college, branch, section, newUser.rows[0].id]
      );
    } else {
      const elective = await pool.query(
        'INSERT INTO electives (name, professor, is_open, college, branch, cr_id, semester) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
        [elective_name, elective_professor, elective_type === 'open', elective_college, elective_type === 'core' ? elective_branch : null, newUser.rows[0].id, semester]
      );
      await pool.query(
        'UPDATE users SET cr_elective_id = $1 WHERE id = $2',
        [elective.rows[0].id, newUser.rows[0].id]
      );
      cr_elective_id = elective.rows[0].id;
    }
    await pool.query('COMMIT');

    // Create or update Firebase user
    let firebaseUser;
    try {
      firebaseUser = await admin.auth().getUserByEmail(email);
    } catch (error) {
      if (error.code === 'auth/user-not-found') {
        firebaseUser = await admin.auth().createUser({
          uid: newUser.rows[0].id.toString(),
          email: email,
          password: password
        });
      } else {
        throw error;
      }
    }

    // Set custom claims in Firebase
    await admin.auth().setCustomUserClaims(firebaseUser.uid, {
      role: newUser.rows[0].role.toUpperCase(),
      class_code: newUser.rows[0].class_code,
      cr_type: newUser.rows[0].cr_type,
      cr_elective_id: cr_elective_id || null,
      college: newUser.rows[0].college,
      branch: newUser.rows[0].branch,
      section: newUser.rows[0].section,
      semester: newUser.rows[0].semester,
      is_cr: newUser.rows[0].is_cr
    });

    // Generate Firebase custom token
    const token = await admin.auth().createCustomToken(firebaseUser.uid);

    res.cookie('user-token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 3600 * 1000
    });
    res.status(201).json({
      token,
      role: newUser.rows[0].role.toUpperCase(),
      user_id: newUser.rows[0].id,
      classcode: newUser.rows[0].class_code,
      cr_type: newUser.rows[0].cr_type,
      cr_elective_id: cr_elective_id
    });
  } catch (error) {
    await pool.query('ROLLBACK');
    console.error('Error during CR registration:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

app.post('/api/auth/custom-token', async (req, res) => {
  const { uid } = req.body;

  if (!uid) {
    console.warn('Custom token request missing uid');
    return res.status(400).json({ error: 'UID is required to generate custom token' });
  }

  try {
    // Create Firebase custom token
    const token = await admin.auth().createCustomToken(uid);
    console.log(`Custom token generated for uid: ${uid}`);
    return res.json({ token });
  } catch (err) {
    console.error('Error creating Firebase custom token:', err);
    return res.status(500).json({ error: 'Internal server error: could not create custom token' });
  }
});


// Forgot Password endpoint
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }
    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    const user = userResult.rows[0];
    const resetToken = crypto.randomBytes(32).toString('hex');
    const expires = Date.now() + 3600000;
    await pool.query(
      'UPDATE users SET reset_password_token = $1, reset_password_expires = $2 WHERE id = $3',
      [resetToken, expires, user.id]
    );
    const resetUrl = `${FRONTEND_URL}/reset-password?token=${resetToken}`;
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Password Reset Request',
      html: `
        <p>You requested a password reset for AttendanceTracker.</p>
        <p>Click <a href="${resetUrl}">here</a> to reset your password.</p>
        <p>This link expires in 1 hour.</p>
      `
    });
    res.json({ message: 'Password reset email sent' });
  } catch (error) {
    console.error('Error in forgot password:', error);
    res.status(500).json({ error: 'Failed to send reset email' });
  }
});

// Reset Password endpoint
app.post('/api/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  try {
    if (!token || !newPassword) {
      return res.status(400).json({ error: 'Token and new password are required' });
    }
    const userResult = await pool.query(
      'SELECT * FROM users WHERE reset_password_token = $1 AND reset_password_expires > $2',
      [token, Date.now()]
    );
    if (userResult.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }
    const user = userResult.rows[0];
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query(
      'UPDATE users SET password = $1, reset_password_token = NULL, reset_password_expires = NULL WHERE id = $2',
      [hashedPassword, user.id]
    );
    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error('Error in reset password:', error);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

app.get('/api/profile', authMiddleware, async (req, res) => {
  console.log('Reached /api/profile endpoint for user:', req.user.id);
  try {
    const userId = req.user.id;
    const user = await pool.query(
      `SELECT 
        id, username, email, role, class_code, branch, college, semester, 
        is_cr, cr_elective_id, cr_type,
        TO_CHAR(semester_start_date, 'YYYY-MM-DD') AS semester_start_date, 
        TO_CHAR(semester_end_date, 'YYYY-MM-DD') AS semester_end_date 
      FROM users 
      WHERE id = $1`,
      [userId]
    );
    if (user.rows.length === 0) {
      console.log(`User not found for id: ${userId}`);
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user.rows[0]);
  } catch (err) {
    console.error('Error in /api/profile:', err.stack);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Class code endpoints
app.post('/api/class-codes', authMiddleware, restrictTo('CR'), async (req, res) => {
  const { college, branch } = req.body;
  try {
    if (!college || !branch) {
      return res.status(400).json({ error: 'College and branch are required' });
    }
    let code;
    let isUnique = false;
    while (!isUnique) {
      code = nanoid(6);
      const existing = await pool.query('SELECT id FROM class_codes WHERE code = $1', [code]);
      if (existing.rows.length === 0) {
        isUnique = true;
      }
    }
    const newCode = await pool.query(
      'INSERT INTO class_codes (code, college, branch, created_by) VALUES ($1, $2, $3, $4) RETURNING *',
      [code, college, branch, req.user.id]
    );
    res.status(201).json(newCode.rows[0]);
  } catch (error) {
    console.error('Error creating class code:', error);
    res.status(500).json({ error: 'Failed to create class code' });
  }
});

app.get('/api/class-codes/:code', async (req, res) => {
  const { code } = req.params;
  try {
    const result = await pool.query('SELECT college, branch, section FROM class_codes WHERE code = $1', [code]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Class code not found' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error validating class code:', error);
    res.status(500).json({ error: 'Failed to validate class code' });
  }
});

app.post('/api/class-codes/validate', async (req, res) => {
  const { code } = req.body;
  const schema = require('joi').object({
    code: require('joi').string().min(6).max(6).required()
  });
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }
  try {
    const result = await pool.query('SELECT * FROM class_codes WHERE code = $1', [code]);
    if (result.rows.length === 0) {
      return res.json({ valid: false });
    }
    res.json({ valid: true });
  } catch (err) {
    console.error('Error validating class code:', err);
    res.status(500).json({ error: 'Failed to validate class code', details: err.message });
  }
});

app.post('/api/refresh-token', authMiddleware, async (req, res) => {
  try {
    const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
    const dbUser = userResult.rows[0];
    await admin.auth().setCustomUserClaims(req.user.id, {
      role: dbUser.role.toUpperCase(),
      class_code: dbUser.class_code,
      cr_type: dbUser.cr_type,
      cr_elective_id: dbUser.cr_elective_id || null
    });
    const refreshedToken = await admin.auth().createCustomToken(req.user.id);
    res.json({ token: refreshedToken });
  } catch (error) {
    console.error('Error refreshing token:', error);
    res.status(500).json({ error: 'Failed to refresh token' });
  }
});

// Subjects endpoints
app.get('/api/subjects', authMiddleware, async (req, res) => {
  try {
    if (!req.user || !req.user.class_code) {
      return res.status(400).json({ error: 'User class code not found' });
    }
    const subjects = await pool.query(
      `SELECT s.id, s.name, s.class_code
       FROM subjects s
       WHERE s.class_code = $1`,
      [req.user.class_code]
    );
    res.json(subjects.rows);
  } catch (error) {
    console.error('Error retrieving subjects:', error);
    res.status(500).json({ error: 'Failed to retrieve subjects', details: error.message });
  }
});

app.post('/api/subjects', authMiddleware, restrictTo('CR'), async (req, res) => {
  const { name, professorIds } = req.body;
  const schema = require('joi').object({
    name: require('joi').string().min(3).required(),
    professorIds: require('joi').array().items(require('joi').number().integer()).optional()
  });
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }
  try {
    const classCode = req.user.class_code;
    if (!classCode) {
      return res.status(400).json({ error: 'Class code is missing in user profile' });
    }
    const newSubject = await pool.query(
      'INSERT INTO subjects (name, class_code) VALUES ($1, $2) RETURNING *',
      [name, classCode]
    );
    if (professorIds && professorIds.length > 0) {
      const values = professorIds.map(professorId => `(${newSubject.rows[0].id}, ${professorId})`).join(', ');
      await pool.query(
        `INSERT INTO subject_professors (subject_id, professor_id) VALUES ${values}`
      );
    }
    res.status(201).json(newSubject.rows[0]);
  } catch (err) {
    console.error('Error adding subject:', err);
    res.status(500).json({ error: 'Failed to add subject', details: err.message });
  }
});

app.delete('/api/subjects/:id', authMiddleware, restrictTo('CR'), async (req, res) => {
  const { id } = req.params;
  try {
    const classCode = req.user.class_code;
    if (!classCode) {
      return res.status(400).json({ error: 'Class code is missing in user profile' });
    }
    await pool.query('DELETE FROM subject_professors WHERE subject_id = $1', [id]);
    const result = await pool.query(
      'DELETE FROM subjects WHERE id = $1 AND classcode = $2 RETURNING *',
      [id, classCode]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Subject not found' });
    }
    res.json({ message: 'Subject deleted' });
  } catch (error) {
    console.error('Error deleting subject:', error);
    res.status(500).json({ error: 'Failed to delete subject', details: error.message });
  }
});

// Professors endpoints
app.get('/api/professors', authMiddleware, restrictTo('CR'), async (req, res) => {
  try {
    const professors = await pool.query(
      `SELECT DISTINCT p.* 
       FROM professors p
       LEFT JOIN subject_professors sp ON p.id = sp.professor_id
       LEFT JOIN subjects s ON sp.subject_id = s.id
       WHERE s.class_code = $1 OR p.created_by = $2
       GROUP BY p.id`,
      [req.user.class_code, req.user.id]
    );
    res.json(professors.rows);
  } catch (err) {
    console.error('Error retrieving professors:', err);
    res.status(500).json({ error: 'Failed to retrieve professors', details: err.message });
  }
});

app.post('/api/professors', authMiddleware, restrictTo('CR'), async (req, res) => {
  const { name } = req.body;
  const schema = require('joi').object({
    name: require('joi').string().min(3).required()
  });
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }
  try {
    const newProfessor = await pool.query(
      'INSERT INTO professors (name, created_by) VALUES ($1, $2) RETURNING *',
      [name, req.user.id]
    );
    res.status(201).json(newProfessor.rows[0]);
  } catch (error) {
    console.error('Error adding professor:', error);
    res.status(500).json({ error: 'Failed to add professor', details: err.message });
  }
});

app.delete('/api/professors/:id', authMiddleware, restrictTo('CR'), async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('DELETE FROM subject_professors WHERE professor_id = $1', [id]);
    const result = await pool.query('DELETE FROM professors WHERE id = $1 RETURNING *', [id]);
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Professor not found' });
    }
    res.json({ message: 'Professor deleted' });
  } catch (error) {
    console.error('Error deleting professor:', error);
    res.status(500).json({ error: 'Failed to delete professor' });
  }
});

// Time slots endpoints
app.get('/api/time-slots', authMiddleware, async (req, res) => {
  try {
    let classCode = req.user.class_code;
    if (req.user.cr_type === 'elective') {
      if (!req.user.cr_elective_id) {
        return res.status(400).json({ error: 'No elective assigned to this CR' });
      }
      const elective = await pool.query(
        'SELECT college, branch FROM electives WHERE id = $1 AND cr_id = $2',
        [req.user.cr_elective_id, req.user.id]
      );
      if (elective.rows.length === 0) {
        return res.status(403).json({ error: 'Elective not found or not managed by this CR' });
      }
      const { college, branch } = elective.rows[0];
      const classCodeResult = await pool.query(
        'SELECT code FROM class_codes WHERE college = $1 AND branch = $2 LIMIT 1',
        [college, branch]
      );
      classCode = classCodeResult.rows.length > 0 ? classCodeResult.rows[0].code : null; // Allow null classCode
    }
    const timeSlots = await pool.query(
      `SELECT id, class_code, 
              TO_CHAR(start_time, 'HH24:MI') AS start_time, 
              TO_CHAR(end_time, 'HH24:MI') AS end_time
       FROM time_slots 
       WHERE (class_code = $1 OR class_code IS NULL OR $1 IS NULL)
       ORDER BY start_time ASC`,
      [classCode]
    );
    res.json(timeSlots.rows);
  } catch (error) {
    console.error('Error fetching time slots:', error);
    res.status(500).json({ error: 'Failed to fetch time slots', details: error.message });
  }
});

app.post('/api/time-slots', authMiddleware, restrictTo('CR'), async (req, res) => {
  const { start_time, end_time } = req.body;
  const schema = require('joi').object({
    start_time: require('joi').string().pattern(/^([0-1]?[0-9]|2[0-3]):([0-5][0-9])$/).required(),
    end_time: require('joi').string().pattern(/^([0-1]?[0-9]|2[0-3]):([0-5][0-9])$/).required()
  });
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ error: 'Time must be in HH:mm format (e.g., 09:00)' });
  }
  const start = new Date(`1970-01-01T${start_time}:00Z`);
  const end = new Date(`1970-01-01T${end_time}:00Z`);
  if (start >= end) {
    return res.status(400).json({ error: 'Start time must be before end time' });
  }
  try {
    let classCode = req.user.class_code;
    if (req.user.cr_type === 'elective') {
      if (!req.user.cr_elective_id) {
        return res.status(400).json({ error: 'No elective assigned to this CR' });
      }
      const elective = await pool.query(
        'SELECT college, branch FROM electives WHERE id = $1 AND cr_id = $2',
        [req.user.cr_elective_id, req.user.id]
      );
      if (elective.rows.length === 0) {
        return res.status(403).json({ error: 'Elective not found or not managed by this CR' });
      }
      const { college, branch } = elective.rows[0];
      let classCodeResult = await pool.query(
        'SELECT code FROM class_codes WHERE college = $1 AND branch = $2 LIMIT 1',
        [college, branch]
      );
      if (classCodeResult.rows.length === 0) {
        let isUnique = false;
        while (!isUnique) {
          classCode = nanoid(6);
          const existing = await pool.query('SELECT id FROM class_codes WHERE code = $1', [classCode]);
          if (existing.rows.length === 0) {
            isUnique = true;
          }
        }
        await pool.query(
          'INSERT INTO class_codes (code, college, branch, section, created_by) VALUES ($1, $2, $3, $4, $5)',
          [classCode, college, branch, 'N/A', req.user.id]
        );
      } else {
        classCode = classCodeResult.rows[0].code;
      }
    } else if (!classCode) {
      return res.status(400).json({ error: 'Class code is missing or invalid in user profile' });
    }
    const existingTimeSlot = await pool.query(
      'SELECT id FROM time_slots WHERE class_code = $1 AND start_time = $2 AND end_time = $3',
      [classCode, start_time, end_time]
    );
    if (existingTimeSlot.rows.length > 0) {
      return res.status(400).json({ error: 'A time slot with the same start and end time already exists' });
    }
    const newTimeSlot = await pool.query(
      'INSERT INTO time_slots (class_code, start_time, end_time) VALUES ($1, $2, $3) RETURNING *',
      [classCode, start_time, end_time]
    );
    res.status(201).json(newTimeSlot.rows[0]);
  } catch (error) {
    console.error('Error adding time slot:', error);
    res.status(500).json({ error: 'Failed to add time slot', details: error.message });
  }
});

app.delete('/api/time-slots/:id', authMiddleware, restrictTo('CR'), async (req, res) => {
  const { id } = req.params;
  try {
    let classCode = req.user.class_code;
    if (req.user.cr_type === 'elective') {
      if (!req.user.cr_elective_id) {
        return res.status(400).json({ error: 'No elective assigned to this CR' });
      }
      const elective = await pool.query(
        'SELECT college, branch FROM electives WHERE id = $1 AND cr_id = $2',
        [req.user.cr_elective_id, req.user.id]
      );
      if (elective.rows.length === 0) {
        return res.status(403).json({ error: 'Elective not found or not managed by this CR' });
      }
      const { college, branch } = elective.rows[0];
      const classCodeResult = await pool.query(
        'SELECT code FROM class_codes WHERE college = $1 AND branch = $2 LIMIT 1',
        [college, branch]
      );
      classCode = classCodeResult.rows.length > 0 ? classCodeResult.rows[0].code : null;
    }
    await pool.query(
      'DELETE FROM class_schedules WHERE time_slot_id = $1 AND (class_code = $2 OR class_code IS NULL)',
      [id, classCode]
    );
    const result = await pool.query(
      'DELETE FROM time_slots WHERE id = $1 AND (class_code = $2 OR class_code IS NULL) RETURNING *',
      [id, classCode]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Time slot not found' });
    }
    res.json({ message: 'Time slot deleted' });
  } catch (error) {
    console.error('Error deleting time slot:', error);
    res.status(500).json({ error: 'Failed to delete time slot' });
  }
});

// Holidays endpoints
app.get('/api/holidays', authMiddleware, async (req, res) => {
  try {
    const holidays = await pool.query(
      'SELECT id, class_code, TO_CHAR(holiday_date, \'YYYY-MM-DD\') AS holiday_date, description, created_by FROM holidays WHERE class_code = $1',
      [req.user.class_code]
    );
    res.json(holidays.rows);
  } catch (err) {
    console.error('Error retrieving holidays:', err);
    res.status(500).json({ error: 'Failed to retrieve holidays' });
  }
});

app.post('/api/holidays', authMiddleware, restrictTo('CR'), async (req, res) => {
  const { holiday_date, description } = req.body;
  const schema = require('joi').object({
    holiday_date: require('joi').string().pattern(/^\d{4}-\d{2}-\d{2}$/).required(),
    description: require('joi').string().required()
  });
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }
  try {
    if (!req.user.class_code) {
      return res.status(400).json({ error: 'Class code is missing or invalid in user profile' });
    }
    if (!req.user.id) {
      return res.status(400).json({ error: 'User ID is missing or invalid in user profile' });
    }
    const newHoliday = await pool.query(
      'INSERT INTO holidays (class_code, holiday_date, description, created_by) VALUES ($1, $2, $3, $4) RETURNING *, TO_CHAR(holiday_date, \'YYYY-MM-DD\') AS holiday_date',
      [req.user.class_code, holiday_date, description, req.user.id]
    );
    res.status(201).json(newHoliday.rows[0]);
  } catch (err) {
    console.error('Error adding holiday:', err);
    res.status(500).json({ error: 'Failed to add holiday' });
  }
});

app.patch('/api/holidays/:id', authMiddleware, restrictTo('CR'), async (req, res) => {
  const { id } = req.params;
  const { description } = req.body;
  const schema = require('joi').object({
    description: require('joi').string().required()
  });
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }
  try {
    const updatedHoliday = await pool.query(
      'UPDATE holidays SET description = $1 WHERE id = $2 AND class_code = $3 RETURNING *, TO_CHAR(holiday_date, \'YYYY-MM-DD\') AS holiday_date',
      [description, id, req.user.class_code]
    );
    if (updatedHoliday.rowCount === 0) {
      return res.status(404).json({ error: 'Holiday not found' });
    }
    res.json(updatedHoliday.rows[0]);
  } catch (err) {
    console.error('Error updating holiday:', err);
    res.status(500).json({ error: 'Failed to update holiday' });
  }
});

app.delete('/api/holidays/:id', authMiddleware, restrictTo('CR'), async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM holidays WHERE id = $1 AND class_code = $2 RETURNING *', [id, req.user.class_code]);
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Holiday not found' });
    }
    res.json({ message: 'Holiday deleted' });
  } catch (err) {
    console.error('Error deleting holiday:', err);
    res.status(500).json({ error: 'Failed to delete holiday' });
  }
});

// Class settings endpoint
app.patch('/api/class-settings', authMiddleware, restrictTo('CR'), async (req, res) => {
  const { semester_start_date, semester_end_date } = req.body;
  const schema = require('joi').object({
    semester_start_date: require('joi').string().pattern(/^\d{4}-\d{2}-\d{2}$/).required(),
    semester_end_date: require('joi').string().pattern(/^\d{4}-\d{2}-\d{2}$/).required()
  });
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }
  try {
    if (semester_start_date >= semester_end_date) {
      return res.status(400).json({ error: 'Semester start date must be before end date' });
    }
    const updatedUsers = await pool.query(
      'UPDATE users SET semester_start_date = $1, semester_end_date = $2 WHERE class_code = $3 RETURNING *',
      [semester_start_date, semester_end_date, req.user.class_code]
    );
    if (updatedUsers.rowCount === 0) {
      return res.status(404).json({ error: 'No users found for this class code' });
    }
    res.json({ message: 'Semester dates updated successfully' });
  } catch (error) {
    console.error('Error updating semester dates:', error);
    res.status(500).json({ error: 'Failed to update semester dates' });
  }
});

// In index.js (around line 1100)
app.get('/api/electives/available', authMiddleware, restrictTo('STUDENT'), async (req, res) => {
  try {
    const { semester } = req.query;
    const { college, branch, semester: userSemester, id: studentId } = req.user;
    const currentSemester = semester || userSemester || '7';
    const electives = await pool.query(
      `SELECT e.id, e.name, e.is_open, e.branch, e.semester, e.college
       FROM electives e
       WHERE e.college = $1
       AND ((e.is_open = true AND (e.semester IS NULL OR e.semester = $3))
            OR (e.is_open = false AND e.branch = $2 AND e.semester = $3))
       AND NOT EXISTS (
         SELECT 1
         FROM student_electives se
         WHERE se.elective_id = e.id
         AND se.student_id = $4
         AND se.status = 'enrolled'
       )`,
      [college, branch, currentSemester, studentId]
    );
    const mockElectives = [
      { id: 1, name: 'Machine Learning', is_open: true, branch: null, semester: currentSemester, college },
      { id: 2, name: 'Data Structures', is_open: false, branch, semester: currentSemester, college },
      { id: 3, name: 'Artificial Intelligence', is_open: true, branch: null, semester: currentSemester, college }
    ];
    res.json(electives.rows.length > 0 ? electives.rows : mockElectives);
  } catch (error) {
    console.error('Error fetching available electives:', error);
    res.status(500).json({ error: 'Failed to fetch available electives', details: error.message });
  }
});

app.post('/api/electives/select', authMiddleware, restrictTo('STUDENT'), async (req, res) => {
  const schema = require('joi').object({
    elective_id: require('joi').number().integer().required()
  });
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }
  const { elective_id } = req.body;
  const student_id = req.user.id;
  try {
    const currentEnrollments = await pool.query(
      'SELECT * FROM student_electives WHERE student_id = $1 AND status = $2',
      [student_id, 'enrolled']
    );
    if (currentEnrollments.rows.length >= 3) {
      return res.status(400).json({ error: 'You cannot enroll in more than 3 electives' });
    }
    const elective = await pool.query(
      'SELECT id, name, is_open, branch, semester, college FROM electives WHERE id = $1',
      [elective_id]
    );
    if (elective.rows.length === 0) {
      return res.status(404).json({ error: 'Elective not found' });
    }
    const { college, branch } = req.user;
    const selectedElective = elective.rows[0];
    if (selectedElective.college !== college || (!selectedElective.is_open && selectedElective.branch !== branch)) {
      return res.status(403).json({ error: 'You are not eligible to enroll in this elective' });
    }
    const existingEnrollment = await pool.query(
      'SELECT * FROM student_electives WHERE student_id = $1 AND elective_id = $2',
      [student_id, elective_id]
    );
    if (existingEnrollment.rows.length > 0) {
      if (existingEnrollment.rows[0].status === 'enrolled') {
        return res.status(400).json({ error: 'You are already enrolled in this elective' });
      }
      await pool.query(
        'UPDATE student_electives SET status = $1 WHERE student_id = $2 AND elective_id = $3',
        ['enrolled', student_id, elective_id]
      );
    } else {
      await pool.query(
        'INSERT INTO student_electives (student_id, elective_id, status) VALUES ($1, $2, $3)',
        [student_id, elective_id, 'enrolled']
      );
    }
    res.json({ message: 'Elective selected successfully' });
  } catch (error) {
    console.error('Error selecting elective:', error);
    res.status(500).json({ error: 'Failed to select elective', details: error.message });
  }
});

app.get('/api/electives/selected', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const electives = await pool.query(
      'SELECT e.id, e.name, e.semester, e.branch, e.is_open, se.status FROM electives e JOIN student_electives se ON e.id = se.elective_id WHERE se.student_id = $1',
      [userId]
    );
    res.json(electives.rows);
  } catch (error) {
    console.error('Error fetching selected electives:', error);
    res.status(500).json({ error: 'Failed to fetch selected electives', details: error.message });
  }
});

app.post('/api/electives/drop', authMiddleware, restrictTo('STUDENT'), async (req, res) => {
  const schema = require('joi').object({
    elective_id: require('joi').number().integer().required()
  });
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }
  const { elective_id } = req.body;
  const student_id = req.user.id;
  try {
    const enrollment = await pool.query(
      'SELECT * FROM student_electives WHERE student_id = $1 AND elective_id = $2 AND status = $3',
      [student_id, elective_id, 'enrolled']
    );
    if (enrollment.rows.length === 0) {
      return res.status(400).json({ error: 'You are not enrolled in this elective or it is already dropped' });
    }
    await pool.query(
      'UPDATE student_electives SET status = $1 WHERE student_id = $2 AND elective_id = $3',
      ['dropped', student_id, elective_id]
    );
    res.json({ message: 'Elective dropped successfully' });
  } catch (error) {
    console.error('Error in /api/electives/drop:', error);
    res.status(500).json({ error: 'Failed to drop elective', details: error.message });
  }
});

app.post('/api/electives/swap', authMiddleware, restrictTo('STUDENT'), async (req, res) => {
  const schema = require('joi').object({
    old_elective_id: require('joi').number().integer().required(),
    new_elective_id: require('joi').number().integer().required()
  });
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }
  const { old_elective_id, new_elective_id } = req.body;
  const student_id = req.user.id;
  try {
    const oldEnrollment = await pool.query(
      'SELECT * FROM student_electives WHERE student_id = $1 AND elective_id = $2 AND status = $3',
      [student_id, old_elective_id, 'enrolled']
    );
    if (oldEnrollment.rows.length === 0) {
      return res.status(400).json({ error: 'You are not enrolled in the old elective' });
    }
    const newElective = await pool.query(
      'SELECT id, name, is_open, branch, semester, college FROM electives WHERE id = $1',
      [new_elective_id]
    );
    if (newElective.rows.length === 0) {
      return res.status(404).json({ error: 'New elective not found' });
    }
    const { college, branch } = req.user;
    const selectedElective = newElective.rows[0];
    if (selectedElective.college !== college || (!selectedElective.is_open && selectedElective.branch !== branch)) {
      return res.status(403).json({ error: 'You are not eligible to enroll in the new elective' });
    }
    const existingEnrollment = await pool.query(
      'SELECT * FROM student_electives WHERE student_id = $1 AND elective_id = $2',
      [student_id, new_elective_id]
    );
    if (existingEnrollment.rows.length > 0 && existingEnrollment.rows[0].status === 'enrolled') {
      return res.status(400).json({ error: 'You are already enrolled in the new elective' });
    }
    await pool.query(
      'UPDATE student_electives SET status = $1 WHERE student_id = $2 AND elective_id = $3',
      ['dropped', student_id, old_elective_id]
    );
    if (existingEnrollment.rows.length > 0) {
      await pool.query(
        'UPDATE student_electives SET status = $1 WHERE student_id = $2 AND elective_id = $3',
        ['enrolled', student_id, new_elective_id]
      );
    } else {
      await pool.query(
        'INSERT INTO student_electives (student_id, elective_id, status) VALUES ($1, $2, $3)',
        [student_id, new_elective_id, 'enrolled']
      );
    }
    res.json({ message: 'Elective swapped successfully' });
  } catch (error) {
    console.error('Error swapping elective:', error);
    res.status(500).json({ error: 'Failed to swap elective', details: error.message });
  }
});

app.get('/api/electives/managed', authMiddleware, restrictTo('CR'), async (req, res) => {
  try {
    if (!req.user || !req.user.id) {
      console.log('req.user or user.id missing in /api/electives/managed:', req.user);
      return res.status(401).json({ error: 'Invalid user ID in token' });
    }
    const cr_id = req.user.id;
    const userCheck = await pool.query(
      'SELECT is_cr, cr_elective_id FROM users WHERE id = $1 AND is_cr = true',
      [cr_id]
    );
    if (userCheck.rows.length === 0) {
      return res.status(403).json({ error: 'User is not a Class Representative' });
    }
    const elective = await pool.query(
      `SELECT id, name, is_open, branch, semester, college, professor, schedule 
       FROM electives 
       WHERE cr_id = $1`,
      [cr_id]
    );
    if (elective.rows.length === 0) {
      return res.status(404).json({ error: 'No elective found for this CR' });
    }
    res.json(elective.rows);
  } catch (error) {
    console.error(`Error fetching managed elective for CR ID ${req.user?.id || 'unknown'}:`, error);
    res.status(500).json({ error: 'Failed to fetch managed elective', details: error.message });
  }
});

app.post('/api/electives/volunteer', authMiddleware, restrictTo('STUDENT'), async (req, res) => {
  const schema = require('joi').object({
    elective_id: require('joi').number().integer().required()
  });
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }
  const { elective_id } = req.body;
  const student_id = req.user.id;
  try {
    const elective = await pool.query(
      'SELECT * FROM electives WHERE id = $1 AND cr_id IS NULL',
      [elective_id]
    );
    if (elective.rows.length === 0) {
      return res.status(400).json({ error: 'Elective not found or already has a CR' });
    }
    const existingCR = await pool.query(
      'SELECT * FROM users WHERE id = $1 AND is_cr = true',
      [student_id]
    );
    if (existingCR.rows.length > 0) {
      return res.status(400).json({ error: 'You are already a CR for another elective' });
    }
    await pool.query(
      'UPDATE electives SET cr_id = $1 WHERE id = $2',
      [student_id, elective_id]
    );
    await pool.query(
      'UPDATE users SET is_cr = true, cr_elective_id = $1, role = $2 WHERE id = $3',
      [elective_id, 'CR', student_id]
    );
    res.json({ message: 'Successfully volunteered as CR' });
  } catch (error) {
    console.error('Error volunteering as CR:', error);
    res.status(500).json({ error: 'Failed to volunteer as CR' });
  }
});

app.get('/api/electives/enrolled', authMiddleware, restrictTo('STUDENT'), async (req, res) => {
  try {
    const studentId = req.user.id; // From authMiddleware
    const electives = await pool.query(
      `SELECT e.id, e.name, e.semester, e.branch, e.is_open, e.college, se.status 
       FROM electives e 
       JOIN student_electives se ON e.id = se.elective_id 
       WHERE se.student_id = $1 
       AND se.status = 'enrolled'`,
      [studentId]
    );
    res.json(electives.rows);
  } catch (error) {
    console.error('Error fetching enrolled electives:', error);
    res.status(500).json({ error: 'Failed to fetch enrolled electives', details: error.message });
  }
});

// Class schedules endpoint
app.post('/api/class-schedules', authMiddleware, restrictTo('CR'), async (req, res) => {
  const schema = require('joi').object({
    subject_id: require('joi').number().integer().optional(),
    elective_id: require('joi').number().integer().optional(),
    specific_date: require('joi').string().pattern(/^\d{4}-\d{2}-\d{2}$/).optional().allow(null),
    time_slot_id: require('joi').number().integer().required(),
    repeat_option: require('joi').string().valid('no-repeat', 'weekly').required(),
    canceled: require('joi').boolean().optional(),
    day_of_week: require('joi').string().valid('Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday').optional().allow(null),
    start_date: require('joi').string().pattern(/^\d{4}-\d{2}-\d{2}$/).optional().allow(null),
    end_date: require('joi').string().pattern(/^\d{4}-\d{2}-\d{2}$/).optional().allow(null)
  });
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }
  const { subject_id, elective_id, specific_date, time_slot_id, repeat_option, canceled, day_of_week, start_date, end_date } = req.body;
  try {
    let classCode = req.user.class_code;
    if (elective_id) {
      const elective = await pool.query(
        'SELECT college, branch FROM electives WHERE id = $1 AND cr_id = $2',
        [elective_id, req.user.id]
      );
      if (elective.rows.length === 0) {
        return res.status(403).json({ error: 'You are not authorized to manage this elective' });
      }
      const { college, branch } = elective.rows[0];
      let classCodeResult = await pool.query(
        'SELECT code FROM class_codes WHERE college = $1 AND branch = $2 LIMIT 1',
        [college, branch]
      );
      if (classCodeResult.rows.length === 0) {
        let isUnique = false;
        while (!isUnique) {
          classCode = nanoid(6);
          const existing = await pool.query('SELECT id FROM class_codes WHERE code = $1', [classCode]);
          if (existing.rows.length === 0) {
            isUnique = true;
          }
        }
        await pool.query(
          'INSERT INTO class_codes (code, college, branch, section, created_by) VALUES ($1, $2, $3, $4, $5)',
          [classCode, college, branch, 'N/A', req.user.id]
        );
      } else {
        classCode = classCodeResult.rows[0].code;
      }
      if (specific_date) {
        const conflict = await pool.query(
          `SELECT cs.id 
           FROM class_schedules cs
           JOIN student_electives se ON cs.elective_id = se.elective_id
           WHERE cs.elective_id != $1 
           AND cs.specific_date = $2 
           AND cs.time_slot_id = $3 
           AND cs.canceled = false
           AND se.student_id IN (
             SELECT student_id FROM student_electives WHERE elective_id = $1 AND status = 'enrolled'
           )`,
          [elective_id, specific_date, time_slot_id]
        );
        if (conflict.rows.length > 0) {
          return res.status(400).json({ error: 'Another elective is scheduled for the same students in this time slot' });
        }
      } else if (day_of_week && start_date && end_date) {
        const conflict = await pool.query(
          `SELECT cs.id 
           FROM class_schedules cs
           JOIN student_electives se ON cs.elective_id = se.elective_id
           WHERE cs.elective_id != $1 
           AND cs.day_of_week = $2 
           AND cs.time_slot_id = $3 
           AND cs.canceled = false
           AND cs.start_date <= $5 
           AND cs.end_date >= $4
           AND se.student_id IN (
             SELECT student_id FROM student_electives WHERE elective_id = $1 AND status = 'enrolled'
           )`,
          [elective_id, day_of_week, time_slot_id, start_date, end_date]
        );
        if (conflict.rows.length > 0) {
          return res.status(400).json({ error: 'Another elective is scheduled for the same students in this time slot' });
        }
      }
    }
    if ((subject_id && elective_id) || (!subject_id && !elective_id)) {
      return res.status(400).json({ error: 'Provide either subject_id or elective_id, not both or neither' });
    }
    if (req.user.cr_type === 'regular' && !classCode && !elective_id) {
      return res.status(400).json({ error: 'Class code is missing or invalid in user profile' });
    }
    const normalizedSpecificDate = specific_date ? moment.tz(specific_date, 'YYYY-MM-DD', 'Asia/Kolkata').format('YYYY-MM-DD') : null;
    const normalizedStartDate = start_date ? moment.tz(start_date, 'YYYY-MM-DD', 'Asia/Kolkata').format('YYYY-MM-DD') : null;
    const normalizedEndDate = end_date ? moment.tz(end_date, 'YYYY-MM-DD', 'Asia/Kolkata').format('YYYY-MM-DD') : null;
    if (specific_date && (day_of_week || start_date || end_date)) {
      return res.status(400).json({ error: 'day_of_week, start_date, and end_date must be null when specific_date is provided' });
    }
    if (day_of_week && (!start_date || !end_date)) {
      return res.status(400).json({ error: 'start_date and end_date are required when day_of_week is provided' });
    }
    if (!specific_date && !day_of_week) {
      return res.status(400).json({ error: 'Either specific_date or day_of_week must be provided' });
    }
    if (normalizedSpecificDate) {
      await pool.query(
        'DELETE FROM class_schedules WHERE (class_code = $1 OR elective_id IN (SELECT id FROM electives WHERE cr_id = $2)) AND specific_date = $3::DATE AND time_slot_id = $4',
        [classCode, req.user.id, normalizedSpecificDate, time_slot_id]
      );
    } else if (day_of_week && normalizedStartDate && normalizedEndDate) {
      await pool.query(
        'DELETE FROM class_schedules WHERE (class_code = $1 OR elective_id IN (SELECT id FROM electives WHERE cr_id = $2)) AND day_of_week = $3 AND time_slot_id = $4 AND start_date = $5::DATE AND end_date = $6::DATE',
        [classCode, req.user.id, day_of_week, time_slot_id, normalizedStartDate, normalizedEndDate]
      );
    }
    const newSchedule = await pool.query(
      `INSERT INTO class_schedules 
       (class_code, subject_id, elective_id, specific_date, time_slot_id, repeat_option, canceled, day_of_week, start_date, end_date) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) 
       RETURNING *, 
              TO_CHAR(specific_date, 'YYYY-MM-DD') AS specific_date, 
              TO_CHAR(start_date, 'YYYY-MM-DD') AS start_date, 
              TO_CHAR(end_date, 'YYYY-MM-DD') AS end_date`,
      [classCode, subject_id || null, elective_id || null, normalizedSpecificDate, time_slot_id, repeat_option, canceled || false, day_of_week, normalizedStartDate, normalizedEndDate]
    );
    res.status(201).json(newSchedule.rows[0]);
  } catch (error) {
    console.error('Error adding class schedule:', error);
    res.status(500).json({ error: 'Failed to add class schedule', details: error.message });
  }
});

app.get('/api/class-schedules', authMiddleware, restrictTo('CR'), async (req, res) => {
  try {
    if (!req.user || !req.user.class_code) {
      console.log('req.user or class_code missing:', req.user);
      return res.status(400).json({ error: 'User class code not found' });
    }
    const user = req.user;
    const coreSchedules = await pool.query(
      `SELECT cs.*, 
              TO_CHAR(cs.specific_date, 'YYYY-MM-DD') AS specific_date,
              TO_CHAR(cs.start_date, 'YYYY-MM-DD') AS start_date,
              TO_CHAR(cs.end_date, 'YYYY-MM-DD') AS end_date,
              s.name as subject_name, 
              ts.start_time, 
              ts.end_time,
              array_agg(p.name) as professor_names 
       FROM class_schedules cs
       LEFT JOIN subjects s ON cs.subject_id = s.id
       JOIN time_slots ts ON cs.time_slot_id = ts.id
       LEFT JOIN subject_professors sp ON s.id = sp.subject_id
       LEFT JOIN professors p ON sp.professor_id = p.id
       WHERE cs.class_code = $1 AND cs.elective_id IS NULL
       GROUP BY cs.id, s.name, ts.start_time, ts.end_time`,
      [user.class_code]
    );
    const electiveSchedules = await pool.query(
      `SELECT cs.*, 
              TO_CHAR(specific_date, 'YYYY-MM-DD') AS specific_date,
              TO_CHAR(start_date, 'YYYY-MM-DD') AS start_date,
              TO_CHAR(end_date, 'YYYY-MM-DD') AS end_date,
              e.name as subject_name, 
              ts.start_time, 
              ts.end_time,
              NULL as professor_names
       FROM class_schedules cs
       JOIN electives e ON cs.elective_id = e.id
       JOIN time_slots ts ON cs.time_slot_id = ts.id
       JOIN student_electives se ON cs.elective_id = e.id
       WHERE se.student_id = $1 
       AND se.status = 'enrolled'
       GROUP BY cs.id, e.name, ts.start_time, ts.end_time`,
      [user.id]
    );
    const schedules = [...coreSchedules.rows, ...electiveSchedules.rows];
    res.json(schedules);
  } catch (error) {
    console.error('Error fetching class schedules:', error);
    res.status(500).json({ error: 'Failed to fetch class schedules', details: error.message });
  }
});

app.get('/api/today-classes', authMiddleware, restrictTo('STUDENT'), async (req, res) => {
  const { date } = req.query;
  const today = date ? moment.tz(date, 'YYYY-MM-DD', 'Asia/Kolkata').toDate() : moment.tz('Asia/Kolkata').toDate();
  const todayStr = moment(today).format('YYYY-MM-DD');
  const dayOfWeek = moment(today).format('dddd');
  try {
    const cancellations = await pool.query(
      `SELECT cs.id, cs.subject_id, cs.elective_id, cs.time_slot_id 
       FROM class_schedules cs 
       WHERE cs.specific_date = $1 
       AND cs.canceled = true 
       AND (cs.class_code = $2 OR cs.elective_id IN (
           SELECT elective_id FROM student_electives WHERE student_id = $3 AND status = 'enrolled'
       ))`,
      [todayStr, req.user.class_code, req.user.id]
    );
    const canceledKeys = new Set(cancellations.rows.map(row => `${row.subject_id || row.elective_id}-${row.time_slot_id}`));
    const coreSingleClasses = await pool.query(
      `SELECT cs.*, 
              s.name AS subject_name, 
              ts.start_time, 
              ts.end_time 
       FROM class_schedules cs
       LEFT JOIN subjects s ON cs.subject_id = s.id
       JOIN time_slots ts ON cs.time_slot_id = ts.id
       WHERE cs.specific_date = $1 
       AND cs.class_code = $2 
       AND cs.elective_id IS NULL
       AND cs.canceled = false`,
      [todayStr, req.user.class_code]
    );
    const electiveSingleClasses = await pool.query(
      `SELECT cs.*, 
              e.name AS subject_name, 
              ts.start_time, 
              ts.end_time 
       FROM class_schedules cs
       JOIN electives e ON cs.elective_id = e.id
       JOIN time_slots ts ON cs.time_slot_id = ts.id
       JOIN student_electives se ON e.id = se.elective_id
       WHERE cs.specific_date = $1 
       AND se.student_id = $2 
       AND se.status = 'enrolled'
       AND cs.canceled = false`,
      [todayStr, req.user.id]
    );
    const coreRecurringClasses = await pool.query(
      `SELECT cs.*, 
              s.name AS subject_name, 
              ts.start_time, 
              ts.end_time 
       FROM class_schedules cs
       LEFT JOIN subjects s ON cs.subject_id = s.id
       JOIN time_slots ts ON cs.time_slot_id = ts.id
       WHERE cs.day_of_week = $1
       AND cs.start_date <= $2
       AND cs.end_date >= $2
       AND cs.class_code = $3
       AND cs.elective_id IS NULL
       AND cs.canceled = false`,
      [dayOfWeek, todayStr, req.user.class_code]
    );
    const electiveRecurringClasses = await pool.query(
      `SELECT cs.*, 
              e.name AS subject_name, 
              ts.start_time, 
              ts.end_time 
       FROM class_schedules cs
       JOIN electives e ON cs.elective_id = e.id
       JOIN time_slots ts ON cs.time_slot_id = ts.id
       JOIN student_electives se ON cs.elective_id = se.elective_id
       WHERE cs.day_of_week = $1
       AND cs.start_date <= $2
       AND cs.end_date >= $2
       AND se.student_id = $3
       AND se.status = 'enrolled'
       AND cs.canceled = false`,
      [dayOfWeek, todayStr, req.user.id]
    );
    const filteredCoreRecurring = coreRecurringClasses.rows.filter(cls => {
      const key = `${cls.subject_id || cls.elective_id}-${cls.time_slot_id}`;
      return !canceledKeys.has(key);
    });
    const filteredElectiveRecurring = electiveRecurringClasses.rows.filter(cls => {
      const key = `${cls.subject_id || cls.elective_id}-${cls.time_slot_id}`;
      return !canceledKeys.has(key);
    });
    const classes = [
      ...coreSingleClasses.rows,
      ...electiveSingleClasses.rows,
      ...filteredCoreRecurring,
      ...filteredElectiveRecurring
    ];
    res.json(classes);
  } catch (error) {
    console.error('Error fetching today’s classes:', error);
    res.status(500).json({ error: 'Failed to fetch today’s classes' });
  }
});

app.get('/api/classes/semester', authMiddleware, restrictTo(['STUDENT']), async (req, res) => {
  try {
    const userResult = await pool.query(
      'SELECT semester_start_date, semester_end_date FROM users WHERE id = $1',
      [req.user.id]
    );

    const user = userResult.rows[0];
    if (!user || !user.semester_start_date || !user.semester_end_date) {
      return res.status(400).json({ error: 'Missing semester start or end date' });
    }

    const semesterStartDate = user.semester_start_date;
    const today = moment.tz('Asia/Kolkata').format('YYYY-MM-DD');
    const endDate = user.semester_end_date < today ? user.semester_end_date : today;

    // 🔹 Core (non-elective) classes
    const coreSchedules = await pool.query(
      `SELECT cs.*, 
              TO_CHAR(cs.specific_date, 'YYYY-MM-DD') AS specific_date,
              TO_CHAR(cs.start_date, 'YYYY-MM-DD') AS start_date,
              TO_CHAR(cs.end_date, 'YYYY-MM-DD') AS end_date,
              s.name AS subject_name, 
              TO_CHAR(ts.start_time, 'HH24:MI') AS start_time, 
              TO_CHAR(ts.end_time, 'HH24:MI') AS end_time,
              ARRAY_AGG(DISTINCT p.name) AS professor_names
       FROM class_schedules cs
       LEFT JOIN subjects s ON cs.subject_id = s.id
       JOIN time_slots ts ON cs.time_slot_id = ts.id
       LEFT JOIN subject_professors sp ON s.id = sp.subject_id
       LEFT JOIN professors p ON sp.professor_id = p.id
       WHERE cs.class_code = $1
         AND cs.elective_id IS NULL
         AND (
           (cs.specific_date IS NOT NULL AND cs.specific_date >= $2 AND cs.specific_date <= $3)
           OR (cs.day_of_week IS NOT NULL AND cs.start_date <= $3 AND cs.end_date >= $2)
         )
         AND (cs.canceled = false OR cs.canceled IS NULL)
       GROUP BY cs.id, s.name, ts.start_time, ts.end_time
       ORDER BY ts.start_time`,
      [req.user.class_code, semesterStartDate, endDate]
    );

    // 🔹 Elective classes
    const electiveSchedules = await pool.query(
  `SELECT 
      cs.*, 
      TO_CHAR(cs.specific_date, 'YYYY-MM-DD') AS specific_date,
      TO_CHAR(cs.start_date, 'YYYY-MM-DD') AS start_date,
      TO_CHAR(cs.end_date, 'YYYY-MM-DD') AS end_date,
      e.name AS subject_name, 
      TO_CHAR(ts.start_time, 'HH24:MI') AS start_time, 
      TO_CHAR(ts.end_time, 'HH24:MI') AS end_time,
      ARRAY_AGG(e.professor) AS professor_names
   FROM class_schedules cs
   JOIN electives e ON cs.elective_id = e.id
   JOIN time_slots ts ON cs.time_slot_id = ts.id
   JOIN student_electives se ON cs.elective_id = se.elective_id
   WHERE se.student_id = $1
     AND se.status = 'enrolled'
     AND (
         (cs.specific_date IS NOT NULL AND cs.specific_date >= $2 AND cs.specific_date <= $3)
         OR (cs.day_of_week IS NOT NULL AND cs.start_date <= $3 AND cs.end_date >= $2)
     )
     AND (cs.canceled = false OR cs.canceled IS NULL)
   GROUP BY 
     cs.id, 
     e.name, 
     ts.start_time, 
     ts.end_time
   ORDER BY ts.start_time`,
  [req.user.id, semesterStartDate, endDate]
);


    const classes = [...coreSchedules.rows, ...electiveSchedules.rows];
    res.json(classes);
  } catch (error) {
    console.error('Error fetching semester classes:', error);
    res.status(500).json({
      error: 'Failed to fetch semester classes',
      details: error.message
    });
  }
});

app.get('/api/elective-schedules', authMiddleware, async (req, res) => {
  try {
    const userRole = req.user.role?.toUpperCase();
    const crType = req.user.cr_type?.toLowerCase();
    let result;

    if (userRole === 'STUDENT') {
      result = await pool.query(
        `SELECT cs.*, 
                TO_CHAR(cs.specific_date, 'YYYY-MM-DD') AS specific_date,
                TO_CHAR(cs.start_date, 'YYYY-MM-DD') AS start_date,
                TO_CHAR(cs.end_date, 'YYYY-MM-DD') AS end_date,
                e.name AS elective_name,
                TO_CHAR(ts.start_time, 'HH24:MI') AS start_time,
                TO_CHAR(ts.end_time, 'HH24:MI') AS end_time,
                ARRAY_AGG(DISTINCT e.professor) AS professor_names
         FROM class_schedules cs
         JOIN electives e ON cs.elective_id = e.id
         JOIN time_slots ts ON cs.time_slot_id = ts.id
         JOIN student_electives se ON cs.elective_id = se.elective_id
         WHERE se.student_id = $1
           AND se.status = 'enrolled'
           AND (cs.canceled = false OR cs.canceled IS NULL)
         GROUP BY cs.id, e.name, ts.start_time, ts.end_time
         ORDER BY ts.start_time`,
        [req.user.id]
      );
    } else if (userRole === 'CR' && crType === 'elective') {
      if (!req.user.cr_elective_id) {
        return res.status(400).json({ error: 'No elective assigned to this CR' });
      }
      result = await pool.query(
        `SELECT cs.*, 
                TO_CHAR(cs.specific_date, 'YYYY-MM-DD') AS specific_date,
                TO_CHAR(cs.start_date, 'YYYY-MM-DD') AS start_date,
                TO_CHAR(cs.end_date, 'YYYY-MM-DD') AS end_date,
                e.name AS elective_name,
                TO_CHAR(ts.start_time, 'HH24:MI') AS start_time,
                TO_CHAR(ts.end_time, 'HH24:MI') AS end_time,
                ARRAY_AGG(DISTINCT e.professor) AS professor_names
         FROM class_schedules cs
         JOIN electives e ON cs.elective_id = e.id
         JOIN time_slots ts ON cs.time_slot_id = ts.id
         WHERE cs.elective_id = $1
           AND e.cr_id = $2
           AND (cs.canceled = false OR cs.canceled IS NULL)
         GROUP BY cs.id, e.name, ts.start_time, ts.end_time
         ORDER BY ts.start_time`,
        [req.user.cr_elective_id, req.user.id]
      );
    } else {
      return res.status(403).json({ error: 'Unauthorized: Access restricted to students or Elective CRs' });
    }

    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching elective schedules:', err);
    res.status(500).json({ error: 'Failed to fetch elective schedules', details: err.message });
  }
});


app.post('/api/attendance', authMiddleware, restrictTo(['STUDENT']), async (req, res) => {
  const entries = Array.isArray(req.body) ? req.body : [req.body];
  const schema = Joi.object({
    class_id: Joi.number().integer().required(),
    date: Joi.string().pattern(/^\d{4}-\d{2}-\d{2}$/).required(),
    status: Joi.string().valid('present', 'absent').required(),
    reason: Joi.string().optional().allow(null, '')
  });
  const results = [];
  try {
    const today = moment.tz('Asia/Kolkata').format('YYYY-MM-DD');
    for (const entry of entries) {
      const { error } = schema.validate(entry);
      if (error) {
        return res.status(400).json({ error: error.details[0].message });
      }
      const { class_id, date, status, reason } = entry;
      const istDate = moment.tz(date, 'YYYY-MM-DD', 'Asia/Kolkata').format('YYYY-MM-DD');
      if (istDate > today) {
        return res.status(400).json({ error: 'Cannot mark attendance for future dates' });
      }
      const classCheck = await pool.query(
        `SELECT cs.id 
         FROM class_schedules cs
         LEFT JOIN student_electives se ON cs.elective_id = se.elective_id 
         WHERE cs.id = $1 
         AND (cs.class_code = $2 OR (se.student_id = $3 AND se.status = 'enrolled'))`,
        [class_id, req.user.class_code, req.user.id]
      );
      if (classCheck.rowCount === 0) {
        return res.status(403).json({ error: 'Class does not belong to your schedule' });
      }
      const existingAttendance = await pool.query(
        'SELECT id FROM attendance WHERE student_id = $1 AND class_id = $2 AND date = $3',
        [req.user.id, class_id, istDate]
      );
      let attendance;
      if (existingAttendance.rowCount > 0) {
        attendance = await pool.query(
          'UPDATE attendance SET status = $1, reason = $2, created_at = CURRENT_TIMESTAMP WHERE student_id = $3 AND class_id = $4 AND date = $5 RETURNING *, TO_CHAR(date, \'YYYY-MM-DD\') AS date_str',
          [status, reason || null, req.user.id, class_id, istDate]
        );
      } else {
        attendance = await pool.query(
          'INSERT INTO attendance (student_id, class_id, date, status, reason) VALUES ($1, $2, $3, $4, $5) RETURNING *, TO_CHAR(date, \'YYYY-MM-DD\') AS date_str',
          [req.user.id, class_id, istDate, status, reason || null]
        );
      }
      results.push(attendance.rows[0]);
    }
    res.status(201).json(results);
  } catch (error) {
    console.error('Error saving attendance:', error);
    res.status(500).json({ error: 'Failed to save attendance', details: error.message });
  }
});

app.get('/api/attendance', authMiddleware, restrictTo(['STUDENT']), async (req, res) => {
  const { start_date, end_date } = req.query;
  const schema = Joi.object({
    start_date: Joi.string().pattern(/^\d{4}-\d{2}-\d{2}$/).required(),
    end_date: Joi.string().pattern(/^\d{4}-\d{2}-\d{2}$/).required()
  });
  const { error } = schema.validate(req.query);
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }
  try {
    const attendance = await pool.query(
      `SELECT a.*, 
              TO_CHAR(a.date, 'YYYY-MM-DD') AS date_str,
              cs.specific_date, cs.day_of_week, cs.start_date, cs.end_date, cs.time_slot_id, 
              COALESCE(s.name, e.name) as subject_name,
              ts.start_time, 
              ts.end_time
       FROM attendance a
       JOIN class_schedules cs ON a.class_id = cs.id
       LEFT JOIN subjects s ON cs.subject_id = s.id
       LEFT JOIN electives e ON cs.elective_id = e.id
       JOIN time_slots ts ON cs.time_slot_id = ts.id
       WHERE a.student_id = $1
       AND a.date BETWEEN $2 AND $3
       AND (cs.class_code = $4 OR cs.elective_id IN (
           SELECT elective_id FROM student_electives WHERE student_id = $1 AND status = 'enrolled'
       ))
       ORDER BY a.date, ts.start_time`,
      [req.user.id, start_date, end_date, req.user.class_code]
    );
    res.json(attendance.rows);
  } catch (error) {
    console.error('Error retrieving attendance:', error);
    res.status(500).json({ error: 'Failed to retrieve attendance', details: error.message });
  }
});

app.get('/api/attendance/reasons', authMiddleware, restrictTo(['STUDENT']), async (req, res) => {
  try {
    const defaultReasons = ['Health Issue', 'Placement Drive'];
    const customReasons = await pool.query(
      'SELECT DISTINCT reason FROM attendance WHERE student_id = $1 AND reason IS NOT NULL AND reason NOT IN ($2, $3)',
      [req.user.id, ...defaultReasons]
    );
    const reasons = [...defaultReasons, ...customReasons.rows.map(row => row.reason)];
    res.json(reasons);
  } catch (error) {
    console.error('Error retrieving absence reasons:', error);
    res.status(500).json({ error: 'Failed to retrieve absence reasons', details: error.message });
  }
});


app.use('/Uploads', express.static(path.join(__dirname, 'Uploads')));





// Initialize Firebase Admin SDK (ensure service account key is set up)
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(require('/Users/manoharkandula/Downloads/service-account-key.json')),
    storageBucket: "prezz-5581d.firebasestorage.app"
  });
}

const db = admin.firestore();
const storage = admin.storage();

app.get('/api/chat/messages', async (req, res) => {
  const { classcode } = req.query;
  if (!classcode) return res.status(400).json({ error: 'Classcode required' });

  try {
    const messagesRef = db.collection(`chats/class_${classcode}/messages`);
    const snapshot = await messagesRef.orderBy('createdAt', 'asc').get();
    const messages = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }));
    res.json(messages);
  } catch (error) {
    console.error('Error fetching messages:', error);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

app.post('/api/chat/send', upload.single('media'), async (req, res) => {
  console.time('chat-send');
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'No token provided' });

    const decoded = await admin.auth().verifyIdToken(token);
    const userId = decoded.uid;

    const user = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
    if (!user.rows[0]) return res.status(401).json({ error: 'User not found' });

    let payload;
    try {
      payload = req.file ? JSON.parse(req.body.message) : req.body;
    } catch (e) {
      return res.status(400).json({ error: 'Invalid message format' });
    }

    const { message, classcode, userId: sentUserId } = payload;
    if (!classcode || sentUserId !== userId) {
      return res.status(400).json({ error: 'Invalid classcode or userId' });
    }
    if (!message && !req.file) {
      return res.status(400).json({ error: 'Message or media required' });
    }

    let mediaUrl = null;
    if (req.file) {
      const storageRef = ref(storage, `chat/${classcode}/${req.file.originalname}`);
      await uploadBytes(storageRef, req.file.buffer);
      mediaUrl = await getDownloadURL(storageRef);
    }

    const messageData = {
      message: message || null,
      userId,
      userName: user.rows[0].username,
      mediaUrl,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    };

    const docRef = await db.collection(`chats/class_${classcode}/messages`).add(messageData);

    res.status(200).json({ success: true, id: docRef.id, ...messageData });
  } catch (error) {
    console.error('Chat send error:', error);
    res.status(500).json({ error: 'Failed to send message' });
  } finally {
    console.timeEnd('chat-send');
  }
});


app.use('/api/materials', authMiddleware, require('./routes/material')); // Ensure this is before other routes

// Custom 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  if (err.message.includes('Only PDFs and images')) {
    return res.status(400).json({ error: err.message });
  }
  if (err.name === 'ValidationError') {
    return res.status(400).json({ error: err.message });
  }
  res.status(500).json({
    error: process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message
  });
});
// Start the server
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));