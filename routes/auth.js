const express = require('express');
const router = express.Router();
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const Joi = require('joi');
const nodemailer = require('nodemailer');
const admin = require('firebase-admin');
const { OAuth2Client } = require('google-auth-library');
require('dotenv').config();

// ✅ Load Firebase service account from env variable
if (!admin.apps.length) {
  if (!process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON) {
    console.error("Missing GOOGLE_APPLICATION_CREDENTIALS_JSON environment variable");
    process.exit(1);
  }
  const serviceAccount = JSON.parse(process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON);

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
}

const db = admin.firestore();
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const createFirebaseUser = async (email, password, userId) => {
  try {
    let firebaseUser = await admin.auth().getUser(userId.toString()).catch(() => null);
    if (!firebaseUser) {
      firebaseUser = await admin.auth().createUser({
        uid: userId.toString(),
        email,
        password: password || undefined, // Firebase requires password only if set
      });
    }
    return firebaseUser;
  } catch (error) {
    console.error('Failed to create Firebase user:', error);
    throw new Error('Failed to create Firebase user');
  }
};

// ------------------- LOGIN -------------------
router.post('/login', async (req, res) => {
  console.log('Login request received:', { email: req.body.email });
  console.time('login');
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = userResult.rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });

    const customToken = await admin.auth().createCustomToken(user.id.toString(), {
      role: user.role,
      class_code: user.class_code,
      cr_type: user.cr_type
    });

    const userRef = db.collection('users').doc(user.id.toString());
    const userDoc = await userRef.get();
    if (!userDoc.exists) {
      await userRef.set({
        email: user.email,
        role: user.role,
        class_code: user.class_code || null,
        cr_type: user.cr_type || null,
        last_login: admin.firestore.FieldValue.serverTimestamp()
      }, { merge: true });
    }

    res.json({
      token: customToken,
      role: user.role.toUpperCase(),
      user_id: user.id,
      classcode: user.class_code || '',
      cr_type: user.cr_type || '',
      cr_elective_id: user.cr_elective_id || '',
      username: user.username || user.email
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error during authentication' });
  } finally {
    console.timeEnd('login');
  }
});

// ------------------- REGISTER -------------------
router.post('/register', async (req, res) => {
  const { email, username, roll_no, room_no, password, role, class_code } = req.body;

  try {
    const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Email already exists' });
    }

    const isApproved = role === 'student' ? true : false;
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await pool.query(
      'INSERT INTO users (email, username, roll_no, room_no, password, role, class_code, is_approved) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *',
      [email, username, roll_no, room_no, hashedPassword, role, class_code, isApproved]
    );

    const user = newUser.rows[0];
    await createFirebaseUser(email, password, user.id);

    await db.collection('users').doc(user.id.toString()).set({
      class_code,
      email,
      username,
      roll_no,
      room_no,
      role: role.toUpperCase(),
      is_approved: isApproved,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    }, { merge: true });

    res.status(201).json({
      message: isApproved ? 'User registered successfully' : 'User registered, awaiting approval'
    });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// ------------------- GOOGLE AUTH -------------------
router.get('/auth/google/callback', async (req, res) => {
  try {
    const { code } = req.query;
    const { tokens } = await client.getToken({
      code,
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      redirect_uri: `${process.env.API_URL}/auth/google/callback`,
    });
    const ticket = await client.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const email = payload.email;

    let userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    let user;
    if (userResult.rows.length === 0) {
      const newUser = await pool.query(
        'INSERT INTO users (email, username, role, is_approved) VALUES ($1, $2, $3, $4) RETURNING *',
        [email, payload.name || email.split('@')[0], 'student', true]
      );
      user = newUser.rows[0];
      await createFirebaseUser(email, null, user.id);
    } else {
      user = userResult.rows[0];
    }

    const customToken = await admin.auth().createCustomToken(user.id.toString(), {
      class_code: user.class_code,
      role: user.role.toUpperCase(),
      cr_type: user.cr_type,
    });

    await db.collection('users').doc(user.id.toString()).set({
      class_code: user.class_code || null,
      email: user.email,
      username: user.username || payload.name,
      role: user.role.toUpperCase(),
      is_approved: user.is_approved,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    }, { merge: true });

    res.redirect(`${process.env.CLIENT_URL}/login?token=${customToken}`);
  } catch (error) {
    console.error('Google auth error:', error);
    res.status(400).send('Google authentication failed');
  }
});

// ------------------- ADMIN ROUTES -------------------
router.get('/pending-users', async (req, res) => {
  const userEmail = req.headers['user-email'];
  try {
    const user = await pool.query('SELECT * FROM users WHERE email = $1', [userEmail]);
    if (user.rows.length === 0 || user.rows[0].role !== 'admin') {
      return res.status(403).json({ error: 'Unauthorized: Only admins can view pending users' });
    }
    const pendingUsers = await pool.query(
      'SELECT * FROM users WHERE is_approved = FALSE AND role = $1',
      ['cr']
    );
    res.json(pendingUsers.rows);
  } catch (err) {
    console.error('Get pending users error:', err);
    res.status(500).json({ error: 'Failed to fetch pending users' });
  }
});

router.post('/approve-user', async (req, res) => {
  const { userId } = req.body;
  const userEmail = req.headers['user-email'];
  try {
    const user = await pool.query('SELECT * FROM users WHERE email = $1', [userEmail]);
    if (user.rows.length === 0 || user.rows[0].role !== 'admin') {
      return res.status(403).json({ error: 'Unauthorized: Only admins can approve users' });
    }
    const updatedUser = await pool.query(
      'UPDATE users SET is_approved = TRUE WHERE id = $1 RETURNING *',
      [userId]
    );
    if (updatedUser.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    await db.collection('users').doc(userId.toString()).set({
      is_approved: true,
    }, { merge: true });

    res.json({ message: 'User approved successfully', user: updatedUser.rows[0] });
  } catch (err) {
    console.error('Approve user error:', err);
    res.status(500).json({ error: 'Failed to approve user' });
  }
});

// ------------------- PASSWORD RESET -------------------
router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    if (!email) return res.status(400).json({ error: 'Email is required' });

    const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (user.rows.length === 0) return res.status(400).json({ error: 'User not found' });

    const token = jwt.sign({ id: user.rows[0].id }, process.env.JWT_SECRET, { expiresIn: '15m' });
    const resetLink = `${process.env.CLIENT_URL}/reset-password/${token}`;

    await transporter.sendMail({
      to: email,
      subject: 'Password Reset - Attendance Tracker',
      html: `<p>Click <a href="${resetLink}">here</a> to reset your password. This link will expire in 15 minutes.</p>`,
    });

    res.json({ message: 'Password reset link sent to your email' });
  } catch (error) {
    console.error('Forgot password error:', error.message);
    res.status(500).json({ error: 'Failed to send reset link' });
  }
});

router.post('/reset-password', async (req, res) => {
  const { token, password } = req.body;
  try {
    if (!token || !password) {
      return res.status(400).json({ error: 'Token and password are required' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decoded.id;

    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashedPassword, userId]);

    await admin.auth().updateUser(userId.toString(), { password });

    res.json({ message: 'Password reset successful' });
  } catch (error) {
    console.error('Reset password error:', error.message);
    if (error.name === 'TokenExpiredError') {
      return res.status(400).json({ error: 'Reset link has expired' });
    }
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

module.exports = router;
