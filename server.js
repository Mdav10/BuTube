const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const xss = require('xss');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

app.set('trust proxy', 1);

// ============ ENV VALIDATION ============
const requiredEnv = ['DB_USER', 'DB_PASSWORD', 'DB_HOST', 'DB_NAME', 'JWT_SECRET'];
for (const env of requiredEnv) {
  if (!process.env[env]) {
    console.error(`❌ Missing required environment variable: ${env}`);
    process.exit(1);
  }
}

// ============ RATE LIMITING ============
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: false },
  skip: (req) => req.path === '/api/health'
});

const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: { error: 'Too many login attempts, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: false },
});

const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 20,
  message: { error: 'Too many upload attempts, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: false },
});

const joinLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: { error: 'Too many join requests. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: false },
});

// ============ MIDDLEWARE ============
app.use(helmet({ 
  contentSecurityPolicy: false, 
  crossOriginEmbedderPolicy: false 
}));
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));
app.use(express.json({ limit: '500mb' }));
app.use(express.urlencoded({ extended: true, limit: '500mb' }));
app.use(compression());
app.use(cookieParser());

// XSS Protection
app.use((req, res, next) => {
  if (req.body) {
    for (let key in req.body) {
      if (typeof req.body[key] === 'string') {
        req.body[key] = xss(req.body[key]);
      }
    }
  }
  next();
});

// ============ SECURITY: Apply Rate Limiting ============
app.use('/api/', limiter);
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);
app.use('/api/videos/upload', uploadLimiter);
app.use('/api/join/request', joinLimiter);

// ============ STATIC FILES ============
app.use('/uploads', express.static('uploads'));
app.use(express.static('public'));

// ============ CREATE DIRECTORIES ============
['uploads', 'uploads/videos', 'uploads/thumbnails'].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// ============ MULTER CONFIG ============
const storage = multer.memoryStorage();

const upload = multer({
  storage: storage,
  limits: { fileSize: 500 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.fieldname === 'video' && !file.mimetype.startsWith('video/')) {
      return cb(new Error('Only video files allowed'));
    }
    if (file.fieldname === 'thumbnail' && !file.mimetype.startsWith('image/')) {
      return cb(new Error('Only image files allowed'));
    }
    if (file.fieldname === 'proof' && !file.mimetype.startsWith('image/')) {
      return cb(new Error('Only image files allowed for proof'));
    }
    cb(null, true);
  }
});

// ============ DATABASE CONNECTION ============
const pool = new Pool({
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT) || 5432,
  database: process.env.DB_NAME,
  ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
  connectionTimeoutMillis: 30000,
  max: 20,
  idleTimeoutMillis: 30000,
});

pool.connect((err, client, release) => {
  if (err) {
    console.error('❌ Database error:', err.message);
  } else {
    console.log('✅ Database connected');
    release();
  }
});

// ============ DATABASE INITIALIZATION ============
async function addMissingColumns() {
  try {
    const columnCheck = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'users' AND column_name = 'subscription_status'
    `);

    if (columnCheck.rows.length === 0) {
      console.log('📝 Adding subscription columns...');
      await pool.query(`
        ALTER TABLE users 
        ADD COLUMN IF NOT EXISTS subscription_status VARCHAR(50) DEFAULT 'pending',
        ADD COLUMN IF NOT EXISTS subscription_plan VARCHAR(50),
        ADD COLUMN IF NOT EXISTS subscription_start DATE,
        ADD COLUMN IF NOT EXISTS subscription_end DATE,
        ADD COLUMN IF NOT EXISTS subscription_proof_image BYTEA,
        ADD COLUMN IF NOT EXISTS subscription_proof_mimetype VARCHAR(100),
        ADD COLUMN IF NOT EXISTS subscription_proof_uploaded_at TIMESTAMP,
        ADD COLUMN IF NOT EXISTS subscription_verified_by INTEGER REFERENCES users(id),
        ADD COLUMN IF NOT EXISTS subscription_verified_at TIMESTAMP,
        ADD COLUMN IF NOT EXISTS subscription_notes TEXT,
        ADD COLUMN IF NOT EXISTS is_approved BOOLEAN DEFAULT false,
        ADD COLUMN IF NOT EXISTS full_name VARCHAR(255),
        ADD COLUMN IF NOT EXISTS phone_number VARCHAR(50),
        ADD COLUMN IF NOT EXISTS join_request_date TIMESTAMP,
        ADD COLUMN IF NOT EXISTS join_request_plan VARCHAR(50),
        ADD COLUMN IF NOT EXISTS join_request_status VARCHAR(50) DEFAULT 'pending'
      `);
      console.log('✅ Subscription columns added');
    }
  } catch (error) {
    console.error('❌ Error adding columns:', error.message);
  }
}

async function initDatabase() {
  try {
    console.log('🔄 Initializing database...');

    // Users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        secret_code VARCHAR(255) NOT NULL,
        heard_from VARCHAR(100),
        role VARCHAR(50) DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP,
        login_attempts INTEGER DEFAULT 0,
        locked_until TIMESTAMP,
        is_approved BOOLEAN DEFAULT false,
        full_name VARCHAR(255),
        phone_number VARCHAR(50),
        join_request_date TIMESTAMP,
        join_request_plan VARCHAR(50),
        join_request_status VARCHAR(50) DEFAULT 'pending'
      )
    `);
    console.log('✅ Users table ready');

    // Videos table with BYTEA for video storage
    await pool.query(`
      CREATE TABLE IF NOT EXISTS videos (
        id SERIAL PRIMARY KEY,
        title VARCHAR(500) NOT NULL,
        description TEXT,
        video_data BYTEA NOT NULL,
        video_mimetype VARCHAR(100),
        video_filename VARCHAR(255),
        thumbnail_data BYTEA,
        thumbnail_mimetype VARCHAR(100),
        uploader_id INTEGER REFERENCES users(id),
        uploader_name VARCHAR(255),
        views INTEGER DEFAULT 0,
        likes INTEGER DEFAULT 0,
        dislikes INTEGER DEFAULT 0,
        share_count INTEGER DEFAULT 0,
        file_size INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT true
      )
    `);
    console.log('✅ Videos table created with BYTEA storage');

    // Comments table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS comments (
        id SERIAL PRIMARY KEY,
        video_id INTEGER REFERENCES videos(id) ON DELETE CASCADE,
        username VARCHAR(255) NOT NULL,
        comment TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('✅ Comments table ready');

    // User actions table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_actions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        video_id INTEGER REFERENCES videos(id) ON DELETE CASCADE,
        action_type VARCHAR(50),
        action_data TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('✅ User actions table ready');

    // User logs table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_logs (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        ip_address VARCHAR(45),
        user_agent TEXT,
        action VARCHAR(255),
        details TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('✅ User logs table ready');

    // Website stats table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS website_stats (
        id SERIAL PRIMARY KEY,
        total_visits INTEGER DEFAULT 0,
        total_users INTEGER DEFAULT 0,
        total_videos INTEGER DEFAULT 0,
        total_views INTEGER DEFAULT 0,
        total_likes INTEGER DEFAULT 0,
        total_comments INTEGER DEFAULT 0
      )
    `);
    console.log('✅ Website stats table ready');

    // Payment settings table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS payment_settings (
        id SERIAL PRIMARY KEY,
        bank_name VARCHAR(255),
        account_number VARCHAR(100),
        account_owner VARCHAR(255),
        phone_number VARCHAR(50),
        updated_by INTEGER REFERENCES users(id),
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('✅ Payment settings table ready');

    // Join Requests table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS join_requests (
        id SERIAL PRIMARY KEY,
        full_name VARCHAR(255) NOT NULL,
        phone_number VARCHAR(50) NOT NULL,
        email VARCHAR(255),
        plan VARCHAR(50) NOT NULL,
        proof_image BYTEA,
        proof_mimetype VARCHAR(100),
        proof_uploaded_at TIMESTAMP,
        status VARCHAR(50) DEFAULT 'pending',
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        processed_by INTEGER REFERENCES users(id),
        processed_at TIMESTAMP,
        user_id INTEGER REFERENCES users(id)
      )
    `);
    console.log('✅ Join requests table ready');

    // ===== SECURITY: Create Super Admin =====
    const adminUsername = process.env.ADMIN_USERNAME || 'OWNER_MPC';
    const adminPassword = process.env.ADMIN_PASSWORD || '08800+_+Owner!';
    const adminSecret = process.env.ADMIN_SECRET || 'ADMIN_SECRET_2024';

    const adminCheck = await pool.query('SELECT * FROM users WHERE username = $1', [adminUsername]);
    if (adminCheck.rows.length === 0) {
      const hashedPassword = await bcrypt.hash(adminPassword, 10);
      const hashedSecret = await bcrypt.hash(adminSecret, 10);
      await pool.query(
        `INSERT INTO users (username, password, secret_code, role, heard_from, subscription_status, is_approved, full_name) 
         VALUES ($1, $2, $3, 'super_admin', 'system', 'active', true, 'Super Administrator')`,
        [adminUsername, hashedPassword, hashedSecret]
      );
      console.log('✅ Super Admin created');
    }

    // Payment settings
    const paymentCheck = await pool.query('SELECT * FROM payment_settings');
    if (paymentCheck.rows.length === 0) {
      await pool.query(`
        INSERT INTO payment_settings (bank_name, account_number, account_owner, phone_number)
        VALUES ('Equity Bank', '1234567890', 'AKABAKUZE Platform', '+250 788 888 888')
      `);
    }

    // Stats
    const statsCheck = await pool.query('SELECT * FROM website_stats');
    if (statsCheck.rows.length === 0) {
      await pool.query(`
        INSERT INTO website_stats (total_visits, total_users, total_videos, total_views, total_likes, total_comments) 
        VALUES (0, 0, 0, 0, 0, 0)
      `);
    }

    await addMissingColumns();

    const userCount = await pool.query('SELECT COUNT(*) as count FROM users');
    const videoCount = await pool.query('SELECT COUNT(*) as count FROM videos');
    await pool.query(
      'UPDATE website_stats SET total_users = $1, total_videos = $2',
      [parseInt(userCount.rows[0].count), parseInt(videoCount.rows[0].count)]
    );

    console.log('✅ Database ready');
    console.log('👑 Super Admin:', adminUsername);
  } catch (error) {
    console.error('❌ Database error:', error.message);
  }
}

// ============ AUTH MIDDLEWARE ============
const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    const user = await pool.query(
      'SELECT id, username, role, subscription_status, is_approved FROM users WHERE id = $1',
      [decoded.userId]
    );
    
    if (!user.rows.length) {
      return res.status(401).json({ error: 'User not found' });
    }
    
    req.user = user.rows[0];
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired' });
    }
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Invalid token' });
    }
    return res.status(401).json({ error: 'Authentication failed' });
  }
};

const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
};

async function logUserActivity(userId, action, details, req) {
  try {
    const ip = req.ip || req.connection?.remoteAddress || 'unknown';
    const userAgent = req.headers['user-agent'] || 'unknown';
    await pool.query(
      `INSERT INTO user_logs (user_id, ip_address, user_agent, action, details) 
       VALUES ($1, $2, $3, $4, $5)`,
      [userId, ip, userAgent, action, JSON.stringify(details || {})]
    );
  } catch (error) {
    console.error('Log error:', error.message);
  }
}

// ============ VALIDATION HELPERS ============
const isValidPhone = (phone) => {
  return phone && phone.length >= 8 && phone.length <= 20 && /^[\+\d\-\(\)\s]+$/.test(phone);
};

const isValidFullName = (name) => {
  return name && name.length >= 2 && name.length <= 100 && /^[a-zA-Z\s\-']+$/.test(name);
};

const isValidEmail = (email) => {
  return !email || /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
};

// ============ JOIN US - REQUEST CREATOR ACCOUNT ============
app.post('/api/join/request', upload.single('proof'), async (req, res) => {
  try {
    const { fullName, phoneNumber, email, plan } = req.body;

    if (!fullName || !phoneNumber || !plan) {
      return res.status(400).json({ error: 'Full name, phone number, and plan are required' });
    }

    if (!isValidFullName(fullName)) {
      return res.status(400).json({ error: 'Please enter a valid full name' });
    }

    if (!isValidPhone(phoneNumber)) {
      return res.status(400).json({ error: 'Please enter a valid phone number' });
    }

    if (email && !isValidEmail(email)) {
      return res.status(400).json({ error: 'Please enter a valid email address' });
    }

    const validPlans = ['monthly', 'quarterly', 'semiannual', 'yearly'];
    if (!validPlans.includes(plan)) {
      return res.status(400).json({ error: 'Invalid plan selected' });
    }

    const existingRequest = await pool.query(
      'SELECT * FROM join_requests WHERE phone_number = $1 AND status = $2',
      [phoneNumber, 'pending']
    );
    if (existingRequest.rows.length > 0) {
      return res.status(400).json({ error: 'You already have a pending request. Please wait for our team to contact you.' });
    }

    let proofImage = null;
    let proofMimetype = null;

    if (req.file) {
      proofImage = req.file.buffer;
      proofMimetype = req.file.mimetype;
    }

    const result = await pool.query(
      `INSERT INTO join_requests (full_name, phone_number, email, plan, proof_image, proof_mimetype, proof_uploaded_at, status) 
       VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP, 'pending') 
       RETURNING id, full_name, phone_number, email, plan, status, created_at`,
      [fullName, phoneNumber, email || null, plan, proofImage, proofMimetype]
    );

    await logUserActivity(null, 'join_request', { 
      fullName, 
      phoneNumber, 
      plan,
      requestId: result.rows[0].id 
    }, req);

    res.json({
      success: true,
      message: '✅ Your request has been submitted successfully! Our team will contact you within 24 hours.',
      request: result.rows[0]
    });

  } catch (error) {
    console.error('❌ Join request error:', error);
    res.status(500).json({ error: 'Failed to submit request: ' + error.message });
  }
});

// ============ GET PENDING JOIN REQUESTS ============
app.get('/api/admin/join-requests', authenticate, authorize('super_admin'), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, full_name, phone_number, email, plan, status, created_at, proof_image IS NOT NULL as has_proof
      FROM join_requests 
      ORDER BY created_at DESC
    `);
    res.json(result.rows);
  } catch (error) {
    console.error('Join requests error:', error);
    res.status(500).json({ error: 'Failed to get join requests' });
  }
});

// ============ PROCESS JOIN REQUEST ============
app.post('/api/admin/process-join-request/:id', authenticate, authorize('super_admin'), async (req, res) => {
  try {
    const requestId = parseInt(req.params.id);
    const { action, username, password, secretCode, notes } = req.body;

    if (!['approve', 'reject'].includes(action)) {
      return res.status(400).json({ error: 'Invalid action' });
    }

    const requestResult = await pool.query(
      'SELECT * FROM join_requests WHERE id = $1',
      [requestId]
    );

    if (requestResult.rows.length === 0) {
      return res.status(404).json({ error: 'Request not found' });
    }

    const request = requestResult.rows[0];

    if (request.status !== 'pending') {
      return res.status(400).json({ error: 'This request has already been processed' });
    }

    if (action === 'approve') {
      if (!username || !password || !secretCode) {
        return res.status(400).json({ error: 'Username, password, and secret code are required' });
      }

      if (username.length < 3) {
        return res.status(400).json({ error: 'Username must be at least 3 characters' });
      }

      if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
      }

      if (secretCode.length < 4) {
        return res.status(400).json({ error: 'Secret code must be at least 4 characters' });
      }

      const userCheck = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
      if (userCheck.rows.length > 0) {
        return res.status(400).json({ error: 'Username already exists' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const hashedSecret = await bcrypt.hash(secretCode, 10);

      const userResult = await pool.query(
        `INSERT INTO users (username, password, secret_code, role, full_name, phone_number, is_approved, subscription_status, join_request_date, join_request_plan) 
         VALUES ($1, $2, $3, 'creator', $4, $5, false, 'pending', CURRENT_TIMESTAMP, $6) 
         RETURNING id, username, role`,
        [username, hashedPassword, hashedSecret, request.full_name, request.phone_number, request.plan]
      );

      await pool.query(
        `UPDATE join_requests SET status = 'approved', processed_by = $1, processed_at = CURRENT_TIMESTAMP, notes = $2, user_id = $3 WHERE id = $4`,
        [req.user.id, notes || 'Approved', userResult.rows[0].id, requestId]
      );

      await logUserActivity(req.user.id, 'approve_join_request', { 
        requestId, 
        username, 
        fullName: request.full_name 
      }, req);

      res.json({
        success: true,
        message: `✅ User "${username}" has been approved and account created!`,
        user: userResult.rows[0]
      });

    } else {
      await pool.query(
        `UPDATE join_requests SET status = 'rejected', processed_by = $1, processed_at = CURRENT_TIMESTAMP, notes = $2 WHERE id = $3`,
        [req.user.id, notes || 'Rejected', requestId]
      );

      await logUserActivity(req.user.id, 'reject_join_request', { 
        requestId, 
        fullName: request.full_name 
      }, req);

      res.json({
        success: true,
        message: 'Request rejected successfully'
      });
    }

  } catch (error) {
    console.error('❌ Process join request error:', error);
    res.status(500).json({ error: 'Failed to process request: ' + error.message });
  }
});

// ============ GET PROOF IMAGE ============
app.get('/api/admin/proof/:id', authenticate, authorize('super_admin'), async (req, res) => {
  try {
    const requestId = parseInt(req.params.id);
    
    const result = await pool.query(
      'SELECT proof_image, proof_mimetype FROM join_requests WHERE id = $1',
      [requestId]
    );
    
    if (result.rows.length === 0 || !result.rows[0].proof_image) {
      return res.status(404).json({ error: 'No proof found' });
    }
    
    const proof = result.rows[0];
    res.setHeader('Content-Type', proof.proof_mimetype || 'image/jpeg');
    res.send(proof.proof_image);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get proof' });
  }
});

// ============ AUTH ROUTES ============
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password, secretCode, heardFrom } = req.body;
    if (!username || !password || !secretCode) {
      return res.status(400).json({ error: 'All fields required' });
    }
    
    const existing = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (existing.rows.length) return res.status(400).json({ error: 'Username exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const hashedSecret = await bcrypt.hash(secretCode, 10);
    
    const result = await pool.query(
      `INSERT INTO users (username, password, secret_code, heard_from, role, subscription_status, is_approved) 
       VALUES ($1, $2, $3, $4, 'user', 'inactive', false) RETURNING id, username, role`,
      [username, hashedPassword, hashedSecret, heardFrom]
    );
    
    await pool.query('UPDATE website_stats SET total_users = total_users + 1, total_visits = total_visits + 1');
    await logUserActivity(result.rows[0].id, 'register', { heardFrom }, req);
    
    const token = jwt.sign(
      { userId: result.rows[0].id, username: result.rows[0].username, role: result.rows[0].role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.json({ token, user: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password, secretCode } = req.body;
    if (!username || !password || !secretCode) {
      return res.status(400).json({ error: 'All fields required' });
    }
    
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (!result.rows.length) return res.status(401).json({ error: 'Invalid credentials' });

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password);
    const validSecret = await bcrypt.compare(secretCode, user.secret_code);
    
    if (!validPassword || !validSecret) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    await pool.query('UPDATE website_stats SET total_visits = total_visits + 1');
    await logUserActivity(user.id, 'login', { success: true }, req);
    
    const token = jwt.sign(
      { userId: user.id, username: user.username, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.json({ 
      token, 
      user: { 
        id: user.id, 
        username: user.username, 
        role: user.role,
        subscription_status: user.subscription_status || 'inactive',
        is_approved: user.is_approved || false
      } 
    });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/auth/me', authenticate, async (req, res) => {
  try {
    const userData = await pool.query(
      'SELECT id, username, role, subscription_status, is_approved, subscription_plan, subscription_start, subscription_end, full_name, phone_number FROM users WHERE id = $1',
      [req.user.id]
    );
    res.json({ user: userData.rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get user info' });
  }
});

app.post('/api/auth/heard-from', authenticate, async (req, res) => {
  try {
    const { heardFrom } = req.body;
    await pool.query('UPDATE users SET heard_from = $1 WHERE id = $2', [heardFrom, req.user.id]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update' });
  }
});

// ============ SUBSCRIPTION ROUTES ============
app.get('/api/subscription/plans', (req, res) => {
  res.json({
    plans: [
      { id: 'monthly', name: 'Monthly', price: 50, duration: '1 month' },
      { id: 'quarterly', name: 'Quarterly', price: 100, duration: '3 months' },
      { id: 'semiannual', name: 'Semi-Annual', price: 150, duration: '6 months' },
      { id: 'yearly', name: 'Yearly', price: 300, duration: '12 months' }
    ]
  });
});

app.get('/api/subscription/payment-settings', async (req, res) => {
  try {
    const result = await pool.query('SELECT bank_name, account_number, account_owner, phone_number FROM payment_settings LIMIT 1');
    if (result.rows.length === 0) {
      return res.json({ bank_name: 'Not set', account_number: 'Not set', account_owner: 'Not set', phone_number: 'Not set' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get payment settings' });
  }
});

app.put('/api/subscription/payment-settings', authenticate, authorize('super_admin'), async (req, res) => {
  try {
    const { bank_name, account_number, account_owner, phone_number } = req.body;
    await pool.query(
      `UPDATE payment_settings SET bank_name = $1, account_number = $2, account_owner = $3, phone_number = $4, updated_by = $5, updated_at = CURRENT_TIMESTAMP WHERE id = 1`,
      [bank_name, account_number, account_owner, phone_number, req.user.id]
    );
    await logUserActivity(req.user.id, 'update_payment_settings', { bank_name, account_number }, req);
    res.json({ success: true, message: 'Payment settings updated' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update payment settings' });
  }
});

app.post('/api/subscription/request', authenticate, async (req, res) => {
  try {
    const { plan } = req.body;
    
    if (req.user.role !== 'admin' && req.user.role !== 'creator') {
      return res.status(403).json({ error: 'Only creators can request subscription' });
    }
    
    const userCheck = await pool.query('SELECT subscription_status FROM users WHERE id = $1', [req.user.id]);
    if (userCheck.rows[0].subscription_status === 'active') {
      return res.status(400).json({ error: 'You already have an active subscription' });
    }
    
    const startDate = new Date();
    let endDate = new Date();
    let planName = '';
    let planPrice = 0;
    
    switch(plan) {
      case 'monthly': endDate.setMonth(endDate.getMonth() + 1); planName = 'Monthly'; planPrice = 50; break;
      case 'quarterly': endDate.setMonth(endDate.getMonth() + 3); planName = 'Quarterly'; planPrice = 100; break;
      case 'semiannual': endDate.setMonth(endDate.getMonth() + 6); planName = 'Semi-Annual'; planPrice = 150; break;
      case 'yearly': endDate.setFullYear(endDate.getFullYear() + 1); planName = 'Yearly'; planPrice = 300; break;
      default: return res.status(400).json({ error: 'Invalid plan selected' });
    }
    
    await pool.query(
      `UPDATE users SET subscription_status = 'pending', subscription_plan = $1, subscription_start = $2, subscription_end = $3 WHERE id = $4`,
      [`${planName} - $${planPrice}`, startDate, endDate, req.user.id]
    );
    
    await logUserActivity(req.user.id, 'request_subscription', { plan, price: planPrice }, req);
    
    res.json({ success: true, message: 'Subscription request submitted. Please upload payment proof.', plan: planName, price: planPrice, startDate, endDate });
  } catch (error) {
    res.status(500).json({ error: 'Failed to request subscription' });
  }
});

app.post('/api/subscription/upload-proof', authenticate, upload.single('proof'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'Proof image is required' });
    if (req.user.role !== 'admin' && req.user.role !== 'creator') {
      return res.status(403).json({ error: 'Only creators can upload payment proof' });
    }
    
    const proofFile = req.file;
    await pool.query(
      `UPDATE users SET subscription_proof_image = $1, subscription_proof_mimetype = $2, subscription_proof_uploaded_at = CURRENT_TIMESTAMP WHERE id = $3`,
      [proofFile.buffer, proofFile.mimetype, req.user.id]
    );
    
    await logUserActivity(req.user.id, 'upload_payment_proof', { fileSize: proofFile.size }, req);
    res.json({ success: true, message: 'Payment proof uploaded. Waiting for admin verification.' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to upload proof' });
  }
});

app.get('/api/subscription/proof/:userId', authenticate, authorize('super_admin'), async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    const result = await pool.query('SELECT subscription_proof_image, subscription_proof_mimetype FROM users WHERE id = $1', [userId]);
    if (result.rows.length === 0 || !result.rows[0].subscription_proof_image) {
      return res.status(404).json({ error: 'No proof found' });
    }
    const proof = result.rows[0];
    res.setHeader('Content-Type', proof.subscription_proof_mimetype || 'image/jpeg');
    res.send(proof.subscription_proof_image);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get proof' });
  }
});

app.get('/api/subscription/pending', authenticate, authorize('super_admin'), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, username, subscription_plan, subscription_start, subscription_end, 
             subscription_proof_uploaded_at, subscription_proof_image IS NOT NULL as has_proof
      FROM users 
      WHERE subscription_status = 'pending' AND role IN ('admin', 'creator')
      ORDER BY subscription_proof_uploaded_at DESC
    `);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get pending subscriptions' });
  }
});

app.post('/api/subscription/verify/:userId', authenticate, authorize('super_admin'), async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    const { approve, notes } = req.body;
    
    if (approve) {
      await pool.query(
        `UPDATE users SET subscription_status = 'active', subscription_verified_by = $1, subscription_verified_at = CURRENT_TIMESTAMP, subscription_notes = $2, is_approved = true WHERE id = $3`,
        [req.user.id, notes || 'Approved', userId]
      );
      await pool.query(`UPDATE users SET role = 'creator' WHERE id = $1 AND role = 'user'`, [userId]);
      await logUserActivity(req.user.id, 'approve_subscription', { userId }, req);
      res.json({ success: true, message: 'Subscription approved and activated' });
    } else {
      await pool.query(
        `UPDATE users SET subscription_status = 'rejected', subscription_notes = $1, subscription_verified_by = $2, subscription_verified_at = CURRENT_TIMESTAMP WHERE id = $3`,
        [notes || 'Rejected', req.user.id, userId]
      );
      await logUserActivity(req.user.id, 'reject_subscription', { userId }, req);
      res.json({ success: true, message: 'Subscription rejected' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Failed to verify subscription' });
  }
});

app.get('/api/subscription/status', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT subscription_status, subscription_plan, subscription_start, subscription_end, is_approved FROM users WHERE id = $1',
      [req.user.id]
    );
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get subscription status' });
  }
});

// ============ ADMIN ROUTES ============
app.post('/api/admin/create-creator', authenticate, authorize('super_admin'), async (req, res) => {
  try {
    const { username, password, secretCode } = req.body;
    if (!username || !password || !secretCode) {
      return res.status(400).json({ error: 'All fields required' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const hashedSecret = await bcrypt.hash(secretCode, 10);
    
    const result = await pool.query(
      `INSERT INTO users (username, password, secret_code, role, subscription_status, is_approved) 
       VALUES ($1, $2, $3, 'creator', 'pending', false) RETURNING id, username, role`,
      [username, hashedPassword, hashedSecret]
    );
    
    await logUserActivity(req.user.id, 'create_creator', { newCreator: username }, req);
    
    res.json({ success: true, creator: result.rows[0], secretCode, message: 'Creator created. They need to subscribe and get approved before uploading.' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create creator' });
  }
});

app.post('/api/admin/approve-creator/:userId', authenticate, authorize('super_admin'), async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    
    const userCheck = await pool.query('SELECT role, is_approved FROM users WHERE id = $1', [userId]);
    if (!userCheck.rows.length) return res.status(404).json({ error: 'User not found' });
    
    if (userCheck.rows[0].is_approved) {
      return res.status(400).json({ error: 'User is already approved' });
    }
    
    await pool.query(
      'UPDATE users SET is_approved = true, role = $1 WHERE id = $2',
      ['creator', userId]
    );
    
    await logUserActivity(req.user.id, 'approve_creator', { userId }, req);
    res.json({ success: true, message: 'Creator approved successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to approve creator' });
  }
});

app.get('/api/admin/pending-creators', authenticate, authorize('super_admin'), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, username, created_at, subscription_status, subscription_plan
      FROM users 
      WHERE role = 'creator' AND is_approved = false
      ORDER BY created_at DESC
    `);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get pending creators' });
  }
});

app.get('/api/admin/super-stats', authenticate, authorize('super_admin'), async (req, res) => {
  try {
    const stats = await pool.query('SELECT * FROM website_stats LIMIT 1');
    const users = await pool.query('SELECT COUNT(*) as total FROM users');
    const creators = await pool.query("SELECT COUNT(*) as total FROM users WHERE role = 'creator'");
    const pendingCreators = await pool.query("SELECT COUNT(*) as total FROM users WHERE role = 'creator' AND is_approved = false");
    const videos = await pool.query('SELECT COUNT(*) as total FROM videos');
    const comments = await pool.query('SELECT COUNT(*) as total FROM comments');
    const pendingSubs = await pool.query("SELECT COUNT(*) as total FROM users WHERE subscription_status = 'pending' AND role IN ('creator', 'admin')");
    const joinRequests = await pool.query("SELECT COUNT(*) as total FROM join_requests WHERE status = 'pending'");
    
    const allCreators = await pool.query(`
      SELECT id, username, created_at, subscription_status, is_approved, subscription_plan, full_name, phone_number
      FROM users 
      WHERE role = 'creator'
      ORDER BY created_at DESC
    `);

    const allVideos = await pool.query(`
      SELECT v.id, v.title, v.description, 
             v.views, v.likes, v.share_count, v.created_at, u.username as uploader_name
      FROM videos v 
      JOIN users u ON v.uploader_id = u.id 
      WHERE v.is_active = true 
      ORDER BY v.created_at DESC
      LIMIT 50
    `);

    const topVideos = await pool.query(`
      SELECT v.id, v.title, v.views, v.likes, v.share_count, u.username 
      FROM videos v 
      JOIN users u ON v.uploader_id = u.id 
      WHERE v.is_active = true 
      ORDER BY v.views DESC 
      LIMIT 10
    `);

    const recentUsers = await pool.query(`
      SELECT id, username, role, heard_from, created_at, subscription_status, is_approved, full_name, phone_number
      FROM users 
      ORDER BY created_at DESC 
      LIMIT 20
    `);

    const logs = await pool.query(
      `SELECT l.*, u.username 
       FROM user_logs l 
       LEFT JOIN users u ON l.user_id = u.id 
       ORDER BY l.created_at DESC 
       LIMIT 100`
    );

    res.json({
      success: true,
      stats: stats.rows[0] || { total_visits: 0, total_users: 0, total_videos: 0, total_views: 0, total_likes: 0, total_comments: 0 },
      userCount: parseInt(users.rows[0].total),
      creatorCount: parseInt(creators.rows[0].total),
      pendingCreators: parseInt(pendingCreators.rows[0].total),
      videoCount: parseInt(videos.rows[0].total),
      commentCount: parseInt(comments.rows[0].total),
      pendingSubscriptions: parseInt(pendingSubs.rows[0].total),
      pendingJoinRequests: parseInt(joinRequests.rows[0].total),
      allCreators: allCreators.rows,
      allVideos: allVideos.rows,
      topVideos: topVideos.rows,
      recentUsers: recentUsers.rows,
      recentLogs: logs.rows || []
    });

  } catch (error) {
    console.error('Super stats error:', error);
    res.status(500).json({ error: 'Failed to get stats: ' + error.message });
  }
});

app.get('/api/creator/my-stats', authenticate, authorize('creator'), async (req, res) => {
  try {
    const videos = await pool.query(
      'SELECT COUNT(*) as total, COALESCE(SUM(views), 0) as total_views, COALESCE(SUM(likes), 0) as total_likes FROM videos WHERE uploader_id = $1 AND is_active = true',
      [req.user.id]
    );
    
    const totalVideos = parseInt(videos.rows[0].total) || 0;
    const totalViews = parseInt(videos.rows[0].total_views) || 0;
    const totalLikes = parseInt(videos.rows[0].total_likes) || 0;

    res.json({
      success: true,
      stats: {
        totalVideos,
        totalViews,
        totalLikes,
        averageViews: totalVideos > 0 ? Math.round(totalViews / totalVideos) : 0
      }
    });
  } catch (error) {
    console.error('My stats error:', error);
    res.status(500).json({ error: 'Failed to get stats: ' + error.message });
  }
});

app.get('/api/creator/my-videos', authenticate, authorize('creator'), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, title, description, uploader_id, uploader_name, views, likes, dislikes, share_count, file_size, created_at,
              CASE WHEN video_data IS NOT NULL THEN true ELSE false END as has_video,
              CASE WHEN thumbnail_data IS NOT NULL THEN true ELSE false END as has_thumbnail
       FROM videos WHERE uploader_id = $1 AND is_active = true ORDER BY created_at DESC`,
      [req.user.id]
    );
    res.json({ success: true, videos: result.rows });
  } catch (error) {
    console.error('My videos error:', error);
    res.status(500).json({ error: 'Failed to get your videos: ' + error.message });
  }
});

// ============ VIDEO UPLOAD - STORE IN DATABASE AS BYTEA ============
app.post('/api/videos/upload', authenticate, authorize('creator', 'super_admin'), upload.fields([
  { name: 'video', maxCount: 1 },
  { name: 'thumbnail', maxCount: 1 }
]), async (req, res) => {
  try {
    console.log('📹 Upload request received');
    
    const { title, description } = req.body;
    
    if (!title || !req.files || !req.files.video) {
      return res.status(400).json({ error: 'Title and video file are required' });
    }
    
    const videoFile = req.files.video[0];
    const thumbnailFile = req.files.thumbnail ? req.files.thumbnail[0] : null;
    
    if (videoFile.size > 500 * 1024 * 1024) {
      return res.status(400).json({ error: 'Video file size exceeds 500MB limit' });
    }
    
    console.log('📁 Video size:', videoFile.size, 'bytes');
    
    // STORE IN DATABASE AS BYTEA
    const result = await pool.query(
      `INSERT INTO videos (title, description, video_data, video_mimetype, video_filename, 
                           thumbnail_data, thumbnail_mimetype, uploader_id, uploader_name, file_size) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) 
       RETURNING id, title, description, video_mimetype, video_filename, file_size, created_at`,
      [
        title, 
        description || '', 
        videoFile.buffer,
        videoFile.mimetype,
        videoFile.originalname,
        thumbnailFile ? thumbnailFile.buffer : null,
        thumbnailFile ? thumbnailFile.mimetype : null,
        req.user.id, 
        req.user.username, 
        videoFile.size
      ]
    );
    
    await pool.query('UPDATE website_stats SET total_videos = total_videos + 1');
    await logUserActivity(req.user.id, 'upload_video', { 
      videoId: result.rows[0].id, 
      title: title,
      fileSize: videoFile.size 
    }, req);
    
    console.log('✅ Video uploaded successfully to database:', result.rows[0].id);
    
    res.json({
      success: true,
      message: 'Video uploaded successfully',
      video: result.rows[0]
    });
  } catch (error) {
    console.error('❌ Upload error:', error);
    res.status(500).json({ error: 'Upload failed: ' + error.message });
  }
});

// ============ VIDEO ROUTES - STREAM FROM DATABASE ============
app.get('/api/videos', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT v.id, v.title, v.description, 
             v.views, v.likes, v.dislikes, v.share_count, v.created_at,
             u.username as uploader_name,
             CASE WHEN v.video_data IS NOT NULL THEN true ELSE false END as has_video,
             CASE WHEN v.thumbnail_data IS NOT NULL THEN true ELSE false END as has_thumbnail
      FROM videos v 
      JOIN users u ON v.uploader_id = u.id 
      WHERE v.is_active = true 
      ORDER BY v.created_at DESC
    `);
    res.json(result.rows);
  } catch (error) {
    console.error('Get videos error:', error);
    res.status(500).json({ error: 'Failed to get videos: ' + error.message });
  }
});

// STREAM VIDEO FROM DATABASE
app.get('/api/videos/:id/stream', async (req, res) => {
  try {
    const videoId = parseInt(req.params.id);
    if (isNaN(videoId)) {
      return res.status(400).json({ error: 'Invalid video ID' });
    }
    
    const result = await pool.query(
      'SELECT video_data, video_mimetype FROM videos WHERE id = $1 AND is_active = true',
      [videoId]
    );
    
    if (result.rows.length === 0 || !result.rows[0].video_data) {
      return res.status(404).json({ error: 'Video not found' });
    }
    
    const video = result.rows[0];
    res.setHeader('Content-Type', video.video_mimetype || 'video/mp4');
    res.setHeader('Content-Length', video.video_data.length);
    res.send(video.video_data);
  } catch (error) {
    console.error('Stream error:', error);
    res.status(500).json({ error: 'Failed to stream video: ' + error.message });
  }
});

// GET THUMBNAIL FROM DATABASE
app.get('/api/videos/:id/thumbnail', async (req, res) => {
  try {
    const videoId = parseInt(req.params.id);
    if (isNaN(videoId)) {
      return res.status(400).json({ error: 'Invalid video ID' });
    }
    
    const result = await pool.query(
      'SELECT thumbnail_data, thumbnail_mimetype FROM videos WHERE id = $1 AND is_active = true',
      [videoId]
    );
    
    if (result.rows.length === 0 || !result.rows[0].thumbnail_data) {
      return res.sendFile(path.join(__dirname, 'public', 'default-thumbnail.jpg'));
    }
    
    const thumbnail = result.rows[0];
    res.setHeader('Content-Type', thumbnail.thumbnail_mimetype || 'image/jpeg');
    res.send(thumbnail.thumbnail_data);
  } catch (error) {
    console.error('Thumbnail error:', error);
    res.status(500).json({ error: 'Failed to get thumbnail: ' + error.message });
  }
});

app.get('/api/videos/:id', async (req, res) => {
  try {
    const videoId = parseInt(req.params.id);
    if (isNaN(videoId)) {
      return res.status(400).json({ error: 'Invalid video ID' });
    }
    
    await pool.query('UPDATE videos SET views = views + 1 WHERE id = $1', [videoId]);
    
    const videoResult = await pool.query(`
      SELECT v.id, v.title, v.description, v.views, v.likes, v.dislikes, v.share_count, v.created_at,
             u.username as uploader_name,
             CASE WHEN v.video_data IS NOT NULL THEN true ELSE false END as has_video,
             CASE WHEN v.thumbnail_data IS NOT NULL THEN true ELSE false END as has_thumbnail
      FROM videos v 
      JOIN users u ON v.uploader_id = u.id 
      WHERE v.id = $1 AND v.is_active = true
    `, [videoId]);
    
    if (videoResult.rows.length === 0) {
      return res.status(404).json({ error: 'Video not found' });
    }
    
    const commentsResult = await pool.query(
      'SELECT id, username, comment, created_at FROM comments WHERE video_id = $1 ORDER BY created_at DESC',
      [videoId]
    );
    
    res.json({
      ...videoResult.rows[0],
      comments: commentsResult.rows
    });
  } catch (error) {
    console.error('Get video error:', error);
    res.status(500).json({ error: 'Failed to get video: ' + error.message });
  }
});

app.put('/api/videos/:id', authenticate, authorize('creator', 'super_admin'), async (req, res) => {
  try {
    const videoId = parseInt(req.params.id);
    const { title, description } = req.body;
    
    if (!title) return res.status(400).json({ error: 'Title required' });

    const check = await pool.query('SELECT uploader_id FROM videos WHERE id = $1', [videoId]);
    if (!check.rows.length) return res.status(404).json({ error: 'Video not found' });
    
    if (check.rows[0].uploader_id !== req.user.id && req.user.role !== 'super_admin') {
      return res.status(403).json({ error: 'You can only edit your own videos' });
    }

    const result = await pool.query(
      'UPDATE videos SET title = $1, description = $2 WHERE id = $3 RETURNING id, title, description, created_at',
      [title, description || '', videoId]
    );
    
    await logUserActivity(req.user.id, 'edit_video', { videoId, title }, req);
    
    res.json({ success: true, video: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update video' });
  }
});

app.delete('/api/videos/:id', authenticate, authorize('creator', 'super_admin'), async (req, res) => {
  try {
    const videoId = parseInt(req.params.id);
    
    const check = await pool.query('SELECT uploader_id FROM videos WHERE id = $1', [videoId]);
    if (!check.rows.length) return res.status(404).json({ error: 'Video not found' });
    
    if (check.rows[0].uploader_id !== req.user.id && req.user.role !== 'super_admin') {
      return res.status(403).json({ error: 'You can only delete your own videos' });
    }

    await pool.query('DELETE FROM videos WHERE id = $1', [videoId]);
    await pool.query('UPDATE website_stats SET total_videos = total_videos - 1');
    await logUserActivity(req.user.id, 'delete_video', { videoId }, req);
    
    res.json({ success: true });
  } catch (error) {
    console.error('❌ Delete error:', error);
    res.status(500).json({ error: 'Failed to delete video' });
  }
});

// ============ PUBLIC INTERACTIONS ============
app.post('/api/videos/:id/like', async (req, res) => {
  try {
    const videoId = parseInt(req.params.id);
    const { action } = req.body;
    const field = action === 'like' ? 'likes' : 'dislikes';
    await pool.query(`UPDATE videos SET ${field} = ${field} + 1 WHERE id = $1`, [videoId]);
    if (action === 'like') {
      await pool.query('UPDATE website_stats SET total_likes = total_likes + 1');
    }
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to process' });
  }
});

app.post('/api/videos/:id/comment', async (req, res) => {
  try {
    const videoId = parseInt(req.params.id);
    const { username, comment } = req.body;
    
    if (!username || !comment) {
      return res.status(400).json({ error: 'Name and comment required' });
    }

    const result = await pool.query(
      'INSERT INTO comments (video_id, username, comment) VALUES ($1, $2, $3) RETURNING id, username, comment, created_at',
      [videoId, username.trim(), comment.trim()]
    );
    
    await pool.query('UPDATE website_stats SET total_comments = total_comments + 1');
    
    res.json({ success: true, comment: result.rows[0] });
  } catch (error) {
    console.error('Comment error:', error);
    res.status(500).json({ error: 'Failed to add comment: ' + error.message });
  }
});

app.post('/api/videos/:id/share', async (req, res) => {
  try {
    const videoId = parseInt(req.params.id);
    await pool.query('UPDATE videos SET share_count = share_count + 1 WHERE id = $1', [videoId]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to record share' });
  }
});

// ============ HEALTH CHECK ============
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

// ============ SERVE FRONTEND ============
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============ ERROR HANDLING ============
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Something went wrong: ' + err.message });
});

// ============ START SERVER ============
app.listen(PORT, async () => {
  console.log(`🚀 Server running on port ${PORT}`);
  await initDatabase();
});
