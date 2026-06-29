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
const crypto = require('crypto');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

app.set('trust proxy', 1);
app.set('x-powered-by', false);

// ============ ENV VALIDATION ============
const requiredEnv = ['DB_USER', 'DB_PASSWORD', 'DB_HOST', 'DB_NAME', 'JWT_SECRET'];
for (const env of requiredEnv) {
  if (!process.env[env]) {
    console.error(`❌ Missing required environment variable: ${env}`);
    process.exit(1);
  }
}

// Generate secure secrets if not provided
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const BCRYPT_ROUNDS = 12;
const JWT_EXPIRY = '7d';

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
  max: 5,
  message: { error: 'Too many login attempts. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: false },
});

const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: { error: 'Too many upload attempts. Please try again later.' },
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

// ============ SECURITY MIDDLEWARE ============

// 1. Helmet Security Headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
      imgSrc: ["'self'", "data:", "https:"],
      mediaSrc: ["'self'"],
      connectSrc: ["'self'"],
    },
  },
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy: true,
  crossOriginResourcePolicy: { policy: "same-site" },
  dnsPrefetchControl: true,
  frameguard: { action: 'deny' },
  hidePoweredBy: true,
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
  ieNoOpen: true,
  noSniff: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  xssFilter: true,
}));

// 2. Strict CORS
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));

// 3. Body Parsers with size limits
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());
app.use(compression());

// 4. XSS Protection
app.use((req, res, next) => {
  if (req.body) {
    for (let key in req.body) {
      if (typeof req.body[key] === 'string') {
        req.body[key] = xss(req.body[key].trim());
      }
    }
  }
  next();
});

// 5. Security Headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=(), payment=()');
  next();
});

// 6. Request ID for tracking
app.use((req, res, next) => {
  req.requestId = crypto.randomBytes(16).toString('hex');
  res.setHeader('X-Request-ID', req.requestId);
  next();
});

// ============ APPLY RATE LIMITING ============
app.use('/api/', limiter);
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);
app.use('/api/videos/upload', uploadLimiter);
app.use('/api/join/request', joinLimiter);

// ============ STATIC FILES ============
app.use('/uploads', express.static('uploads', {
  maxAge: '1y',
  immutable: true,
  dotfiles: 'deny',
}));
app.use(express.static('public', {
  maxAge: '1y',
  immutable: true,
  dotfiles: 'deny',
}));

// ============ CREATE DIRECTORIES ============
['uploads', 'uploads/videos', 'uploads/thumbnails'].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o755 });
});

// ============ MULTER WITH SECURE VALIDATION ============
const storage = multer.memoryStorage();

const fileFilter = (req, file, cb) => {
  const allowedVideo = ['video/mp4', 'video/webm', 'video/ogg', 'video/quicktime', 'video/x-msvideo'];
  const allowedImage = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
  
  if (file.fieldname === 'video' && !allowedVideo.includes(file.mimetype)) {
    return cb(new Error('Invalid video format. Allowed: MP4, WebM, OGG, MOV, AVI'));
  }
  if ((file.fieldname === 'thumbnail' || file.fieldname === 'proof') && !allowedImage.includes(file.mimetype)) {
    return cb(new Error('Invalid image format. Allowed: JPEG, PNG, GIF, WebP'));
  }
  cb(null, true);
};

const upload = multer({
  storage: storage,
  limits: { 
    fileSize: 500 * 1024 * 1024,
    files: 2,
  },
  fileFilter: fileFilter,
});

// ============ DATABASE CONNECTION ============
const pool = new Pool({
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT) || 5432,
  database: process.env.DB_NAME,
  ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
  connectionTimeoutMillis: 10000,
  max: 20,
  idleTimeoutMillis: 30000,
  statement_timeout: 30000,
});

pool.on('error', (err) => {
  console.error('❌ Database pool error:', err);
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
async function ensureAllColumns() {
  try {
    console.log('📝 Checking and adding missing columns...');
    
    await pool.query(`
      ALTER TABLE users 
      ADD COLUMN IF NOT EXISTS last_login TIMESTAMP,
      ADD COLUMN IF NOT EXISTS login_attempts INTEGER DEFAULT 0,
      ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP,
      ADD COLUMN IF NOT EXISTS is_approved BOOLEAN DEFAULT true,
      ADD COLUMN IF NOT EXISTS full_name VARCHAR(255),
      ADD COLUMN IF NOT EXISTS phone_number VARCHAR(50),
      ADD COLUMN IF NOT EXISTS join_request_date TIMESTAMP,
      ADD COLUMN IF NOT EXISTS join_request_plan VARCHAR(50),
      ADD COLUMN IF NOT EXISTS join_request_status VARCHAR(50) DEFAULT 'pending',
      ADD COLUMN IF NOT EXISTS subscription_status VARCHAR(50) DEFAULT 'pending',
      ADD COLUMN IF NOT EXISTS subscription_plan VARCHAR(50),
      ADD COLUMN IF NOT EXISTS subscription_start DATE,
      ADD COLUMN IF NOT EXISTS subscription_end DATE,
      ADD COLUMN IF NOT EXISTS subscription_proof_image BYTEA,
      ADD COLUMN IF NOT EXISTS subscription_proof_mimetype VARCHAR(100),
      ADD COLUMN IF NOT EXISTS subscription_proof_uploaded_at TIMESTAMP,
      ADD COLUMN IF NOT EXISTS subscription_verified_by INTEGER,
      ADD COLUMN IF NOT EXISTS subscription_verified_at TIMESTAMP,
      ADD COLUMN IF NOT EXISTS subscription_notes TEXT,
      ADD COLUMN IF NOT EXISTS last_ip INET,
      ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT true
    `);
    console.log('✅ All columns checked and added if missing');
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
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('✅ Users table ready');

    // Videos table
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
        uploader_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        uploader_name VARCHAR(255),
        views INTEGER DEFAULT 0,
        likes INTEGER DEFAULT 0,
        dislikes INTEGER DEFAULT 0,
        share_count INTEGER DEFAULT 0,
        file_size INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT true,
        video_hash VARCHAR(64)
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
        is_approved BOOLEAN DEFAULT true,
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
        processed_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
        processed_at TIMESTAMP,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL
      )
    `);
    console.log('✅ Join requests table ready');

    // Security logs table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS security_logs (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        event_type VARCHAR(100) NOT NULL,
        ip_address INET,
        user_agent TEXT,
        details JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('✅ Security logs table ready');

    await ensureAllColumns();

    // ===== CREATE SUPER ADMIN =====
    const adminUsername = process.env.ADMIN_USERNAME || 'OWNER_MPC';
    const adminPassword = process.env.ADMIN_PASSWORD || '08800+_+Owner!';
    const adminSecret = process.env.ADMIN_SECRET || 'ADMIN_SECRET_2024';

    const adminCheck = await pool.query('SELECT * FROM users WHERE username = $1', [adminUsername]);
    if (adminCheck.rows.length === 0) {
      const hashedPassword = await bcrypt.hash(adminPassword, BCRYPT_ROUNDS);
      const hashedSecret = await bcrypt.hash(adminSecret, BCRYPT_ROUNDS);
      await pool.query(
        `INSERT INTO users (username, password, secret_code, role, heard_from, is_approved, full_name, is_verified) 
         VALUES ($1, $2, $3, 'super_admin', 'system', true, 'Super Administrator', true)`,
        [adminUsername, hashedPassword, hashedSecret]
      );
      console.log('✅ Super Admin created');
    }

    // Payment settings
    const paymentCheck = await pool.query('SELECT * FROM payment_settings');
    if (paymentCheck.rows.length === 0) {
      await pool.query(`
        INSERT INTO payment_settings (bank_name, account_number, account_owner, phone_number)
        VALUES ('Equity Bank', '1234567890', 'BuTube Platform', '+250 788 888 888')
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

// ============ SECURITY LOGGING ============
async function logSecurityEvent(eventType, details, req = null) {
  try {
    const userId = req?.user?.id || null;
    const ip = req?.ip || req?.connection?.remoteAddress || 'unknown';
    const userAgent = req?.headers?.['user-agent'] || 'unknown';
    
    await pool.query(
      `INSERT INTO security_logs (user_id, event_type, ip_address, user_agent, details) 
       VALUES ($1, $2, $3, $4, $5)`,
      [userId, eventType, ip, userAgent, JSON.stringify(details || {})]
    );
  } catch (error) {
    console.error('Security log error:', error);
  }
}

// ============ AUTH MIDDLEWARE ============
const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      await logSecurityEvent('auth_failure', { reason: 'no_token' }, req);
      return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];
    
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      
      const user = await pool.query(
        `SELECT id, username, role, is_approved, subscription_end,
                CASE 
                  WHEN subscription_end IS NOT NULL AND subscription_end > CURRENT_DATE 
                  THEN (subscription_end - CURRENT_DATE)
                  ELSE 0 
                END as days_remaining
         FROM users WHERE id = $1`,
        [decoded.userId]
      );
      
      if (!user.rows.length) {
        await logSecurityEvent('auth_failure', { reason: 'user_not_found' }, req);
        return res.status(401).json({ error: 'User not found' });
      }
      
      if (!user.rows[0].is_approved) {
        await logSecurityEvent('auth_failure', { reason: 'not_approved' }, req);
        return res.status(403).json({ error: 'Account not approved' });
      }
      
      req.user = user.rows[0];
      await logSecurityEvent('auth_success', { userId: req.user.id }, req);
      next();
    } catch (jwtError) {
      if (jwtError.name === 'TokenExpiredError') {
        await logSecurityEvent('auth_failure', { reason: 'token_expired' }, req);
        return res.status(401).json({ error: 'Token expired' });
      }
      if (jwtError.name === 'JsonWebTokenError') {
        await logSecurityEvent('auth_failure', { reason: 'invalid_token' }, req);
        return res.status(401).json({ error: 'Invalid token' });
      }
      throw jwtError;
    }
  } catch (error) {
    console.error('Auth error:', error);
    await logSecurityEvent('auth_error', { error: error.message }, req);
    return res.status(401).json({ error: 'Authentication failed' });
  }
};

const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    if (!roles.includes(req.user.role)) {
      logSecurityEvent('auth_failure', { 
        reason: 'insufficient_permissions',
        userId: req.user.id,
        role: req.user.role,
        required: roles 
      }, req);
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
};

// ============ LOG USER ACTIVITY ============
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

// ============ AUTH ROUTES ============

// ============ REGISTER ============
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { username, password, secretCode } = req.body;

    if (!username || !password || !secretCode) {
      return res.status(400).json({ error: 'Username, password, and secret code are required' });
    }

    if (username.length < 3) {
      return res.status(400).json({ error: 'Username must be at least 3 characters' });
    }

    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    if (secretCode.length < 4) {
      return res.status(400).json({ error: 'Secret code must be at least 4 characters' });
    }

    const userCheck = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const hashedSecret = await bcrypt.hash(secretCode, BCRYPT_ROUNDS);

    const result = await pool.query(
      `INSERT INTO users (username, password, secret_code, role, is_approved, is_verified) 
       VALUES ($1, $2, $3, 'user', true, true) 
       RETURNING id, username, role`,
      [username, hashedPassword, hashedSecret]
    );

    const token = jwt.sign(
      { userId: result.rows[0].id, username: result.rows[0].username },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRY }
    );

    await logSecurityEvent('registration_success', { userId: result.rows[0].id }, req);

    res.json({
      token,
      user: result.rows[0],
      message: 'Registration successful!'
    });
  } catch (error) {
    console.error('Register error:', error);
    await logSecurityEvent('registration_error', { error: error.message }, req);
    res.status(500).json({ error: 'Registration failed: ' + error.message });
  }
});

// ============ LOGIN ============
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const user = await pool.query(
      `SELECT id, username, password, role, is_approved, login_attempts, locked_until, subscription_end,
              CASE 
                WHEN subscription_end IS NOT NULL AND subscription_end > CURRENT_DATE 
                THEN (subscription_end - CURRENT_DATE)
                ELSE 0 
              END as days_remaining
       FROM users WHERE username = $1`,
      [username]
    );

    if (user.rows.length === 0) {
      await logSecurityEvent('login_failure', { reason: 'user_not_found' }, req);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const userData = user.rows[0];

    // Check account lockout
    if (userData.locked_until && new Date(userData.locked_until) > new Date()) {
      await logSecurityEvent('login_failure', { reason: 'account_locked' }, req);
      return res.status(403).json({ 
        error: `Account locked. Try again after ${new Date(userData.locked_until).toLocaleString()}`
      });
    }

    const validPassword = await bcrypt.compare(password, userData.password);
    if (!validPassword) {
      const attempts = (userData.login_attempts || 0) + 1;
      let lockUntil = null;
      
      if (attempts >= 5) {
        lockUntil = new Date(Date.now() + 15 * 60 * 1000);
      }

      await pool.query(
        'UPDATE users SET login_attempts = $1, locked_until = $2 WHERE id = $3',
        [attempts, lockUntil, userData.id]
      );

      await logSecurityEvent('login_failure', { 
        reason: 'invalid_password',
        attempts 
      }, req);

      return res.status(401).json({ 
        error: 'Invalid credentials',
        attemptsRemaining: Math.max(0, 5 - attempts)
      });
    }

    // Reset login attempts on success
    await pool.query(
      `UPDATE users SET 
        login_attempts = 0, 
        locked_until = NULL,
        last_login = CURRENT_TIMESTAMP,
        last_ip = $1
       WHERE id = $2`,
      [req.ip, userData.id]
    );

    const token = jwt.sign(
      { userId: userData.id, username: userData.username },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRY }
    );

    await logSecurityEvent('login_success', { userId: userData.id }, req);

    res.json({
      token,
      user: {
        id: userData.id,
        username: userData.username,
        role: userData.role,
        is_approved: userData.is_approved,
        days_remaining: userData.days_remaining || 0,
        subscription_end: userData.subscription_end
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    await logSecurityEvent('login_error', { error: error.message }, req);
    res.status(500).json({ error: 'Login failed: ' + error.message });
  }
});

// ============ GET CURRENT USER ============
app.get('/api/auth/me', authenticate, async (req, res) => {
  try {
    const user = await pool.query(
      `SELECT id, username, role, is_approved, full_name, phone_number, subscription_end,
              CASE 
                WHEN subscription_end IS NOT NULL AND subscription_end > CURRENT_DATE 
                THEN (subscription_end - CURRENT_DATE)
                ELSE 0 
              END as days_remaining
       FROM users WHERE id = $1`,
      [req.user.id]
    );
    res.json({ user: user.rows[0] });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Failed to get user info' });
  }
});

// ============ LOGOUT ============
app.post('/api/auth/logout', authenticate, async (req, res) => {
  try {
    await logSecurityEvent('logout_success', { userId: req.user.id }, req);
    res.json({ success: true, message: 'Logged out successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Logout failed' });
  }
});

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
      SELECT id, full_name, phone_number, email, plan, status, created_at, 
             proof_image IS NOT NULL as has_proof,
             proof_mimetype
      FROM join_requests 
      ORDER BY created_at DESC
    `);
    res.json(result.rows);
  } catch (error) {
    console.error('Join requests error:', error);
    res.status(500).json({ error: 'Failed to get join requests' });
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
      return res.status(404).json({ error: 'Proof not found' });
    }

    res.setHeader('Content-Type', result.rows[0].proof_mimetype || 'image/jpeg');
    res.send(result.rows[0].proof_image);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get proof' });
  }
});

// ============ PROCESS JOIN REQUEST ============
app.post('/api/admin/process-join-request/:id', authenticate, authorize('super_admin'), async (req, res) => {
  try {
    const requestId = parseInt(req.params.id);
    const { action, username, password, secretCode, notes, subscriptionDays } = req.body;

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

      if (password.length < 8) {
        return res.status(400).json({ error: 'Password must be at least 8 characters' });
      }

      if (secretCode.length < 4) {
        return res.status(400).json({ error: 'Secret code must be at least 4 characters' });
      }

      const userCheck = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
      if (userCheck.rows.length > 0) {
        return res.status(400).json({ error: 'Username already exists' });
      }

      const hashedPassword = await bcrypt.hash(password, BCRYPT_ROUNDS);
      const hashedSecret = await bcrypt.hash(secretCode, BCRYPT_ROUNDS);

      let subscriptionEnd = null;
      let days = parseInt(subscriptionDays) || 30;
      if (days > 0) {
        subscriptionEnd = new Date();
        subscriptionEnd.setDate(subscriptionEnd.getDate() + days);
      }

      const userResult = await pool.query(
        `INSERT INTO users (username, password, secret_code, role, full_name, phone_number, subscription_end, is_approved, is_verified) 
         VALUES ($1, $2, $3, 'creator', $4, $5, $6, true, true) 
         RETURNING id, username, role`,
        [username, hashedPassword, hashedSecret, request.full_name, request.phone_number, subscriptionEnd]
      );

      await pool.query(
        'UPDATE join_requests SET status = $1, processed_by = $2, processed_at = CURRENT_TIMESTAMP, user_id = $3, notes = $4 WHERE id = $5',
        ['approved', req.user.id, userResult.rows[0].id, notes || null, requestId]
      );

      await logUserActivity(req.user.id, 'approve_join_request', { 
        requestId, 
        userId: userResult.rows[0].id,
        username,
        subscriptionDays: days
      }, req);

      res.json({ 
        success: true, 
        message: `User ${username} has been approved as a creator with ${days} days subscription!`,
        user: userResult.rows[0]
      });
    } else {
      await pool.query(
        'UPDATE join_requests SET status = $1, processed_by = $2, processed_at = CURRENT_TIMESTAMP, notes = $3 WHERE id = $4',
        ['rejected', req.user.id, notes || 'Request rejected', requestId]
      );

      await logUserActivity(req.user.id, 'reject_join_request', { 
        requestId,
        phoneNumber: request.phone_number 
      }, req);

      res.json({ success: true, message: 'Request rejected' });
    }
  } catch (error) {
    console.error('Process request error:', error);
    res.status(500).json({ error: 'Failed to process request: ' + error.message });
  }
});

// ============ SUPER ADMIN DASHBOARD STATS ============
app.get('/api/admin/super-stats', authenticate, authorize('super_admin'), async (req, res) => {
  try {
    const userStats = await pool.query(`
      SELECT 
        COUNT(*) as total_users,
        COUNT(CASE WHEN role = 'super_admin' THEN 1 END) as super_admins,
        COUNT(CASE WHEN role = 'creator' THEN 1 END) as creators,
        COUNT(CASE WHEN role = 'user' THEN 1 END) as regular_users,
        COUNT(CASE WHEN subscription_end IS NOT NULL AND subscription_end > CURRENT_DATE THEN 1 END) as active_subscriptions,
        COUNT(CASE WHEN subscription_end IS NOT NULL AND subscription_end < CURRENT_DATE THEN 1 END) as expired_subscriptions
      FROM users
    `);

    const videoStats = await pool.query(`
      SELECT 
        COUNT(*) as total_videos,
        SUM(views) as total_views,
        SUM(likes) as total_likes,
        SUM(dislikes) as total_dislikes,
        SUM(share_count) as total_shares,
        COUNT(CASE WHEN is_active = true THEN 1 END) as active_videos
      FROM videos
    `);

    const joinRequestStats = await pool.query(`
      SELECT 
        COUNT(*) as total_requests,
        COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_requests,
        COUNT(CASE WHEN status = 'approved' THEN 1 END) as approved_requests,
        COUNT(CASE WHEN status = 'rejected' THEN 1 END) as rejected_requests
      FROM join_requests
    `);

    const commentCount = await pool.query('SELECT COUNT(*) as total_comments FROM comments');

    const recentUsers = await pool.query(`
      SELECT id, username, role, created_at, full_name, subscription_end
      FROM users 
      ORDER BY created_at DESC 
      LIMIT 10
    `);

    const allUsers = await pool.query(`
      SELECT id, username, role, subscription_end,
             CASE 
               WHEN subscription_end IS NOT NULL AND subscription_end > CURRENT_DATE 
               THEN (subscription_end - CURRENT_DATE)
               ELSE 0 
             END as days_remaining
      FROM users 
      WHERE role IN ('creator', 'user')
      ORDER BY created_at DESC
    `);

    const recentVideos = await pool.query(`
      SELECT id, title, views, likes, created_at, uploader_name
      FROM videos 
      ORDER BY created_at DESC 
      LIMIT 10
    `);

    const recentJoinRequests = await pool.query(`
      SELECT id, full_name, phone_number, plan, status, created_at
      FROM join_requests 
      ORDER BY created_at DESC 
      LIMIT 10
    `);

    const websiteStats = await pool.query('SELECT * FROM website_stats LIMIT 1');

    res.json({
      success: true,
      stats: {
        users: userStats.rows[0],
        videos: videoStats.rows[0],
        comments: commentCount.rows[0],
        joinRequests: joinRequestStats.rows[0],
        website: websiteStats.rows[0] || { total_visits: 0, total_users: 0, total_videos: 0, total_views: 0, total_likes: 0, total_comments: 0 }
      },
      recent: {
        users: recentUsers.rows,
        videos: recentVideos.rows,
        joinRequests: recentJoinRequests.rows
      },
      allUsers: allUsers.rows
    });

  } catch (error) {
    console.error('❌ Admin stats error:', error);
    res.status(500).json({ error: 'Failed to get admin statistics: ' + error.message });
  }
});

// ============ GET ALL USERS (Admin) ============
app.get('/api/admin/users', authenticate, authorize('super_admin'), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, username, role, created_at, full_name, phone_number,
             subscription_end,
             CASE 
               WHEN subscription_end IS NOT NULL AND subscription_end > CURRENT_DATE 
               THEN (subscription_end - CURRENT_DATE)
               ELSE 0 
             END as days_remaining
      FROM users 
      ORDER BY created_at DESC
    `);
    res.json(result.rows);
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Failed to get users' });
  }
});

// ============ DELETE USER (Admin only) ============
app.delete('/api/admin/users/:id', authenticate, authorize('super_admin'), async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    
    if (userId === req.user.id) {
      return res.status(400).json({ error: 'You cannot delete your own account' });
    }

    const userCheck = await pool.query('SELECT role FROM users WHERE id = $1', [userId]);
    if (userCheck.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (userCheck.rows[0].role === 'super_admin') {
      return res.status(403).json({ error: 'Cannot delete another super admin' });
    }

    // Clean up references
    await pool.query('UPDATE join_requests SET user_id = NULL, processed_by = NULL WHERE user_id = $1 OR processed_by = $1', [userId]);
    await pool.query('DELETE FROM videos WHERE uploader_id = $1', [userId]);
    await pool.query('DELETE FROM comments WHERE username IN (SELECT username FROM users WHERE id = $1)', [userId]);
    await pool.query('DELETE FROM user_logs WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM user_actions WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM users WHERE id = $1', [userId]);
    
    await logUserActivity(req.user.id, 'delete_user', { userId }, req);
    res.json({ success: true, message: 'User deleted successfully' });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ error: 'Failed to delete user: ' + error.message });
  }
});

// ============ UPDATE SUBSCRIPTION (Admin) ============
app.put('/api/admin/users/:id/subscription', authenticate, authorize('super_admin'), async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    const { days } = req.body;

    if (!days || days < 1) {
      return res.status(400).json({ error: 'Valid days are required' });
    }

    const subscriptionEnd = new Date();
    subscriptionEnd.setDate(subscriptionEnd.getDate() + days);

    await pool.query(
      'UPDATE users SET subscription_end = $1 WHERE id = $2',
      [subscriptionEnd, userId]
    );

    await logUserActivity(req.user.id, 'update_subscription', { userId, days }, req);
    res.json({ success: true, message: `Subscription updated with ${days} days` });
  } catch (error) {
    console.error('Update subscription error:', error);
    res.status(500).json({ error: 'Failed to update subscription' });
  }
});

// ============ PAYMENT SETTINGS ============
app.get('/api/payment-settings', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM payment_settings ORDER BY id DESC LIMIT 1');
    res.json(result.rows);
  } catch (error) {
    console.error('Payment settings error:', error);
    res.status(500).json({ error: 'Failed to get payment settings' });
  }
});

app.post('/api/payment-settings', authenticate, authorize('super_admin'), async (req, res) => {
  try {
    const { bankName, accountNumber, accountOwner, phoneNumber } = req.body;
    
    const check = await pool.query('SELECT id FROM payment_settings LIMIT 1');
    
    if (check.rows.length > 0) {
      await pool.query(
        `UPDATE payment_settings 
         SET bank_name = $1, account_number = $2, account_owner = $3, phone_number = $4, 
             updated_by = $5, updated_at = CURRENT_TIMESTAMP
         WHERE id = $6`,
        [bankName, accountNumber, accountOwner, phoneNumber, req.user.id, check.rows[0].id]
      );
    } else {
      await pool.query(
        `INSERT INTO payment_settings (bank_name, account_number, account_owner, phone_number, updated_by, updated_at) 
         VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)`,
        [bankName, accountNumber, accountOwner, phoneNumber, req.user.id]
      );
    }
    
    res.json({ success: true, message: 'Payment settings updated' });
  } catch (error) {
    console.error('Update payment error:', error);
    res.status(500).json({ error: 'Failed to update payment settings' });
  }
});

// ============ VIDEO ROUTES ============
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

// ============ CHECK SUBSCRIPTION ============
const checkSubscription = async (userId) => {
  const result = await pool.query(
    `SELECT subscription_end 
     FROM users 
     WHERE id = $1 AND subscription_end IS NOT NULL AND subscription_end > CURRENT_DATE`,
    [userId]
  );
  return result.rows.length > 0;
};

// ============ UPLOAD VIDEO ============
app.post('/api/videos/upload', authenticate, authorize('creator', 'super_admin'), upload.fields([
  { name: 'video', maxCount: 1 },
  { name: 'thumbnail', maxCount: 1 }
]), async (req, res) => {
  try {
    // Check subscription for creators
    if (req.user.role === 'creator') {
      const hasSubscription = await checkSubscription(req.user.id);
      if (!hasSubscription) {
        return res.status(403).json({ 
          error: 'Your subscription has expired. Please renew to upload videos.' 
        });
      }
    }

    const { title, description } = req.body;
    
    if (!title) {
      return res.status(400).json({ error: 'Title is required' });
    }

    if (!req.files || !req.files['video']) {
      return res.status(400).json({ error: 'Video file is required' });
    }

    const videoFile = req.files['video'][0];
    const thumbnailFile = req.files['thumbnail'] ? req.files['thumbnail'][0] : null;

    // Generate video hash for integrity
    const videoHash = crypto.createHash('sha256').update(videoFile.buffer).digest('hex');

    const result = await pool.query(
      `INSERT INTO videos (title, description, video_data, video_mimetype, video_filename, 
                           thumbnail_data, thumbnail_mimetype, uploader_id, uploader_name, file_size, video_hash)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       RETURNING id, title, description, created_at`,
      [
        title,
        description || '',
        videoFile.buffer,
        videoFile.mimetype,
        videoFile.originalname.replace(/[^a-zA-Z0-9.-]/g, '_'),
        thumbnailFile ? thumbnailFile.buffer : null,
        thumbnailFile ? thumbnailFile.mimetype : null,
        req.user.id,
        req.user.username,
        videoFile.size,
        videoHash
      ]
    );

    await pool.query('UPDATE website_stats SET total_videos = total_videos + 1');
    
    await logUserActivity(req.user.id, 'upload_video', { 
      videoId: result.rows[0].id, 
      title,
      fileSize: videoFile.size 
    }, req);

    res.json({
      success: true,
      message: 'Video uploaded successfully!',
      video: result.rows[0]
    });

  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Failed to upload video: ' + error.message });
  }
});

// ============ STREAM VIDEO WITH RANGE SUPPORT ============
app.get('/api/videos/:id/stream', async (req, res) => {
  try {
    const videoId = parseInt(req.params.id);
    if (isNaN(videoId)) {
      return res.status(400).json({ error: 'Invalid video ID' });
    }

    const result = await pool.query(
      'SELECT video_data, video_mimetype, video_hash FROM videos WHERE id = $1 AND is_active = true',
      [videoId]
    );

    if (result.rows.length === 0 || !result.rows[0].video_data) {
      return res.status(404).json({ error: 'Video not found' });
    }

    const video = result.rows[0];
    const videoData = video.video_data;
    const videoSize = videoData.length;
    const mimeType = video.video_mimetype || 'video/mp4';

    // Set security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', "default-src 'none'; media-src 'self'");

    const range = req.headers.range;
    
    if (!range) {
      res.setHeader('Content-Type', mimeType);
      res.setHeader('Content-Length', videoSize);
      res.setHeader('Accept-Ranges', 'bytes');
      return res.send(videoData);
    }

    const parts = range.replace(/bytes=/, '').split('-');
    const start = parseInt(parts[0], 10);
    const end = parts[1] ? parseInt(parts[1], 10) : videoSize - 1;
    const chunksize = (end - start) + 1;

    if (start >= videoSize || end >= videoSize) {
      res.setHeader('Content-Range', `bytes */${videoSize}`);
      return res.status(416).json({ error: 'Requested range not satisfiable' });
    }

    res.setHeader('Content-Range', `bytes ${start}-${end}/${videoSize}`);
    res.setHeader('Accept-Ranges', 'bytes');
    res.setHeader('Content-Length', chunksize);
    res.setHeader('Content-Type', mimeType);
    res.status(206).send(videoData.slice(start, end + 1));

  } catch (error) {
    console.error('Stream error:', error);
    res.status(500).json({ error: 'Failed to stream video: ' + error.message });
  }
});

// ============ GET THUMBNAIL ============
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

// ============ GET VIDEO DETAILS ============
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

// ============ UPDATE VIDEO ============
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
    console.error('Update error:', error);
    res.status(500).json({ error: 'Failed to update video' });
  }
});

// ============ DELETE VIDEO ============
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

// ============ LIKE VIDEO ============
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
    console.error('Like error:', error);
    res.status(500).json({ error: 'Failed to process' });
  }
});

// ============ COMMENT ============
app.post('/api/videos/:id/comment', async (req, res) => {
  try {
    const videoId = parseInt(req.params.id);
    const { username, comment } = req.body;

    if (!username || !comment) {
      return res.status(400).json({ error: 'Name and comment required' });
    }

    // Sanitize comment
    const sanitizedComment = xss(comment.trim());
    const sanitizedUsername = xss(username.trim());

    const result = await pool.query(
      'INSERT INTO comments (video_id, username, comment) VALUES ($1, $2, $3) RETURNING id, username, comment, created_at',
      [videoId, sanitizedUsername, sanitizedComment]
    );

    await pool.query('UPDATE website_stats SET total_comments = total_comments + 1');

    res.json({ success: true, comment: result.rows[0] });
  } catch (error) {
    console.error('Comment error:', error);
    res.status(500).json({ error: 'Failed to add comment: ' + error.message });
  }
});

// ============ SHARE ============
app.post('/api/videos/:id/share', async (req, res) => {
  try {
    const videoId = parseInt(req.params.id);
    await pool.query('UPDATE videos SET share_count = share_count + 1 WHERE id = $1', [videoId]);
    res.json({ success: true });
  } catch (error) {
    console.error('Share error:', error);
    res.status(500).json({ error: 'Failed to record share' });
  }
});

// ============ HEALTH CHECK ============
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ============ SERVE FRONTEND ============
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============ ERROR HANDLING ============
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  // Don't expose internal errors
  res.status(500).json({ error: 'Something went wrong. Please try again later.' });
});

// ============ START SERVER ============
app.listen(PORT, async () => {
  console.log(`🚀 Server running on port ${PORT}`);
  await initDatabase();
});

