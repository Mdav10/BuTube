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
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// ============ SECURITY: Strong JWT Secret ============
const JWT_SECRET = process.env.JWT_SECRET || 'akabakuze_super_secure_secret_key_2024_7x9k2m5p8q3w';

// ============ SECURITY: Rate Limiting ============
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per window
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // Limit each IP to 10 login attempts per hour
  message: { error: 'Too many login attempts, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 20, // Limit each IP to 20 uploads per hour
  message: { error: 'Too many upload attempts, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ============ SECURITY: Helmet (Security Headers) ============
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      mediaSrc: ["'self'", "data:", "blob:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'", "https:", "data:"],
    },
  },
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy: true,
  crossOriginResourcePolicy: { policy: "same-site" },
  dnsPrefetchControl: true,
  frameguard: { action: "deny" },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  ieNoOpen: true,
  noSniff: true,
  referrerPolicy: { policy: "same-origin" },
  xssFilter: true,
}));

// ============ SECURITY: CORS ============
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));

// ============ SECURITY: Cookie Parser ============
app.use(cookieParser());

// ============ SECURITY: CSRF Protection ============
const csrfProtection = csrf({ cookie: true });

// ============ SECURITY: Input Sanitization ============
app.use(express.json({ limit: '500mb' }));
app.use(express.urlencoded({ extended: true, limit: '500mb' }));

// ============ SECURITY: XSS Protection ============
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

// ============ SECURITY: Compression ============
app.use(compression());

// ============ SECURITY: Apply Rate Limiting ============
app.use('/api/', limiter);
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);
app.use('/api/videos/upload', uploadLimiter);

// ============ SECURITY: Static Files ============
app.use(express.static('public', {
  maxAge: '1d',
  etag: true,
  lastModified: true,
}));

// ============ SECURITY: SQL Injection Prevention ============
// (Using parameterized queries throughout - already done)

// ============ DATABASE CONNECTION ============
const pool = new Pool({
  user: 'neondb_owner',
  password: 'npg_Cb7XtKr0BIoN',
  host: 'ep-holy-scene-apw8vqig.c-7.us-east-1.aws.neon.tech',
  port: 5432,
  database: 'neondb',
  ssl: { rejectUnauthorized: false },
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

// ============ MULTER CONFIG ============
const storage = multer.memoryStorage();

const upload = multer({
  storage: storage,
  limits: { 
    fileSize: 500 * 1024 * 1024,
    files: 2,
  },
  fileFilter: (req, file, cb) => {
    if (file.fieldname === 'video') {
      const allowedTypes = ['video/mp4', 'video/webm', 'video/ogg', 'video/quicktime', 'video/x-msvideo'];
      if (!allowedTypes.includes(file.mimetype) && !file.mimetype.startsWith('video/')) {
        return cb(new Error('Only video files are allowed'));
      }
    } else if (file.fieldname === 'thumbnail') {
      const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
      if (!allowedTypes.includes(file.mimetype) && !file.mimetype.startsWith('image/')) {
        return cb(new Error('Only image files are allowed for thumbnails'));
      }
    }
    cb(null, true);
  }
});

// ============ SECURITY: Input Validation Helpers ============
const isValidUsername = (username) => {
  return username && username.length >= 3 && username.length <= 50 && /^[a-zA-Z0-9_]+$/.test(username);
};

const isValidPassword = (password) => {
  return password && password.length >= 6;
};

const isValidSecretCode = (code) => {
  return code && code.length >= 4 && code.length <= 100;
};

const isValidTitle = (title) => {
  return title && title.length >= 1 && title.length <= 500;
};

const isValidComment = (comment) => {
  return comment && comment.length >= 1 && comment.length <= 1000;
};

// ============ INIT DATABASE ============
async function initDatabase() {
  try {
    console.log('🔄 Initializing database...');

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
        locked_until TIMESTAMP
      )
    `);

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

    await pool.query(`
      CREATE TABLE IF NOT EXISTS comments (
        id SERIAL PRIMARY KEY,
        video_id INTEGER REFERENCES videos(id) ON DELETE CASCADE,
        username VARCHAR(255) NOT NULL,
        comment TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

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

    await pool.query(`
      CREATE TABLE IF NOT EXISTS website_stats (
        id SERIAL PRIMARY KEY,
        total_visits INTEGER DEFAULT 0,
        total_users INTEGER DEFAULT 0,
        total_videos INTEGER DEFAULT 0,
        total_views INTEGER DEFAULT 0,
        total_likes INTEGER DEFAULT 0,
        total_comments INTEGER DEFAULT 0,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create Super Admin if not exists
    const adminCheck = await pool.query('SELECT * FROM users WHERE username = $1', ['OWNER_MPC']);
    if (adminCheck.rows.length === 0) {
      const hashedPassword = await bcrypt.hash('08800+_+Owner!', 10);
      const hashedSecret = await bcrypt.hash('ADMIN_SECRET_2024', 10);
      await pool.query(
        `INSERT INTO users (username, password, secret_code, role, heard_from) 
         VALUES ($1, $2, $3, 'super_admin', 'system')`,
        ['OWNER_MPC', hashedPassword, hashedSecret]
      );
      console.log('✅ Super Admin created');
    }

    // Initialize stats if empty
    const statsCheck = await pool.query('SELECT * FROM website_stats');
    if (statsCheck.rows.length === 0) {
      await pool.query(`
        INSERT INTO website_stats (total_visits, total_users, total_videos, total_views, total_likes, total_comments) 
        VALUES (0, 0, 0, 0, 0, 0)
      `);
    }

    // Update stats
    const userCount = await pool.query('SELECT COUNT(*) as count FROM users');
    const videoCount = await pool.query('SELECT COUNT(*) as count FROM videos');
    await pool.query(
      'UPDATE website_stats SET total_users = $1, total_videos = $2',
      [parseInt(userCount.rows[0].count), parseInt(videoCount.rows[0].count)]
    );

    console.log('✅ Database ready');
    console.log('👑 Super Admin: OWNER_MPC');
    console.log('🔑 Password: 08800+_+Owner!');
    console.log('🔐 Secret: ADMIN_SECRET_2024');
  } catch (error) {
    console.error('❌ Database error:', error.message);
  }
}

// ============ SECURITY: Stronger Auth Middleware ============
const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const user = await pool.query(
      'SELECT id, username, role FROM users WHERE id = $1 AND is_active = true',
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
    return res.status(403).json({ error: 'Authentication failed' });
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

// ============ SECURITY: Logging with sanitization ============
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

// ============ SECURITY: Block IP after too many failed attempts ============
async function handleFailedLogin(username, req) {
  const ip = req.ip || req.connection?.remoteAddress || 'unknown';
  const attempts = await pool.query(
    'SELECT COUNT(*) as count FROM user_logs WHERE ip_address = $1 AND action = $2 AND created_at > NOW() - INTERVAL \'1 hour\'',
    [ip, 'login_failed']
  );
  
  if (parseInt(attempts.rows[0].count) > 5) {
    await pool.query(
      'UPDATE users SET locked_until = NOW() + INTERVAL \'1 hour\' WHERE username = $1',
      [username]
    );
  }
}

// ============ AUTH ROUTES ============
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password, secretCode, heardFrom } = req.body;
    
    if (!isValidUsername(username)) {
      return res.status(400).json({ error: 'Username must be 3-50 characters and contain only letters, numbers, and underscores' });
    }
    
    if (!isValidPassword(password)) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    if (!isValidSecretCode(secretCode)) {
      return res.status(400).json({ error: 'Secret code must be at least 4 characters' });
    }
    
    const existing = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (existing.rows.length) return res.status(400).json({ error: 'Username already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const hashedSecret = await bcrypt.hash(secretCode, 10);
    
    const result = await pool.query(
      `INSERT INTO users (username, password, secret_code, heard_from, role) 
       VALUES ($1, $2, $3, $4, 'user') RETURNING id, username, role`,
      [username, hashedPassword, hashedSecret, heardFrom]
    );
    
    await pool.query('UPDATE website_stats SET total_users = total_users + 1, total_visits = total_visits + 1');
    await logUserActivity(result.rows[0].id, 'register', { heardFrom }, req);
    
    const token = jwt.sign(
      { userId: result.rows[0].id, username: result.rows[0].username, role: result.rows[0].role },
      JWT_SECRET,
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
    
    const result = await pool.query(
      'SELECT * FROM users WHERE username = $1 AND (locked_until IS NULL OR locked_until < NOW())',
      [username]
    );
    
    if (!result.rows.length) {
      await logUserActivity(null, 'login_failed', { username, reason: 'user_not_found' }, req);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password);
    const validSecret = await bcrypt.compare(secretCode, user.secret_code);
    
    if (!validPassword || !validSecret) {
      await logUserActivity(user.id, 'login_failed', { reason: 'invalid_credentials' }, req);
      await handleFailedLogin(username, req);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    await pool.query('UPDATE users SET last_login = NOW(), login_attempts = 0 WHERE id = $1', [user.id]);
    await pool.query('UPDATE website_stats SET total_visits = total_visits + 1');
    await logUserActivity(user.id, 'login', { success: true }, req);
    
    const token = jwt.sign(
      { userId: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.json({ 
      token, 
      user: { 
        id: user.id, 
        username: user.username, 
        role: user.role,
        lastLogin: user.last_login 
      } 
    });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/auth/me', authenticate, async (req, res) => {
  res.json({ user: req.user });
});

app.post('/api/auth/heard-from', authenticate, async (req, res) => {
  try {
    const { heardFrom } = req.body;
    const validSources = ['friend', 'self', 'facebook', 'instagram', 'twitter', 'other'];
    if (!validSources.includes(heardFrom)) {
      return res.status(400).json({ error: 'Invalid source' });
    }
    await pool.query('UPDATE users SET heard_from = $1 WHERE id = $2', [heardFrom, req.user.id]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update' });
  }
});

app.post('/api/auth/logout', authenticate, async (req, res) => {
  await logUserActivity(req.user.id, 'logout', {}, req);
  res.json({ success: true });
});

// ============ ADMIN ROUTES ============
app.post('/api/admin/create-admin', authenticate, authorize('super_admin'), async (req, res) => {
  try {
    const { username, password, secretCode } = req.body;
    
    if (!isValidUsername(username)) {
      return res.status(400).json({ error: 'Username must be 3-50 characters' });
    }
    if (!isValidPassword(password)) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    if (!isValidSecretCode(secretCode)) {
      return res.status(400).json({ error: 'Secret code must be at least 4 characters' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const hashedSecret = await bcrypt.hash(secretCode, 10);
    
    const result = await pool.query(
      `INSERT INTO users (username, password, secret_code, role) 
       VALUES ($1, $2, $3, 'admin') RETURNING id, username, role`,
      [username, hashedPassword, hashedSecret]
    );
    
    await logUserActivity(req.user.id, 'create_admin', { newAdmin: username }, req);
    
    res.json({ success: true, admin: result.rows[0], secretCode });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create admin' });
  }
});

app.get('/api/admin/super-stats', authenticate, authorize('super_admin'), async (req, res) => {
  try {
    const stats = await pool.query('SELECT * FROM website_stats LIMIT 1');
    const users = await pool.query('SELECT COUNT(*) as total FROM users');
    const admins = await pool.query("SELECT COUNT(*) as total FROM users WHERE role IN ('admin', 'super_admin')");
    const videos = await pool.query('SELECT COUNT(*) as total FROM videos');
    const comments = await pool.query('SELECT COUNT(*) as total FROM comments');
    
    const allAdmins = await pool.query(`
      SELECT id, username, role, created_at, last_login
      FROM users 
      WHERE role IN ('admin', 'super_admin')
      ORDER BY created_at DESC
    `);

    const allVideos = await pool.query(`
      SELECT v.id, v.title, v.views, v.likes, v.share_count, v.created_at, u.username as uploader_name
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
      SELECT id, username, role, heard_from, created_at, last_login
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
      stats: stats.rows[0] || { 
        total_visits: 0, 
        total_users: 0, 
        total_videos: 0, 
        total_views: 0,
        total_likes: 0,
        total_comments: 0
      },
      userCount: parseInt(users.rows[0].total),
      adminCount: parseInt(admins.rows[0].total),
      videoCount: parseInt(videos.rows[0].total),
      commentCount: parseInt(comments.rows[0].total),
      allAdmins: allAdmins.rows,
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

app.get('/api/admin/my-stats', authenticate, authorize('admin', 'super_admin'), async (req, res) => {
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

app.get('/api/admin/my-videos', authenticate, authorize('admin', 'super_admin'), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, title, description, uploader_id, uploader_name, views, likes, dislikes, share_count, file_size, created_at, 
              CASE WHEN video_data IS NOT NULL THEN true ELSE false END as has_video
       FROM videos WHERE uploader_id = $1 AND is_active = true ORDER BY created_at DESC`,
      [req.user.id]
    );
    res.json({ success: true, videos: result.rows });
  } catch (error) {
    console.error('My videos error:', error);
    res.status(500).json({ error: 'Failed to get your videos: ' + error.message });
  }
});

// ============ VIDEO UPLOAD ============
app.post('/api/videos/upload', authenticate, authorize('admin', 'super_admin'), upload.fields([
  { name: 'video', maxCount: 1 },
  { name: 'thumbnail', maxCount: 1 }
]), async (req, res) => {
  try {
    const { title, description } = req.body;
    
    if (!isValidTitle(title)) {
      return res.status(400).json({ error: 'Title must be between 1 and 500 characters' });
    }
    
    if (!req.files || !req.files.video) {
      return res.status(400).json({ error: 'Video file is required' });
    }
    
    const videoFile = req.files.video[0];
    const thumbnailFile = req.files.thumbnail ? req.files.thumbnail[0] : null;
    
    if (videoFile.size > 500 * 1024 * 1024) {
      return res.status(400).json({ error: 'Video file size exceeds 500MB limit' });
    }
    
    // SECURITY: Scan for malicious content (basic)
    const dangerousPatterns = [/<script/i, /javascript:/i, /data:/i, /vbscript:/i];
    const titleCheck = title;
    for (const pattern of dangerousPatterns) {
      if (pattern.test(titleCheck)) {
        return res.status(400).json({ error: 'Invalid title content' });
      }
    }
    
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

// ============ VIDEO ROUTES ============
app.get('/api/videos', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT v.id, v.title, v.description, v.views, v.likes, v.dislikes, v.share_count, v.created_at,
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
    res.setHeader('Cache-Control', 'public, max-age=31536000');
    res.send(video.video_data);
  } catch (error) {
    console.error('Stream error:', error);
    res.status(500).json({ error: 'Failed to stream video: ' + error.message });
  }
});

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
    res.setHeader('Cache-Control', 'public, max-age=31536000');
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

app.put('/api/videos/:id', authenticate, authorize('admin', 'super_admin'), async (req, res) => {
  try {
    const videoId = parseInt(req.params.id);
    const { title, description } = req.body;
    
    if (!isValidTitle(title)) {
      return res.status(400).json({ error: 'Title must be between 1 and 500 characters' });
    }

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

app.delete('/api/videos/:id', authenticate, authorize('admin', 'super_admin'), async (req, res) => {
  try {
    const videoId = parseInt(req.params.id);
    
    if (isNaN(videoId)) {
      return res.status(400).json({ error: 'Invalid video ID' });
    }
    
    const videoResult = await pool.query(
      'SELECT * FROM videos WHERE id = $1',
      [videoId]
    );
    
    if (videoResult.rows.length === 0) {
      return res.status(404).json({ error: 'Video not found' });
    }
    
    const video = videoResult.rows[0];
    
    if (req.user.role !== 'super_admin' && video.uploader_id !== req.user.id) {
      return res.status(403).json({ error: 'You can only delete your own videos' });
    }
    
    await pool.query('DELETE FROM videos WHERE id = $1', [videoId]);
    await pool.query('UPDATE website_stats SET total_videos = total_videos - 1');
    
    await logUserActivity(req.user.id, 'delete_video', { 
      videoId, 
      title: video.title,
      uploader: video.uploader_name 
    }, req);
    
    res.json({ 
      success: true, 
      message: 'Video deleted successfully' 
    });
  } catch (error) {
    console.error('❌ Delete error:', error);
    res.status(500).json({ error: 'Failed to delete video: ' + error.message });
  }
});

// ============ PUBLIC INTERACTIONS ============
app.post('/api/videos/:id/like', async (req, res) => {
  try {
    const videoId = parseInt(req.params.id);
    const { action } = req.body;
    if (!['like', 'dislike'].includes(action)) {
      return res.status(400).json({ error: 'Invalid action' });
    }
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
    
    if (!username || username.length < 1 || username.length > 50) {
      return res.status(400).json({ error: 'Name must be between 1 and 50 characters' });
    }
    
    if (!comment || !isValidComment(comment)) {
      return res.status(400).json({ error: 'Comment must be between 1 and 1000 characters' });
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

// ============ CSRF Token Endpoint ============
app.get('/api/csrf-token', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// ============ SERVE FRONTEND ============
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============ ERROR HANDLING ============
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  res.status(500).json({ error: 'Something went wrong' });
});

// ============ START SERVER ============
app.listen(PORT, async () => {
  console.log(`🚀 Server running on port ${PORT}`);
  await initDatabase();
});
