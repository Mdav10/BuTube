const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;

// Database connection
const pool = new Pool({
  connectionString: 'postgresql://neondb_owner:npg_Cb7XtKr0BIoN@ep-holy-scene-apw8vqig.c-7.us-east-1.aws.neon.tech/neondb?sslmode=require',
  ssl: { rejectUnauthorized: false },
  max: 20,
  connectionTimeoutMillis: 30000,
});

// Test connection
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('❌ Database connection failed:', err.message);
  } else {
    console.log('✅ Database connected successfully');
  }
});

// Middleware
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(cors({ origin: '*', methods: ['GET', 'POST', 'PUT', 'DELETE'], allowedHeaders: ['Content-Type', 'Authorization'] }));
app.use(express.json({ limit: '500mb' }));
app.use(express.urlencoded({ extended: true, limit: '500mb' }));
app.use(compression());
app.use('/uploads', express.static('uploads'));
app.use(express.static('public'));

// Create upload directories
['uploads', 'uploads/videos', 'uploads/thumbnails'].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// Multer config for video uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    let dir = 'uploads/';
    if (file.fieldname === 'video') {
      dir = 'uploads/videos/';
    } else if (file.fieldname === 'thumbnail') {
      dir = 'uploads/thumbnails/';
    }
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
    cb(null, uniqueName);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 500 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.fieldname === 'video') {
      if (!file.mimetype.startsWith('video/')) {
        return cb(new Error('Only video files are allowed'));
      }
    } else if (file.fieldname === 'thumbnail') {
      if (!file.mimetype.startsWith('image/')) {
        return cb(new Error('Only image files are allowed for thumbnails'));
      }
    }
    cb(null, true);
  }
});

// Initialize database
async function initDatabase() {
  try {
    console.log('🔄 Initializing database...');

    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        secret_code VARCHAR(255) NOT NULL,
        heard_from VARCHAR(100) DEFAULT NULL,
        role VARCHAR(50) DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT true
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS videos (
        id SERIAL PRIMARY KEY,
        title VARCHAR(500) NOT NULL,
        description TEXT,
        video_url VARCHAR(500) NOT NULL,
        thumbnail_url VARCHAR(500),
        uploader_id INTEGER REFERENCES users(id),
        uploader_name VARCHAR(255),
        views INTEGER DEFAULT 0,
        likes INTEGER DEFAULT 0,
        dislikes INTEGER DEFAULT 0,
        share_count INTEGER DEFAULT 0,
        file_size INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT true
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS comments (
        id SERIAL PRIMARY KEY,
        video_id INTEGER REFERENCES videos(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id),
        username VARCHAR(255),
        comment TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_actions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        video_id INTEGER REFERENCES videos(id),
        action_type VARCHAR(50),
        action_data TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_logs (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        ip_address VARCHAR(45),
        user_agent TEXT,
        action VARCHAR(255),
        details TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
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
      );
    `);

    // Create Super Admin
    const hashedPassword = await bcrypt.hash('08800+_+Owner!', 10);
    const hashedSecret = await bcrypt.hash('ADMIN_SECRET_2024', 10);

    await pool.query(
      `INSERT INTO users (username, password, secret_code, role, heard_from) 
       VALUES ($1, $2, $3, 'super_admin', 'system') 
       ON CONFLICT (username) DO UPDATE SET 
       password = EXCLUDED.password, 
       secret_code = EXCLUDED.secret_code`,
      ['OWNER_MPC', hashedPassword, hashedSecret]
    );
    console.log('✅ Super Admin ready');

    // Initialize stats
    await pool.query(`
      INSERT INTO website_stats (total_visits, total_users, total_videos, total_views, total_likes, total_comments) 
      SELECT 0, 0, 0, 0, 0, 0 
      WHERE NOT EXISTS (SELECT 1 FROM website_stats);
    `);

    console.log('✅ Database initialized successfully!');
    console.log('👑 Super Admin: OWNER_MPC');
    console.log('🔑 Password: 08800+_+Owner!');
    console.log('🔐 Secret Code: ADMIN_SECRET_2024');

  } catch (error) {
    console.error('❌ Database error:', error.message);
    throw error;
  }
}

// Auth middleware
const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'akabakuze_secret_2024');

    const result = await pool.query(
      'SELECT id, username, role, heard_from FROM users WHERE id = $1 AND is_active = true',
      [decoded.userId]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'User not found' });
    }

    req.user = result.rows[0];
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid or expired token' });
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

// ============ API ROUTES ============

// REGISTER
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password, secretCode, heardFrom } = req.body;

    if (!username || !password || !secretCode) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (username.length < 3) {
      return res.status(400).json({ error: 'Username must be at least 3 characters' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const existing = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const hashedSecret = await bcrypt.hash(secretCode, 10);

    const result = await pool.query(
      `INSERT INTO users (username, password, secret_code, heard_from, role) 
       VALUES ($1, $2, $3, $4, 'user') 
       RETURNING id, username, role, heard_from`,
      [username, hashedPassword, hashedSecret, heardFrom || null]
    );

    const user = result.rows[0];
    await pool.query('UPDATE website_stats SET total_users = total_users + 1, total_visits = total_visits + 1');

    await logUserActivity(user.id, 'register', { heardFrom: user.heard_from }, req);

    const token = jwt.sign(
      { userId: user.id, username: user.username, role: user.role },
      process.env.JWT_SECRET || 'akabakuze_secret_2024',
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        heardFrom: user.heard_from
      }
    });

  } catch (error) {
    console.error('❌ Registration error:', error);
    res.status(500).json({ error: 'Registration failed: ' + error.message });
  }
});

// LOGIN
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password, secretCode } = req.body;

    if (!username || !password || !secretCode) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const result = await pool.query('SELECT * FROM users WHERE username = $1 AND is_active = true', [username]);

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const validSecret = await bcrypt.compare(secretCode, user.secret_code);
    if (!validSecret) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    await pool.query('UPDATE website_stats SET total_visits = total_visits + 1');
    await logUserActivity(user.id, 'login', { success: true }, req);

    const token = jwt.sign(
      { userId: user.id, username: user.username, role: user.role },
      process.env.JWT_SECRET || 'akabakuze_secret_2024',
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        heardFrom: user.heard_from
      }
    });

  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({ error: 'Login failed: ' + error.message });
  }
});

// GET CURRENT USER
app.get('/api/auth/me', authenticate, async (req, res) => {
  try {
    res.json({
      success: true,
      user: req.user
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get user info' });
  }
});

// UPDATE HEARD FROM
app.post('/api/auth/heard-from', authenticate, async (req, res) => {
  try {
    const { heardFrom } = req.body;

    if (!heardFrom) {
      return res.status(400).json({ error: 'Please select how you heard about us' });
    }

    await pool.query(
      'UPDATE users SET heard_from = $1 WHERE id = $2',
      [heardFrom, req.user.id]
    );

    req.user.heard_from = heardFrom;
    await logUserActivity(req.user.id, 'update_heard_from', { heardFrom }, req);

    res.json({
      success: true,
      message: 'Thank you for sharing how you found us!',
      heardFrom: heardFrom,
      user: req.user
    });

  } catch (error) {
    console.error('❌ Heard from error:', error);
    res.status(500).json({ error: 'Failed to update: ' + error.message });
  }
});

// ===== SUPER ADMIN ONLY =====

// CREATE ADMIN
app.post('/api/admin/create-admin', authenticate, authorize('super_admin'), async (req, res) => {
  try {
    const { username, password, secretCode } = req.body;

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

    const existing = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const hashedSecret = await bcrypt.hash(secretCode, 10);

    const result = await pool.query(
      `INSERT INTO users (username, password, secret_code, role, heard_from) 
       VALUES ($1, $2, $3, 'admin', 'admin_created') 
       RETURNING id, username, role`,
      [username, hashedPassword, hashedSecret]
    );

    await logUserActivity(req.user.id, 'create_admin', { 
      newAdmin: username, 
      secretCode: secretCode 
    }, req);

    res.json({
      success: true,
      message: 'Admin created successfully',
      admin: result.rows[0],
      secretCode: secretCode
    });

  } catch (error) {
    console.error('Create admin error:', error);
    res.status(500).json({ error: 'Failed to create admin: ' + error.message });
  }
});

// GET SUPER ADMIN STATS
app.get('/api/admin/super-stats', authenticate, authorize('super_admin'), async (req, res) => {
  try {
    const stats = await pool.query('SELECT * FROM website_stats LIMIT 1');
    const users = await pool.query('SELECT COUNT(*) as total FROM users');
    const admins = await pool.query("SELECT COUNT(*) as total FROM users WHERE role IN ('admin', 'super_admin')");
    const videos = await pool.query('SELECT COUNT(*) as total FROM videos');
    const comments = await pool.query('SELECT COUNT(*) as total FROM comments');
    
    const allAdmins = await pool.query(`
      SELECT id, username, role, created_at 
      FROM users 
      WHERE role IN ('admin', 'super_admin')
      ORDER BY created_at DESC
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
      SELECT id, username, role, heard_from, created_at 
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
      topVideos: topVideos.rows,
      recentUsers: recentUsers.rows,
      recentLogs: logs.rows || []
    });

  } catch (error) {
    console.error('Super stats error:', error);
    res.status(500).json({ error: 'Failed to get stats: ' + error.message });
  }
});

// ===== ADMIN VIDEOS =====

// GET ADMIN VIDEOS
app.get('/api/admin/my-videos', authenticate, authorize('admin', 'super_admin'), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT v.*, u.username as uploader_name 
       FROM videos v 
       JOIN users u ON v.uploader_id = u.id 
       WHERE v.uploader_id = $1 AND v.is_active = true 
       ORDER BY v.created_at DESC`,
      [req.user.id]
    );

    res.json({
      success: true,
      videos: result.rows,
      total: result.rows.length
    });
  } catch (error) {
    console.error('Get my videos error:', error);
    res.status(500).json({ error: 'Failed to get your videos: ' + error.message });
  }
});

// GET ADMIN STATS
app.get('/api/admin/my-stats', authenticate, authorize('admin', 'super_admin'), async (req, res) => {
  try {
    const videos = await pool.query(
      'SELECT COUNT(*) as total, SUM(views) as total_views, SUM(likes) as total_likes FROM videos WHERE uploader_id = $1 AND is_active = true',
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

// ===== VIDEO UPLOAD =====
app.post('/api/videos/upload', authenticate, authorize('admin', 'super_admin'), upload.fields([
  { name: 'video', maxCount: 1 },
  { name: 'thumbnail', maxCount: 1 }
]), async (req, res) => {
  try {
    const { title, description } = req.body;

    if (!title || !req.files || !req.files.video) {
      return res.status(400).json({ error: 'Title and video file are required' });
    }

    const videoFile = req.files.video[0];
    const thumbnailFile = req.files.thumbnail ? req.files.thumbnail[0] : null;

    if (videoFile.size > 500 * 1024 * 1024) {
      return res.status(400).json({ error: 'Video file size exceeds 500MB limit' });
    }

    const videoPath = '/uploads/videos/' + videoFile.filename;
    const thumbnailPath = thumbnailFile ? '/uploads/thumbnails/' + thumbnailFile.filename : null;

    const result = await pool.query(
      `INSERT INTO videos (title, description, video_url, thumbnail_url, uploader_id, uploader_name, file_size) 
       VALUES ($1, $2, $3, $4, $5, $6, $7) 
       RETURNING id, title, description, video_url, thumbnail_url, file_size, created_at`,
      [title, description || '', videoPath, thumbnailPath, req.user.id, req.user.username, videoFile.size]
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

// ===== PUBLIC VIDEO ROUTES (No authentication required) =====

// GET ALL VIDEOS
app.get('/api/videos', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT v.id, v.title, v.description, v.video_url, v.thumbnail_url, 
              v.views, v.likes, v.dislikes, v.share_count, v.created_at,
              u.username as uploader_name
       FROM videos v 
       JOIN users u ON v.uploader_id = u.id 
       WHERE v.is_active = true 
       ORDER BY v.created_at DESC`
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Get videos error:', error);
    res.status(500).json({ error: 'Failed to get videos: ' + error.message });
  }
});

// GET VIDEO BY ID
app.get('/api/videos/:id', async (req, res) => {
  try {
    const videoId = parseInt(req.params.id);

    if (isNaN(videoId)) {
      return res.status(400).json({ error: 'Invalid video ID' });
    }

    await pool.query('UPDATE videos SET views = views + 1 WHERE id = $1', [videoId]);

    const videoResult = await pool.query(
      `SELECT v.*, u.username as uploader_name 
       FROM videos v 
       JOIN users u ON v.uploader_id = u.id 
       WHERE v.id = $1 AND v.is_active = true`,
      [videoId]
    );

    if (videoResult.rows.length === 0) {
      return res.status(404).json({ error: 'Video not found' });
    }

    const commentsResult = await pool.query(
      `SELECT c.id, c.comment, c.created_at, c.username 
       FROM comments c 
       WHERE c.video_id = $1 
       ORDER BY c.created_at DESC`,
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

// ===== PUBLIC INTERACTIONS (No login required) =====

// LIKE VIDEO - PUBLIC
app.post('/api/videos/:id/like', async (req, res) => {
  try {
    const videoId = parseInt(req.params.id);
    const { action } = req.body;

    if (isNaN(videoId)) {
      return res.status(400).json({ error: 'Invalid video ID' });
    }

    if (!['like', 'dislike'].includes(action)) {
      return res.status(400).json({ error: 'Invalid action' });
    }

    const field = action === 'like' ? 'likes' : 'dislikes';
    await pool.query(`UPDATE videos SET ${field} = ${field} + 1 WHERE id = $1`, [videoId]);
    
    if (action === 'like') {
      await pool.query('UPDATE website_stats SET total_likes = total_likes + 1');
    }

    res.json({
      success: true,
      message: `${action} recorded successfully`
    });

  } catch (error) {
    console.error('Like error:', error);
    res.status(500).json({ error: 'Failed to process: ' + error.message });
  }
});

// ADD COMMENT - PUBLIC
app.post('/api/videos/:id/comment', async (req, res) => {
  try {
    const videoId = parseInt(req.params.id);
    const { username, comment } = req.body;

    if (isNaN(videoId)) {
      return res.status(400).json({ error: 'Invalid video ID' });
    }

    if (!username || username.trim().length === 0) {
      return res.status(400).json({ error: 'Please enter your name' });
    }

    if (!comment || comment.trim().length === 0) {
      return res.status(400).json({ error: 'Comment is required' });
    }

    if (username.length > 50) {
      return res.status(400).json({ error: 'Name is too long (max 50 characters)' });
    }

    if (comment.length > 1000) {
      return res.status(400).json({ error: 'Comment is too long (max 1000 characters)' });
    }

    // Clean username and comment
    const cleanUsername = username.trim().substring(0, 50);
    const cleanComment = comment.trim();

    const result = await pool.query(
      `INSERT INTO comments (video_id, username, comment) 
       VALUES ($1, $2, $3) 
       RETURNING id, comment, username, created_at`,
      [videoId, cleanUsername, cleanComment]
    );

    await pool.query('UPDATE website_stats SET total_comments = total_comments + 1');

    res.json({
      success: true,
      message: 'Comment added successfully',
      comment: result.rows[0]
    });

  } catch (error) {
    console.error('Comment error:', error);
    res.status(500).json({ error: 'Failed to add comment: ' + error.message });
  }
});

// SHARE VIDEO - PUBLIC
app.post('/api/videos/:id/share', async (req, res) => {
  try {
    const videoId = parseInt(req.params.id);

    if (isNaN(videoId)) {
      return res.status(400).json({ error: 'Invalid video ID' });
    }

    await pool.query('UPDATE videos SET share_count = share_count + 1 WHERE id = $1', [videoId]);

    res.json({
      success: true,
      message: 'Share recorded successfully'
    });

  } catch (error) {
    console.error('Share error:', error);
    res.status(500).json({ error: 'Failed to record share' });
  }
});

// DELETE VIDEO (Admin only)
app.delete('/api/videos/:id', authenticate, authorize('admin', 'super_admin'), async (req, res) => {
  try {
    const videoId = parseInt(req.params.id);

    if (isNaN(videoId)) {
      return res.status(400).json({ error: 'Invalid video ID' });
    }

    const videoResult = await pool.query(
      'SELECT video_url, thumbnail_url, title, uploader_id FROM videos WHERE id = $1',
      [videoId]
    );

    if (videoResult.rows.length === 0) {
      return res.status(404).json({ error: 'Video not found' });
    }

    const video = videoResult.rows[0];

    if (video.uploader_id !== req.user.id && req.user.role !== 'super_admin') {
      return res.status(403).json({ error: 'You can only delete your own videos' });
    }

    try {
      if (video.video_url) {
        const videoPath = path.join(__dirname, video.video_url);
        if (fs.existsSync(videoPath)) fs.unlinkSync(videoPath);
      }
      if (video.thumbnail_url) {
        const thumbPath = path.join(__dirname, video.thumbnail_url);
        if (fs.existsSync(thumbPath)) fs.unlinkSync(thumbPath);
      }
    } catch (fileError) {
      console.error('File deletion error:', fileError);
    }

    await pool.query('DELETE FROM videos WHERE id = $1', [videoId]);
    await logUserActivity(req.user.id, 'delete_video', { videoId, title: video.title }, req);

    res.json({
      success: true,
      message: 'Video deleted successfully'
    });

  } catch (error) {
    console.error('Delete error:', error);
    res.status(500).json({ error: 'Failed to delete video: ' + error.message });
  }
});

// Health check
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', database: 'connected' });
  } catch (error) {
    res.status(500).json({ status: 'error', database: 'disconnected', error: error.message });
  }
});

// Serve frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Something went wrong: ' + err.message });
});

// Start server
app.listen(PORT, async () => {
  console.log(`\n🚀 AKABAKUZE Server running on port ${PORT}`);
  console.log(`🌐 URL: http://localhost:${PORT}\n`);

  try {
    await initDatabase();
    console.log('\n✅ Server is ready!');
    console.log('=' .repeat(60));
    console.log('👑 SUPER ADMIN Credentials:');
    console.log('   Username: OWNER_MPC');
    console.log('   Password: 08800+_+Owner!');
    console.log('   Secret Code: ADMIN_SECRET_2024');
    console.log('=' .repeat(60));
  } catch (error) {
    console.error('❌ Failed to initialize database:', error.message);
  }
});
