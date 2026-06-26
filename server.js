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
app.use(express.static('public'));

// Create upload directories
['uploads', 'uploads/videos', 'uploads/thumbnails'].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// Multer config
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = file.fieldname === 'video' ? 'uploads/videos' : 'uploads/thumbnails';
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 500 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.fieldname === 'video' && !file.mimetype.startsWith('video/')) {
      return cb(new Error('Only video files allowed'));
    }
    if (file.fieldname === 'thumbnail' && !file.mimetype.startsWith('image/')) {
      return cb(new Error('Only image files allowed'));
    }
    cb(null, true);
  }
});

// Initialize database
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
        heard_from VARCHAR(100) DEFAULT NULL,
        role VARCHAR(50) DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT true
      );
    `);

    // Videos table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS videos (
        id SERIAL PRIMARY KEY,
        title VARCHAR(500) NOT NULL,
        description TEXT,
        video_url VARCHAR(500) NOT NULL,
        thumbnail_url VARCHAR(500),
        uploader_id INTEGER REFERENCES users(id),
        views INTEGER DEFAULT 0,
        likes INTEGER DEFAULT 0,
        dislikes INTEGER DEFAULT 0,
        share_count INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT true
      );
    `);

    // Comments table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS comments (
        id SERIAL PRIMARY KEY,
        video_id INTEGER REFERENCES videos(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id),
        comment TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // User actions table
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

    // User logs table
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

    // Website stats table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS website_stats (
        id SERIAL PRIMARY KEY,
        total_visits INTEGER DEFAULT 0,
        total_users INTEGER DEFAULT 0,
        total_videos INTEGER DEFAULT 0,
        total_views INTEGER DEFAULT 0,
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

    // Initialize stats
    await pool.query(`
      INSERT INTO website_stats (total_visits, total_users, total_videos) 
      SELECT 0, 0, 0 
      WHERE NOT EXISTS (SELECT 1 FROM website_stats);
    `);

    console.log('✅ Database initialized successfully');
    console.log('👑 Super Admin: OWNER_MPC');
    console.log('🔑 Password: 08800+_+Owner!');
    console.log('🔐 Secret: ADMIN_SECRET_2024');

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

// UPDATE HEARD FROM - FIXED
app.post('/api/auth/heard-from', authenticate, async (req, res) => {
  try {
    const { heardFrom } = req.body;

    if (!heardFrom) {
      return res.status(400).json({ error: 'Please select how you heard about us' });
    }

    // Update the user's heard_from in database
    await pool.query(
      'UPDATE users SET heard_from = $1 WHERE id = $2',
      [heardFrom, req.user.id]
    );

    // Update the user object
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

// CREATE ADMIN
app.post('/api/admin/create-admin', authenticate, authorize('super_admin'), async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const existing = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const hashedSecret = await bcrypt.hash('ADMIN_' + Date.now(), 10);

    const result = await pool.query(
      `INSERT INTO users (username, password, secret_code, role, heard_from) 
       VALUES ($1, $2, $3, 'admin', 'admin_created') 
       RETURNING id, username, role`,
      [username, hashedPassword, hashedSecret]
    );

    await logUserActivity(req.user.id, 'create_admin', { newAdmin: username }, req);

    res.json({
      success: true,
      message: 'Admin created successfully',
      admin: result.rows[0]
    });

  } catch (error) {
    console.error('Create admin error:', error);
    res.status(500).json({ error: 'Failed to create admin: ' + error.message });
  }
});

// GET ADMIN STATS
app.get('/api/admin/stats', authenticate, authorize('admin', 'super_admin'), async (req, res) => {
  try {
    const stats = await pool.query('SELECT * FROM website_stats LIMIT 1');
    const users = await pool.query('SELECT COUNT(*) as total FROM users');
    const videos = await pool.query('SELECT COUNT(*) as total FROM videos');
    const logs = await pool.query(
      `SELECT l.*, u.username 
       FROM user_logs l 
       LEFT JOIN users u ON l.user_id = u.id 
       ORDER BY l.created_at DESC 
       LIMIT 100`
    );

    res.json({
      success: true,
      stats: stats.rows[0] || { total_visits: 0, total_users: 0, total_videos: 0 },
      userCount: parseInt(users.rows[0].total),
      videoCount: parseInt(videos.rows[0].total),
      recentLogs: logs.rows || []
    });

  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({ error: 'Failed to get stats: ' + error.message });
  }
});

// UPLOAD VIDEO
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

    const videoPath = '/uploads/videos/' + videoFile.filename;
    const thumbnailPath = thumbnailFile ? '/uploads/thumbnails/' + thumbnailFile.filename : null;

    const result = await pool.query(
      `INSERT INTO videos (title, description, video_url, thumbnail_url, uploader_id) 
       VALUES ($1, $2, $3, $4, $5) 
       RETURNING id, title, description, video_url, thumbnail_url, created_at`,
      [title, description || '', videoPath, thumbnailPath, req.user.id]
    );

    await pool.query('UPDATE website_stats SET total_videos = total_videos + 1');
    await logUserActivity(req.user.id, 'upload_video', { videoId: result.rows[0].id, title }, req);

    res.json({
      success: true,
      message: 'Video uploaded successfully',
      video: result.rows[0]
    });

  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Upload failed: ' + error.message });
  }
});

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
    res.status(500).json({ error: 'Failed to get videos' });
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
      `SELECT c.id, c.comment, c.created_at, u.username 
       FROM comments c 
       JOIN users u ON c.user_id = u.id 
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
    res.status(500).json({ error: 'Failed to get video' });
  }
});

// LIKE/DISLIKE
app.post('/api/videos/:id/like', authenticate, async (req, res) => {
  try {
    const videoId = parseInt(req.params.id);
    const { action } = req.body;

    if (isNaN(videoId)) {
      return res.status(400).json({ error: 'Invalid video ID' });
    }

    if (!['like', 'dislike'].includes(action)) {
      return res.status(400).json({ error: 'Invalid action' });
    }

    const existing = await pool.query(
      `SELECT * FROM user_actions 
       WHERE user_id = $1 AND video_id = $2 AND action_type = 'like_or_dislike'`,
      [req.user.id, videoId]
    );

    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'You already interacted with this video' });
    }

    const field = action === 'like' ? 'likes' : 'dislikes';
    await pool.query(`UPDATE videos SET ${field} = ${field} + 1 WHERE id = $1`, [videoId]);

    await pool.query(
      `INSERT INTO user_actions (user_id, video_id, action_type, action_data) 
       VALUES ($1, $2, 'like_or_dislike', $3)`,
      [req.user.id, videoId, action]
    );

    await logUserActivity(req.user.id, 'like_video', { videoId, action }, req);

    res.json({
      success: true,
      message: `${action} recorded successfully`
    });

  } catch (error) {
    console.error('Like error:', error);
    res.status(500).json({ error: 'Failed to process: ' + error.message });
  }
});

// ADD COMMENT
app.post('/api/videos/:id/comment', authenticate, async (req, res) => {
  try {
    const videoId = parseInt(req.params.id);
    const { comment } = req.body;

    if (isNaN(videoId)) {
      return res.status(400).json({ error: 'Invalid video ID' });
    }

    if (!comment || comment.trim().length === 0) {
      return res.status(400).json({ error: 'Comment is required' });
    }

    if (comment.length > 1000) {
      return res.status(400).json({ error: 'Comment is too long (max 1000 characters)' });
    }

    const result = await pool.query(
      `INSERT INTO comments (video_id, user_id, comment) 
       VALUES ($1, $2, $3) 
       RETURNING id, comment, created_at`,
      [videoId, req.user.id, comment.trim()]
    );

    await logUserActivity(req.user.id, 'comment_video', { videoId, comment: comment.trim() }, req);

    res.json({
      success: true,
      message: 'Comment added successfully',
      comment: {
        ...result.rows[0],
        username: req.user.username
      }
    });

  } catch (error) {
    console.error('Comment error:', error);
    res.status(500).json({ error: 'Failed to add comment: ' + error.message });
  }
});

// SHARE VIDEO
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

// DELETE VIDEO
app.delete('/api/videos/:id', authenticate, authorize('admin', 'super_admin'), async (req, res) => {
  try {
    const videoId = parseInt(req.params.id);

    if (isNaN(videoId)) {
      return res.status(400).json({ error: 'Invalid video ID' });
    }

    const videoResult = await pool.query('SELECT video_url, thumbnail_url, title FROM videos WHERE id = $1', [videoId]);

    if (videoResult.rows.length === 0) {
      return res.status(404).json({ error: 'Video not found' });
    }

    const video = videoResult.rows[0];

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
    console.log('=' .repeat(50));
    console.log('👑 Super Admin Credentials:');
    console.log('   Username: OWNER_MPC');
    console.log('   Password: 08800+_+Owner!');
    console.log('   Secret Code: ADMIN_SECRET_2024');
    console.log('=' .repeat(50));
  } catch (error) {
    console.error('❌ Failed to initialize database:', error.message);
  }
});
