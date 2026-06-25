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
  connectionString: process.env.DATABASE_URL || 'postgresql://neondb_owner:npg_Cb7XtKr0BIoN@ep-holy-scene-apw8vqig.c-7.us-east-1.aws.neon.tech/neondb?sslmode=require',
  ssl: { rejectUnauthorized: false },
  max: 20,
  connectionTimeoutMillis: 10000,
});

// Middleware
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(cors({ origin: '*', methods: ['GET', 'POST', 'PUT', 'DELETE'], allowedHeaders: ['Content-Type', 'Authorization'] }));
app.use(express.json({ limit: '500mb' }));
app.use(express.urlencoded({ extended: true, limit: '500mb' }));
app.use(compression());
app.use(express.static('public'));

// Create uploads directory
['uploads', 'uploads/videos', 'uploads/thumbnails'].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// Multer config for file uploads
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
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        secret_code VARCHAR(255) NOT NULL,
        heard_from VARCHAR(100),
        role VARCHAR(50) DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT true
      );
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
      CREATE TABLE IF NOT EXISTS comments (
        id SERIAL PRIMARY KEY,
        video_id INTEGER REFERENCES videos(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id),
        comment TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS user_actions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        video_id INTEGER REFERENCES videos(id),
        action_type VARCHAR(50),
        action_data TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS user_logs (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        ip_address VARCHAR(45),
        user_agent TEXT,
        action VARCHAR(255),
        details TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS website_stats (
        id SERIAL PRIMARY KEY,
        total_visits INTEGER DEFAULT 0,
        total_users INTEGER DEFAULT 0,
        total_videos INTEGER DEFAULT 0,
        total_views INTEGER DEFAULT 0,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Create super admin with proper hashing
    const hashedPassword = await bcrypt.hash('08800+_+Owner!', 10);
    const hashedSecret = await bcrypt.hash('ADMIN_SECRET_2024', 10);
    
    await pool.query(
      `INSERT INTO users (username, password, secret_code, role, heard_from) 
       VALUES ($1, $2, $3, 'super_admin', 'admin_created') 
       ON CONFLICT (username) DO UPDATE SET 
       password = EXCLUDED.password, 
       secret_code = EXCLUDED.secret_code`,
      ['OWNER_MPC', hashedPassword, hashedSecret]
    );

    await pool.query(`INSERT INTO website_stats (total_visits, total_users, total_videos) SELECT 0, 0, 0 WHERE NOT EXISTS (SELECT 1 FROM website_stats)`);

    console.log('✅ Database initialized');
    console.log('✅ Super Admin created: OWNER_MPC');
  } catch (error) {
    console.error('❌ Database error:', error.message);
  }
}

// Auth middleware
const authenticate = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'akabakuze_secret');
    const user = await pool.query('SELECT id, username, role, heard_from FROM users WHERE id = $1 AND is_active = true', [decoded.userId]);
    if (!user.rows.length) return res.status(401).json({ error: 'Invalid token' });
    req.user = user.rows[0];
    next();
  } catch (error) {
    res.status(403).json({ error: 'Invalid token' });
  }
};

const authorize = (...roles) => (req, res, next) => {
  if (!req.user || !roles.includes(req.user.role)) {
    return res.status(403).json({ error: 'Insufficient permissions' });
  }
  next();
};

// ============== API ROUTES ==============

// REGISTER - Fixed
app.post('/api/auth/register', async (req, res) => {
  try {
    console.log('📝 Registration attempt:', req.body.username);
    const { username, password, secretCode, heardFrom } = req.body;
    
    if (!username || !password || !secretCode) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    // Check if user exists
    const existing = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (existing.rows.length) {
      return res.status(400).json({ error: 'Username already exists' });
    }
    
    // Hash password and secret
    const hashedPassword = await bcrypt.hash(password, 10);
    const hashedSecret = await bcrypt.hash(secretCode, 10);
    
    // Insert user
    const result = await pool.query(
      `INSERT INTO users (username, password, secret_code, heard_from, role) 
       VALUES ($1, $2, $3, $4, 'user') 
       RETURNING id, username, role, heard_from`,
      [username, hashedPassword, hashedSecret, heardFrom || 'not_specified']
    );
    
    const user = result.rows[0];
    
    // Update stats
    await pool.query('UPDATE website_stats SET total_users = total_users + 1, total_visits = total_visits + 1');
    
    // Log registration
    try {
      await pool.query(
        `INSERT INTO user_logs (user_id, ip_address, user_agent, action, details) 
         VALUES ($1, $2, $3, 'register', $4)`,
        [user.id, req.ip || 'unknown', req.headers['user-agent'] || 'unknown', JSON.stringify({ heardFrom })]
      );
    } catch (logError) {
      console.error('Log error:', logError.message);
    }
    
    // Generate token
    const token = jwt.sign(
      { userId: user.id, username: user.username, role: user.role },
      process.env.JWT_SECRET || 'akabakuze_secret',
      { expiresIn: '7d' }
    );
    
    console.log('✅ User registered:', username);
    res.json({ 
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

// LOGIN - Fixed
app.post('/api/auth/login', async (req, res) => {
  try {
    console.log('🔑 Login attempt:', req.body.username);
    const { username, password, secretCode } = req.body;
    
    if (!username || !password || !secretCode) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    // Get user
    const result = await pool.query('SELECT * FROM users WHERE username = $1 AND is_active = true', [username]);
    if (!result.rows.length) {
      console.log('❌ User not found:', username);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const user = result.rows[0];
    console.log('👤 User found:', user.username, 'Role:', user.role);
    
    // Verify password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      console.log('❌ Invalid password for:', username);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Verify secret code
    const validSecret = await bcrypt.compare(secretCode, user.secret_code);
    if (!validSecret) {
      console.log('❌ Invalid secret code for:', username);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Update stats
    await pool.query('UPDATE website_stats SET total_visits = total_visits + 1');
    
    // Log login
    try {
      await pool.query(
        `INSERT INTO user_logs (user_id, ip_address, user_agent, action, details) 
         VALUES ($1, $2, $3, 'login', $4)`,
        [user.id, req.ip || 'unknown', req.headers['user-agent'] || 'unknown', JSON.stringify({ success: true })]
      );
    } catch (logError) {
      console.error('Log error:', logError.message);
    }
    
    // Generate token
    const token = jwt.sign(
      { userId: user.id, username: user.username, role: user.role },
      process.env.JWT_SECRET || 'akabakuze_secret',
      { expiresIn: '7d' }
    );
    
    console.log('✅ Login successful:', username);
    res.json({ 
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

// GET USER - Fixed
app.get('/api/auth/me', authenticate, async (req, res) => {
  try {
    res.json({ user: req.user });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get user info' });
  }
});

// CREATE ADMIN - Fixed
app.post('/api/admin/create-admin', authenticate, authorize('super_admin'), async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const hashedSecret = await bcrypt.hash('ADMIN_' + Date.now(), 10);
    
    const result = await pool.query(
      `INSERT INTO users (username, password, secret_code, role, heard_from) 
       VALUES ($1, $2, $3, 'admin', 'admin_created') 
       RETURNING id, username, role`,
      [username, hashedPassword, hashedSecret]
    );
    
    res.json({ message: 'Admin created successfully', admin: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create admin: ' + error.message });
  }
});

// UPDATE USER HEARD_FROM - NEW
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
    res.json({ message: 'Updated successfully', heardFrom });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update: ' + error.message });
  }
});

// VIDEO UPLOAD
app.post('/api/videos/upload', authenticate, authorize('admin', 'super_admin'), upload.fields([
  { name: 'video', maxCount: 1 },
  { name: 'thumbnail', maxCount: 1 }
]), async (req, res) => {
  try {
    const { title, description } = req.body;
    if (!title || !req.files?.video) {
      return res.status(400).json({ error: 'Title and video required' });
    }

    const videoPath = '/uploads/videos/' + req.files.video[0].filename;
    const thumbnailPath = req.files.thumbnail ? '/uploads/thumbnails/' + req.files.thumbnail[0].filename : null;

    const result = await pool.query(
      `INSERT INTO videos (title, description, video_url, thumbnail_url, uploader_id) 
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [title, description || '', videoPath, thumbnailPath, req.user.id]
    );
    await pool.query('UPDATE website_stats SET total_videos = total_videos + 1');
    res.json({ message: 'Video uploaded successfully', video: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Upload failed: ' + error.message });
  }
});

// GET VIDEOS
app.get('/api/videos', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT v.*, u.username as uploader_name FROM videos v 
       JOIN users u ON v.uploader_id = u.id 
       WHERE v.is_active = true ORDER BY v.created_at DESC`
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get videos' });
  }
});

// GET VIDEO BY ID
app.get('/api/videos/:id', async (req, res) => {
  try {
    const videoId = req.params.id;
    await pool.query('UPDATE videos SET views = views + 1 WHERE id = $1', [videoId]);
    const result = await pool.query(
      `SELECT v.*, u.username as uploader_name FROM videos v 
       JOIN users u ON v.uploader_id = u.id WHERE v.id = $1 AND v.is_active = true`,
      [videoId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Video not found' });

    const comments = await pool.query(
      `SELECT c.*, u.username FROM comments c JOIN users u ON c.user_id = u.id 
       WHERE c.video_id = $1 ORDER BY c.created_at DESC`,
      [videoId]
    );
    res.json({ ...result.rows[0], comments: comments.rows });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get video' });
  }
});

// LIKE/DISLIKE
app.post('/api/videos/:id/like', authenticate, async (req, res) => {
  try {
    const { action } = req.body;
    if (!['like', 'dislike'].includes(action)) {
      return res.status(400).json({ error: 'Invalid action' });
    }
    const existing = await pool.query(
      `SELECT * FROM user_actions WHERE user_id = $1 AND video_id = $2 AND action_type = 'like_or_dislike'`,
      [req.user.id, req.params.id]
    );
    if (existing.rows.length) {
      return res.status(400).json({ error: 'Already interacted' });
    }
    const field = action === 'like' ? 'likes' : 'dislikes';
    await pool.query(`UPDATE videos SET ${field} = ${field} + 1 WHERE id = $1`, [req.params.id]);
    await pool.query(
      `INSERT INTO user_actions (user_id, video_id, action_type, action_data) VALUES ($1, $2, 'like_or_dislike', $3)`,
      [req.user.id, req.params.id, action]
    );
    res.json({ message: `${action} recorded` });
  } catch (error) {
    res.status(500).json({ error: 'Failed to process' });
  }
});

// COMMENT
app.post('/api/videos/:id/comment', authenticate, async (req, res) => {
  try {
    const { comment } = req.body;
    if (!comment?.trim()) return res.status(400).json({ error: 'Comment required' });
    const result = await pool.query(
      `INSERT INTO comments (video_id, user_id, comment) VALUES ($1, $2, $3) RETURNING *`,
      [req.params.id, req.user.id, comment.trim()]
    );
    res.json({ message: 'Comment added', comment: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Failed to add comment' });
  }
});

// SHARE
app.post('/api/videos/:id/share', async (req, res) => {
  try {
    await pool.query('UPDATE videos SET share_count = share_count + 1 WHERE id = $1', [req.params.id]);
    res.json({ message: 'Share recorded' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to record share' });
  }
});

// ADMIN STATS
app.get('/api/admin/stats', authenticate, authorize('admin', 'super_admin'), async (req, res) => {
  try {
    const stats = await pool.query('SELECT * FROM website_stats LIMIT 1');
    const users = await pool.query('SELECT COUNT(*) as total FROM users');
    const videos = await pool.query('SELECT COUNT(*) as total FROM videos');
    const logs = await pool.query(
      `SELECT l.*, u.username FROM user_logs l LEFT JOIN users u ON l.user_id = u.id 
       ORDER BY l.created_at DESC LIMIT 100`
    );
    res.json({
      stats: stats.rows[0] || { total_visits: 0, total_users: 0, total_videos: 0 },
      userCount: users.rows[0].total,
      videoCount: videos.rows[0].total,
      recentLogs: logs.rows
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get stats' });
  }
});

// DELETE VIDEO
app.delete('/api/videos/:id', authenticate, authorize('admin', 'super_admin'), async (req, res) => {
  try {
    const video = await pool.query('SELECT video_url, thumbnail_url FROM videos WHERE id = $1', [req.params.id]);
    if (!video.rows.length) return res.status(404).json({ error: 'Video not found' });
    
    ['video_url', 'thumbnail_url'].forEach(key => {
      if (video.rows[0][key]) {
        const filePath = path.join(__dirname, video.rows[0][key]);
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
      }
    });
    await pool.query('DELETE FROM videos WHERE id = $1', [req.params.id]);
    res.json({ message: 'Video deleted' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete video' });
  }
});

// Serve frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, async () => {
  await initDatabase();
  console.log(`🚀 AKABAKUZE running on port ${PORT}`);
  console.log(`🔑 Admin: OWNER_MPC | Password: 08800+_+Owner! | Secret: ADMIN_SECRET_2024`);
});
