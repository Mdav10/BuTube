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
const PORT = process.env.PORT || 3000;

// Database connection
const pool = new Pool({
  user: 'neondb_owner',
  password: 'npg_Cb7XtKr0BIoN',
  host: 'ep-holy-scene-apw8vqig.c-7.us-east-1.aws.neon.tech',
  port: 5432,
  database: 'neondb',
  ssl: { rejectUnauthorized: false },
  connectionTimeoutMillis: 10000,
});

pool.connect((err, client, release) => {
  if (err) {
    console.error('❌ Database error:', err.message);
  } else {
    console.log('✅ Database connected');
    release();
  }
});

// Middleware
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(cors());
app.use(express.json({ limit: '500mb' }));
app.use(express.urlencoded({ extended: true, limit: '500mb' }));
app.use(compression());
app.use('/uploads', express.static('uploads'));
app.use(express.static('public'));

// Create directories
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
    const unique = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
    cb(null, unique);
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

// Init database
async function initDatabase() {
  try {
    // Drop and recreate tables to ensure correct schema
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
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
      CREATE TABLE IF NOT EXISTS website_stats (
        id SERIAL PRIMARY KEY,
        total_visits INTEGER DEFAULT 0,
        total_users INTEGER DEFAULT 0,
        total_videos INTEGER DEFAULT 0
      )
    `);

    // Create super admin
    const hashedPassword = await bcrypt.hash('08800+_+Owner!', 10);
    const hashedSecret = await bcrypt.hash('ADMIN_SECRET_2024', 10);
    
    await pool.query(
      `INSERT INTO users (username, password, secret_code, role) 
       VALUES ($1, $2, $3, 'super_admin') 
       ON CONFLICT (username) DO NOTHING`,
      ['OWNER_MPC', hashedPassword, hashedSecret]
    );

    await pool.query(
      `INSERT INTO website_stats (total_visits, total_users, total_videos) 
       SELECT 0, 0, 0 WHERE NOT EXISTS (SELECT 1 FROM website_stats)`
    );

    console.log('✅ Database ready');
    console.log('👑 Super Admin: OWNER_MPC');
    console.log('🔑 Password: 08800+_+Owner!');
    console.log('🔐 Secret: ADMIN_SECRET_2024');
  } catch (error) {
    console.error('❌ Database error:', error.message);
  }
}

// Auth middleware
const auth = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret123');
    const user = await pool.query('SELECT id, username, role FROM users WHERE id = $1', [decoded.userId]);
    if (!user.rows.length) return res.status(401).json({ error: 'Invalid token' });
    req.user = user.rows[0];
    next();
  } catch (error) {
    res.status(403).json({ error: 'Invalid token' });
  }
};

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
      `INSERT INTO users (username, password, secret_code, heard_from, role) 
       VALUES ($1, $2, $3, $4, 'user') RETURNING id, username, role`,
      [username, hashedPassword, hashedSecret, heardFrom]
    );
    
    await pool.query('UPDATE website_stats SET total_users = total_users + 1');
    
    const token = jwt.sign(
      { userId: result.rows[0].id, username: result.rows[0].username, role: result.rows[0].role },
      process.env.JWT_SECRET || 'secret123',
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
    
    const token = jwt.sign(
      { userId: user.id, username: user.username, role: user.role },
      process.env.JWT_SECRET || 'secret123',
      { expiresIn: '7d' }
    );
    
    res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/auth/me', auth, async (req, res) => {
  res.json({ user: req.user });
});

app.post('/api/auth/heard-from', auth, async (req, res) => {
  try {
    const { heardFrom } = req.body;
    await pool.query('UPDATE users SET heard_from = $1 WHERE id = $2', [heardFrom, req.user.id]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update' });
  }
});

// ============ ADMIN ROUTES ============
app.post('/api/admin/create', auth, async (req, res) => {
  try {
    if (req.user.role !== 'super_admin') {
      return res.status(403).json({ error: 'Only super admin can create admins' });
    }
    
    const { username, password, secretCode } = req.body;
    if (!username || !password || !secretCode) {
      return res.status(400).json({ error: 'All fields required' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const hashedSecret = await bcrypt.hash(secretCode, 10);
    
    const result = await pool.query(
      `INSERT INTO users (username, password, secret_code, role) 
       VALUES ($1, $2, $3, 'admin') RETURNING id, username, role`,
      [username, hashedPassword, hashedSecret]
    );
    
    res.json({ success: true, admin: result.rows[0], secretCode });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create admin' });
  }
});

app.get('/api/admin/admins', auth, async (req, res) => {
  try {
    if (req.user.role !== 'super_admin') {
      return res.status(403).json({ error: 'Access denied' });
    }
    const result = await pool.query("SELECT id, username, role FROM users WHERE role IN ('admin', 'super_admin')");
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get admins' });
  }
});

app.get('/api/admin/stats', auth, async (req, res) => {
  try {
    if (req.user.role !== 'super_admin' && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    const stats = await pool.query('SELECT * FROM website_stats LIMIT 1');
    const users = await pool.query('SELECT COUNT(*) as total FROM users');
    const videos = await pool.query('SELECT COUNT(*) as total FROM videos');
    
    res.json({
      stats: stats.rows[0] || { total_visits: 0, total_users: 0, total_videos: 0 },
      userCount: parseInt(users.rows[0].total),
      videoCount: parseInt(videos.rows[0].total)
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get stats' });
  }
});

// ============ VIDEO ROUTES ============
app.post('/api/videos/upload', auth, upload.fields([
  { name: 'video', maxCount: 1 },
  { name: 'thumbnail', maxCount: 1 }
]), async (req, res) => {
  try {
    if (req.user.role !== 'admin' && req.user.role !== 'super_admin') {
      return res.status(403).json({ error: 'Only admins can upload' });
    }

    const { title, description } = req.body;
    if (!title || !req.files?.video) {
      return res.status(400).json({ error: 'Title and video required' });
    }

    const videoPath = '/uploads/videos/' + req.files.video[0].filename;
    const thumbnailPath = req.files.thumbnail ? '/uploads/thumbnails/' + req.files.thumbnail[0].filename : null;

    const result = await pool.query(
      `INSERT INTO videos (title, description, video_url, thumbnail_url, uploader_id, uploader_name) 
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [title, description || '', videoPath, thumbnailPath, req.user.id, req.user.username]
    );

    await pool.query('UPDATE website_stats SET total_videos = total_videos + 1');
    res.json({ success: true, video: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Upload failed: ' + error.message });
  }
});

app.get('/api/videos', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT v.*, u.username as uploader_name 
      FROM videos v 
      JOIN users u ON v.uploader_id = u.id 
      ORDER BY v.created_at DESC
    `);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get videos' });
  }
});

app.get('/api/videos/:id', async (req, res) => {
  try {
    const videoId = parseInt(req.params.id);
    await pool.query('UPDATE videos SET views = views + 1 WHERE id = $1', [videoId]);
    
    const video = await pool.query(`
      SELECT v.*, u.username as uploader_name 
      FROM videos v 
      JOIN users u ON v.uploader_id = u.id 
      WHERE v.id = $1
    `, [videoId]);
    
    if (!video.rows.length) return res.status(404).json({ error: 'Video not found' });
    
    const comments = await pool.query(
      'SELECT * FROM comments WHERE video_id = $1 ORDER BY created_at DESC',
      [videoId]
    );
    
    res.json({ ...video.rows[0], comments: comments.rows });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get video' });
  }
});

app.put('/api/videos/:id', auth, async (req, res) => {
  try {
    if (req.user.role !== 'admin' && req.user.role !== 'super_admin') {
      return res.status(403).json({ error: 'Access denied' });
    }

    const videoId = parseInt(req.params.id);
    const { title, description } = req.body;
    
    if (!title) return res.status(400).json({ error: 'Title required' });

    const check = await pool.query('SELECT uploader_id FROM videos WHERE id = $1', [videoId]);
    if (!check.rows.length) return res.status(404).json({ error: 'Video not found' });
    
    if (check.rows[0].uploader_id !== req.user.id && req.user.role !== 'super_admin') {
      return res.status(403).json({ error: 'You can only edit your own videos' });
    }

    const result = await pool.query(
      'UPDATE videos SET title = $1, description = $2 WHERE id = $3 RETURNING *',
      [title, description || '', videoId]
    );
    
    res.json({ success: true, video: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update video' });
  }
});

app.delete('/api/videos/:id', auth, async (req, res) => {
  try {
    if (req.user.role !== 'admin' && req.user.role !== 'super_admin') {
      return res.status(403).json({ error: 'Access denied' });
    }

    const videoId = parseInt(req.params.id);
    
    const check = await pool.query('SELECT uploader_id, video_url, thumbnail_url FROM videos WHERE id = $1', [videoId]);
    if (!check.rows.length) return res.status(404).json({ error: 'Video not found' });
    
    if (check.rows[0].uploader_id !== req.user.id && req.user.role !== 'super_admin') {
      return res.status(403).json({ error: 'You can only delete your own videos' });
    }

    const video = check.rows[0];
    if (video.video_url) {
      const filePath = path.join(__dirname, video.video_url);
      if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    }
    if (video.thumbnail_url) {
      const filePath = path.join(__dirname, video.thumbnail_url);
      if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    }

    await pool.query('DELETE FROM videos WHERE id = $1', [videoId]);
    res.json({ success: true });
  } catch (error) {
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
      'INSERT INTO comments (video_id, username, comment) VALUES ($1, $2, $3) RETURNING *',
      [videoId, username.trim(), comment.trim()]
    );
    
    res.json({ success: true, comment: result.rows[0] });
  } catch (error) {
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

// ============ MY VIDEOS ============
app.get('/api/my-videos', auth, async (req, res) => {
  try {
    if (req.user.role !== 'admin' && req.user.role !== 'super_admin') {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    const result = await pool.query(
      'SELECT * FROM videos WHERE uploader_id = $1 ORDER BY created_at DESC',
      [req.user.id]
    );
    
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get your videos' });
  }
});

app.get('/api/my-stats', auth, async (req, res) => {
  try {
    if (req.user.role !== 'admin' && req.user.role !== 'super_admin') {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    const result = await pool.query(
      'SELECT COUNT(*) as total, COALESCE(SUM(views), 0) as views FROM videos WHERE uploader_id = $1',
      [req.user.id]
    );
    
    res.json({
      totalVideos: parseInt(result.rows[0].total) || 0,
      totalViews: parseInt(result.rows[0].views) || 0
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get stats' });
  }
});

// Serve frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(PORT, async () => {
  console.log(`🚀 Server running on port ${PORT}`);
  await initDatabase();
});
