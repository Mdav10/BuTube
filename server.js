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

// ============ SECURITY: Rate Limiting (Safe addition) ============
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests, please try again later.' },
});

const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: { error: 'Too many login attempts, please try again later.' },
});

// ============ MIDDLEWARE (Your original working middleware + security) ============
app.use(helmet({ 
  contentSecurityPolicy: false, 
  crossOriginEmbedderPolicy: false 
}));
app.use(cors());
app.use(express.json({ limit: '500mb' }));
app.use(express.urlencoded({ extended: true, limit: '500mb' }));
app.use(compression());
app.use(cookieParser());

// ============ SECURITY: Apply rate limiting only to auth routes ============
app.use('/api/', limiter);
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);

// ============ SECURITY: XSS Protection (Safe addition) ============
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

// ============ STATIC FILES ============
app.use('/uploads', express.static('uploads'));
app.use(express.static('public'));

// ============ CREATE DIRECTORIES ============
['uploads', 'uploads/videos', 'uploads/thumbnails'].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// ============ MULTER CONFIG (YOUR EXACT WORKING VERSION) ============
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
  storage: storage,
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

// ============ DATABASE CONNECTION (YOUR EXACT VERSION) ============
const pool = new Pool({
  user: 'neondb_owner',
  password: 'npg_Cb7XtKr0BIoN',
  host: 'ep-holy-scene-apw8vqig.c-7.us-east-1.aws.neon.tech',
  port: 5432,
  database: 'neondb',
  ssl: { rejectUnauthorized: false },
  connectionTimeoutMillis: 30000,
});

pool.connect((err, client, release) => {
  if (err) {
    console.error('❌ Database error:', err.message);
  } else {
    console.log('✅ Database connected');
    release();
  }
});

// ============ INIT DATABASE (YOUR EXACT VERSION) ============
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
        total_comments INTEGER DEFAULT 0
      )
    `);

    const hashedPassword = await bcrypt.hash('08800+_+Owner!', 10);
    const hashedSecret = await bcrypt.hash('ADMIN_SECRET_2024', 10);
    
    await pool.query(
      `INSERT INTO users (username, password, secret_code, role, heard_from) 
       VALUES ($1, $2, $3, 'super_admin', 'system') 
       ON CONFLICT (username) DO NOTHING`,
      ['OWNER_MPC', hashedPassword, hashedSecret]
    );

    await pool.query(`
      INSERT INTO website_stats (total_visits, total_users, total_videos, total_views, total_likes, total_comments) 
      SELECT 0, 0, 0, 0, 0, 0 
      WHERE NOT EXISTS (SELECT 1 FROM website_stats)
    `);

    console.log('✅ Database ready');
    console.log('👑 Super Admin: OWNER_MPC');
    console.log('🔑 Password: 08800+_+Owner!');
    console.log('🔐 Secret: ADMIN_SECRET_2024');
  } catch (error) {
    console.error('❌ Database error:', error.message);
  }
}

// ============ AUTH MIDDLEWARE (YOUR EXACT VERSION) ============
const authenticate = async (req, res, next) => {
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

// ============ AUTH ROUTES (YOUR EXACT VERSION) ============
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
    
    await pool.query('UPDATE website_stats SET total_users = total_users + 1, total_visits = total_visits + 1');
    await logUserActivity(result.rows[0].id, 'register', { heardFrom }, req);
    
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
    await logUserActivity(user.id, 'login', { success: true }, req);
    
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

app.get('/api/auth/me', authenticate, async (req, res) => {
  res.json({ user: req.user });
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

// ============ ADMIN ROUTES (YOUR EXACT VERSION) ============
app.post('/api/admin/create-admin', authenticate, authorize('super_admin'), async (req, res) => {
  try {
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
      SELECT id, username, role, created_at 
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
      `SELECT * FROM videos WHERE uploader_id = $1 AND is_active = true ORDER BY created_at DESC`,
      [req.user.id]
    );
    res.json({ success: true, videos: result.rows });
  } catch (error) {
    console.error('My videos error:', error);
    res.status(500).json({ error: 'Failed to get your videos: ' + error.message });
  }
});

// ============ VIDEO UPLOAD - YOUR EXACT WORKING VERSION (UNTOUCHED) ============
app.post('/api/videos/upload', authenticate, authorize('admin', 'super_admin'), upload.fields([
  { name: 'video', maxCount: 1 },
  { name: 'thumbnail', maxCount: 1 }
]), async (req, res) => {
  try {
    console.log('📹 Upload request received');
    console.log('Body:', req.body);
    console.log('Files:', req.files);
    
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
    
    console.log('📁 Video saved at:', videoPath);
    console.log('🖼️ Thumbnail saved at:', thumbnailPath);
    
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
    
    console.log('✅ Video uploaded successfully:', result.rows[0].id);
    
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

// ============ VIDEO ROUTES (YOUR EXACT VERSION) ============
app.get('/api/videos', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT v.id, v.title, v.description, v.video_url, v.thumbnail_url, 
             v.views, v.likes, v.dislikes, v.share_count, v.created_at,
             u.username as uploader_name
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

app.get('/api/videos/:id', async (req, res) => {
  try {
    const videoId = parseInt(req.params.id);
    if (isNaN(videoId)) {
      return res.status(400).json({ error: 'Invalid video ID' });
    }
    
    await pool.query('UPDATE videos SET views = views + 1 WHERE id = $1', [videoId]);
    
    const videoResult = await pool.query(`
      SELECT v.*, u.username as uploader_name 
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
    
    await logUserActivity(req.user.id, 'edit_video', { videoId, title }, req);
    
    res.json({ success: true, video: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update video' });
  }
});

app.delete('/api/videos/:id', authenticate, authorize('admin', 'super_admin'), async (req, res) => {
  try {
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
    await logUserActivity(req.user.id, 'delete_video', { videoId }, req);
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete video' });
  }
});

// ============ PUBLIC INTERACTIONS (YOUR EXACT VERSION) ============
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
