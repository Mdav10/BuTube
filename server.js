const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const xss = require('xss');
const compression = require('compression');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Database connection with explicit configuration
const pool = new Pool({
  host: 'ep-holy-scene-apw8vqig.c-7.us-east-1.aws.neon.tech',
  port: 5432,
  database: 'neondb',
  user: 'neondb_owner',
  password: 'npg_Cb7XtKr0BIoN',
  ssl: {
    rejectUnauthorized: false
  },
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

// Test database connection
pool.connect((err, client, release) => {
  if (err) {
    console.error('❌ Database connection error:', err.message);
    console.log('⚠️ Will retry connection...');
  } else {
    console.log('✅ Database connected successfully!');
    release();
  }
});

// Security Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      mediaSrc: ["'self'", "data:", "blob:", "https:"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use('/api/', limiter);

app.use(express.json({ limit: '500mb' }));
app.use(express.urlencoded({ extended: true, limit: '500mb' }));
app.use(compression());

app.use('/thumbnails', express.static('thumbnails'));
app.use(express.static('public'));

if (!fs.existsSync('thumbnails')) {
  fs.mkdirSync('thumbnails');
}

const storage = multer.memoryStorage();

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 500 * 1024 * 1024
  },
  fileFilter: (req, file, cb) => {
    if (file.fieldname === 'video') {
      if (file.mimetype.startsWith('video/')) {
        cb(null, true);
      } else {
        cb(new Error('Only video files are allowed'));
      }
    } else if (file.fieldname === 'thumbnail') {
      if (file.mimetype.startsWith('image/')) {
        cb(null, true);
      } else {
        cb(new Error('Only image files are allowed for thumbnails'));
      }
    }
  }
});

async function initDatabase() {
  let retries = 5;
  while (retries > 0) {
    try {
      console.log(`🔄 Attempting database connection... (${retries} retries left)`);
      
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
          views INTEGER DEFAULT 0,
          likes INTEGER DEFAULT 0,
          dislikes INTEGER DEFAULT 0,
          share_count INTEGER DEFAULT 0,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          is_active BOOLEAN DEFAULT true
        );
      `);

      await pool.query(`
        CREATE TABLE IF NOT EXISTS comments (
          id SERIAL PRIMARY KEY,
          video_id INTEGER REFERENCES videos(id) ON DELETE CASCADE,
          user_id INTEGER REFERENCES users(id),
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
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);

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
         SELECT 0, 0, 0 
         WHERE NOT EXISTS (SELECT 1 FROM website_stats)`
      );

      console.log('✅ Database initialized successfully');
      return true;
    } catch (error) {
      console.error('❌ Database error:', error.message);
      retries--;
      if (retries === 0) {
        console.error('❌ Failed to connect to database after 5 attempts');
        throw error;
      }
      // Wait 3 seconds before retrying
      await new Promise(resolve => setTimeout(resolve, 3000));
    }
  }
}

const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'akabakuze_super_secret_key_2024');
    const user = await pool.query('SELECT id, username, role FROM users WHERE id = $1', [decoded.userId]);
    
    if (user.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    
    req.user = user.rows[0];
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
};

async function logUserActivity(userId, action, details, req) {
  try {
    const ip = req.ip || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'] || 'Unknown';
    await pool.query(
      `INSERT INTO user_logs (user_id, ip_address, user_agent, action, details) 
       VALUES ($1, $2, $3, $4, $5)`,
      [userId, ip, userAgent, action, JSON.stringify(details)]
    );
  } catch (error) {
    console.error('Error logging activity:', error);
  }
}

// ============== API ROUTES ==============

app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    res.json({ user: req.user });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get user info' });
  }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password, secretCode, heardFrom } = req.body;
    
    if (!username || !password || !secretCode) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    const existingUser = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Username already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const hashedSecret = await bcrypt.hash(secretCode, 10);
    
    const result = await pool.query(
      `INSERT INTO users (username, password, secret_code, heard_from, role) 
       VALUES ($1, $2, $3, $4, 'user') 
       RETURNING id, username, role`,
      [username, hashedPassword, hashedSecret, heardFrom]
    );
    
    const user = result.rows[0];
    await pool.query('UPDATE website_stats SET total_users = total_users + 1, total_visits = total_visits + 1');
    await logUserActivity(user.id, 'register', { heardFrom }, req);
    
    const token = jwt.sign(
      { userId: user.id, username: user.username, role: user.role },
      process.env.JWT_SECRET || 'akabakuze_super_secret_key_2024',
      { expiresIn: '7d' }
    );
    
    res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password, secretCode } = req.body;
    
    if (!username || !password || !secretCode) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
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
      return res.status(401).json({ error: 'Invalid secret code' });
    }
    
    await logUserActivity(user.id, 'login', {}, req);
    await pool.query('UPDATE website_stats SET total_visits = total_visits + 1');
    
    const token = jwt.sign(
      { userId: user.id, username: user.username, role: user.role },
      process.env.JWT_SECRET || 'akabakuze_super_secret_key_2024',
      { expiresIn: '7d' }
    );
    
    res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/api/admin/create-admin', authenticateToken, authorize('super_admin'), async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const hashedSecret = await bcrypt.hash('ADMIN_' + Date.now(), 10);
    
    const result = await pool.query(
      `INSERT INTO users (username, password, secret_code, role) 
       VALUES ($1, $2, $3, 'admin') 
       RETURNING id, username, role`,
      [username, hashedPassword, hashedSecret]
    );
    
    await logUserActivity(req.user.id, 'create_admin', { newAdmin: username }, req);
    res.json({ message: 'Admin created successfully', admin: result.rows[0] });
  } catch (error) {
    console.error('Create admin error:', error);
    res.status(500).json({ error: 'Failed to create admin' });
  }
});

app.post('/api/videos/upload', authenticateToken, authorize('admin', 'super_admin'), upload.fields([
  { name: 'video', maxCount: 1 },
  { name: 'thumbnail', maxCount: 1 }
]), async (req, res) => {
  try {
    const { title, description } = req.body;
    
    if (!title || !req.files || !req.files.video) {
      return res.status(400).json({ error: 'Title and video are required' });
    }

    const videoFile = req.files.video[0];
    const thumbnailFile = req.files.thumbnail ? req.files.thumbnail[0] : null;

    const result = await pool.query(
      `INSERT INTO videos 
       (title, description, video_data, video_mimetype, video_filename, 
        thumbnail_data, thumbnail_mimetype, uploader_id) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) 
       RETURNING id, title, description, uploader_id, created_at`,
      [
        title, 
        description || '', 
        videoFile.buffer,
        videoFile.mimetype,
        videoFile.originalname,
        thumbnailFile ? thumbnailFile.buffer : null,
        thumbnailFile ? thumbnailFile.mimetype : null,
        req.user.id
      ]
    );
    
    await logUserActivity(req.user.id, 'upload_video', { videoId: result.rows[0].id, title }, req);
    await pool.query('UPDATE website_stats SET total_videos = total_videos + 1');
    
    res.json({ 
      message: 'Video uploaded successfully to database', 
      video: result.rows[0]
    });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Failed to upload video: ' + error.message });
  }
});

app.get('/api/videos', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT v.id, v.title, v.description, v.uploader_id, v.views, 
              v.likes, v.dislikes, v.share_count, v.created_at,
              u.username as uploader_name,
              CASE WHEN v.thumbnail_data IS NOT NULL THEN true ELSE false END as has_thumbnail
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

app.get('/api/videos/:id', async (req, res) => {
  try {
    const videoId = req.params.id;
    
    await pool.query('UPDATE videos SET views = views + 1 WHERE id = $1', [videoId]);
    
    const result = await pool.query(
      `SELECT v.*, u.username as uploader_name 
       FROM videos v 
       JOIN users u ON v.uploader_id = u.id 
       WHERE v.id = $1 AND v.is_active = true`,
      [videoId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Video not found' });
    }
    
    const video = result.rows[0];
    
    const commentsResult = await pool.query(
      `SELECT c.*, u.username 
       FROM comments c 
       JOIN users u ON c.user_id = u.id 
       WHERE c.video_id = $1 
       ORDER BY c.created_at DESC`,
      [videoId]
    );
    
    const { video_data, thumbnail_data, ...videoMetadata } = video;
    
    res.json({
      ...videoMetadata,
      comments: commentsResult.rows,
      has_video: !!video_data,
      has_thumbnail: !!thumbnail_data
    });
  } catch (error) {
    console.error('Get video error:', error);
    res.status(500).json({ error: 'Failed to get video' });
  }
});

app.get('/api/videos/:id/stream', async (req, res) => {
  try {
    const videoId = req.params.id;
    
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
    res.status(500).json({ error: 'Failed to stream video' });
  }
});

app.get('/api/videos/:id/thumbnail', async (req, res) => {
  try {
    const videoId = req.params.id;
    
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
    res.status(500).json({ error: 'Failed to get thumbnail' });
  }
});

app.post('/api/videos/:id/like', authenticateToken, async (req, res) => {
  try {
    const videoId = req.params.id;
    const { action } = req.body;
    
    if (!['like', 'dislike'].includes(action)) {
      return res.status(400).json({ error: 'Invalid action' });
    }
    
    const existingAction = await pool.query(
      `SELECT * FROM user_actions 
       WHERE user_id = $1 AND video_id = $2 AND action_type = 'like_or_dislike'`,
      [req.user.id, videoId]
    );
    
    if (existingAction.rows.length > 0) {
      return res.status(400).json({ error: 'You already interacted with this video' });
    }
    
    const field = action === 'like' ? 'likes' : 'dislikes';
    await pool.query(`UPDATE videos SET ${field} = ${field} + 1 WHERE id = $1`, [videoId]);
    
    await pool.query(
      `INSERT INTO user_actions (user_id, video_id, action_type, action_data) 
       VALUES ($1, $2, $3, $4)`,
      [req.user.id, videoId, 'like_or_dislike', action]
    );
    
    await logUserActivity(req.user.id, 'like_video', { videoId, action }, req);
    res.json({ message: `${action} recorded successfully` });
  } catch (error) {
    console.error('Like error:', error);
    res.status(500).json({ error: 'Failed to process like' });
  }
});

app.post('/api/videos/:id/comment', authenticateToken, async (req, res) => {
  try {
    const videoId = req.params.id;
    const { comment } = req.body;
    
    if (!comment || comment.trim().length === 0) {
      return res.status(400).json({ error: 'Comment is required' });
    }
    
    const sanitizedComment = xss(comment);
    
    const result = await pool.query(
      `INSERT INTO comments (video_id, user_id, comment) 
       VALUES ($1, $2, $3) 
       RETURNING *`,
      [videoId, req.user.id, sanitizedComment]
    );
    
    await logUserActivity(req.user.id, 'comment_video', { videoId, comment: sanitizedComment }, req);
    res.json({ message: 'Comment added successfully', comment: result.rows[0] });
  } catch (error) {
    console.error('Comment error:', error);
    res.status(500).json({ error: 'Failed to add comment' });
  }
});

app.post('/api/videos/:id/share', async (req, res) => {
  try {
    const videoId = req.params.id;
    await pool.query('UPDATE videos SET share_count = share_count + 1 WHERE id = $1', [videoId]);
    res.json({ message: 'Share recorded successfully' });
  } catch (error) {
    console.error('Share error:', error);
    res.status(500).json({ error: 'Failed to record share' });
  }
});

app.get('/api/admin/stats', authenticateToken, authorize('admin', 'super_admin'), async (req, res) => {
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
      stats: stats.rows[0] || { total_visits: 0, total_users: 0, total_videos: 0 },
      userCount: users.rows[0].total,
      videoCount: videos.rows[0].total,
      recentLogs: logs.rows
    });
  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({ error: 'Failed to get stats' });
  }
});

app.delete('/api/videos/:id', authenticateToken, authorize('admin', 'super_admin'), async (req, res) => {
  try {
    const videoId = req.params.id;
    
    const videoResult = await pool.query('SELECT title FROM videos WHERE id = $1', [videoId]);
    if (videoResult.rows.length === 0) {
      return res.status(404).json({ error: 'Video not found' });
    }
    
    await pool.query('DELETE FROM videos WHERE id = $1', [videoId]);
    await logUserActivity(req.user.id, 'delete_video', { videoId, title: videoResult.rows[0].title }, req);
    
    res.json({ message: 'Video deleted successfully' });
  } catch (error) {
    console.error('Delete error:', error);
    res.status(500).json({ error: 'Failed to delete video' });
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Start server
app.listen(PORT, async () => {
  console.log(`🚀 AKABAKUZE server starting on port ${PORT}`);
  try {
    await initDatabase();
    console.log(`✅ Server ready!`);
    console.log(`🔑 Super Admin: OWNER_MPC`);
    console.log(`🔑 Password: 08800+_+Owner!`);
    console.log(`🔑 Secret Code: ADMIN_SECRET_2024`);
  } catch (error) {
    console.error('❌ Failed to start server:', error.message);
    process.exit(1);
  }
});
