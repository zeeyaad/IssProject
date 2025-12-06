const express = require('express');
require('dotenv').config();
// Bctypt For Hashing Password "Import"
const bcrypt = require('bcrypt');
// For generating random tokens
const jwt = require('jsonwebtoken');
// For Encryption
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const rateLimit = require('express-rate-limit');
// For Security headers "Prevent XSS"
const helmet = require('helmet');
// Allow Front Access
const cors = require('cors');
const validator = require('validator');
// Perform Google token requests
const axios = require('axios');
const querystring = require('querystring');
// Verify Google ID tokens
const { OAuth2Client } = require('google-auth-library');
const path = require('path');
const fs = require('fs');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://accounts.google.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://accounts.google.com"],
      frameSrc: ["https://accounts.google.com"],
      imgSrc: ["'self'", "data:", "https:", "https://*.googleusercontent.com"],
      connectSrc: ["'self'", "https://accounts.google.com"]
    }
  }
}));
const allowedOrigin = process.env.FRONTEND_URL || 'http://localhost:5173';
app.use(cors({ origin: allowedOrigin, credentials: true }));
if (process.env.NODE_ENV === 'production') {
  app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }));
}
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser()); // Enable cookie parsing for httpOnly tokens

// Rate limiting for DoS & Brute Force protection
// Limiter for all routes
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Enhanced endpoint-specific rate limiters
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many login attempts, try again later.',
  standardHeaders: true,
  legacyHeaders: false
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3,  // 3 registrations per hour per IP
  message: 'Too many accounts created from this IP. Try again in 1 hour.',
  standardHeaders: true,
  legacyHeaders: false
});

const vaultLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 30,  // 30 vault operations per minute
  message: 'Too many vault requests. Please slow down.',
  standardHeaders: true,
  legacyHeaders: false
});

const searchLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 10,  // 10 searches per minute
  message: 'Too many searches. Please wait before searching again.',
  standardHeaders: true,
  legacyHeaders: false
});

const oauthLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,  // 10 OAuth attempts per 15 minutes
  message: 'Too many OAuth attempts. Try again later.',
  standardHeaders: true,
  legacyHeaders: false
});

const sha256Hex = (s) => crypto.createHash('sha256').update(s).digest('hex');

// AES Encryption utilities
class AESEncryption {
  static algorithm = 'aes-256-gcm'; // Encryption Algorithm

  // Create a Security Log Entry
  static auditLog(operation, status, details = {}) {
    const timestamp = new Date().toISOString();
    const logEntry = {
      timestamp,
      operation,
      status,
      ...details
    };
    // For demo: log to console. For production: write to secure log file or DB.
    console.log('[AUDIT]', JSON.stringify(logEntry));
  }
  // Encryption part
  static encrypt(text, keyHex, userId = null, field = '') {
    try {
      // Convert Key From Hex
      const key = Buffer.from(keyHex, 'hex');
      if (key.length !== 32) throw new Error('AES key must be 32 bytes (256 bits)');
      // Generate Random Initialization Vector
      const iv = crypto.randomBytes(12); // requires a 12-byte (96-bit) IV for best security
      const cipher = crypto.createCipheriv(this.algorithm, key, iv); // Algo AES, Key 3s Bytes, IV 12 Byte
      const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]); // Preform Encryption Convert Plaintext to Encrypted data
      this.auditLog('encrypt', 'success', { userId, field });
      return { // Return Encrypted Data "Cipher"
        iv: iv.toString('hex'),
        data: encrypted.toString('hex'),
        authTag: cipher.getAuthTag().toString('hex')
      };
    } catch (err) {
      this.auditLog('encrypt', 'failure', { userId, field, error: err.message });
      throw err;
    }
  }
  // Decryption part
  static decrypt(encryptedData, keyHex, userId = null, field = '') {
    try {
      const key = Buffer.from(keyHex, 'hex');
      const iv = Buffer.from(encryptedData.iv, 'hex');
      const decipher = crypto.createDecipheriv(this.algorithm, key, iv);
      decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex')); // To Ensure CipherText Was Not Modified "If Attacker Changed even 1 Byte"
      // Convert Encrypted to Bytes then Decrypts into Plaintext
      const decrypted = Buffer.concat([decipher.update(Buffer.from(encryptedData.data, 'hex')), decipher.final()]);
      this.auditLog('decrypt', 'success', { userId, field });
      return decrypted.toString('utf8'); // Return Plain Text
    } catch (err) {
      this.auditLog('decrypt', 'failure', { userId, field, error: err.message });
      throw err;
    }
  }
}

// Database setup
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'app.db');
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new sqlite3.Database(DB_PATH);
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT,
    email TEXT UNIQUE,
    sso_id TEXT,
    sso_provider TEXT,
    google_id TEXT,
    profile_picture TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME,
    sensitive_data TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    token TEXT,
    sso_provider TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  // Vault items table for multiple secrets per user
  db.run(`CREATE TABLE IF NOT EXISTS vault_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    secret_value TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);

  // Add indexes for performance
  db.run(`CREATE INDEX IF NOT EXISTS idx_sso ON users(sso_id, sso_provider)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_email ON users(email)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_vault_user ON vault_items(user_id)`);

  // Migrate existing sensitive_data to vault_items (one-time migration)
  db.all('SELECT id, sensitive_data FROM users WHERE sensitive_data IS NOT NULL AND sensitive_data != ""', (err, rows) => {
    if (err || !rows || rows.length === 0) return;

    rows.forEach(row => {
      db.get('SELECT COUNT(*) as count FROM vault_items WHERE user_id = ?', [row.id], (err, result) => {
        if (err || (result && result.count > 0)) return; // Skip if already migrated

        db.run(
          'INSERT INTO vault_items (user_id, title, secret_value) VALUES (?, ?, ?)',
          [row.id, 'Legacy Secret', row.sensitive_data],
          (err) => {
            if (!err) {
              console.log(`[MIGRATION] Migrated legacy secret for user ${row.id}`);
            }
          }
        );
      });
    });
  });
});

// JWT Configuration
const JWT_SECRET = process.env.JWT_SECRET;
const AES_KEY_HEX = process.env.AES_KEY_HEX;
if (!JWT_SECRET || !AES_KEY_HEX) {
  console.error('Missing JWT_SECRET or AES_KEY_HEX in environment - exiting.');
  process.exit(1);
}
const isHex = /^[0-9a-fA-F]+$/.test(AES_KEY_HEX); // Validate AES Key Format 
if (AES_KEY_HEX.length !== 64 || !isHex) {
  console.error('AES_KEY_HEX must be 64 hex characters.');
  process.exit(1);
}

// Input validation middleware
const validateInput = (req, res, next) => {
  const { username, password, email } = req.body;

  // Username: allow letters, numbers, underscore, dot, dash; length 3-30
  // This Prevent <Script>, Emojis, SQL injection, Spaces, Special Sybmols
  if (username && !/^[\w.-]{3,30}$/.test(username)) {
    return res.status(400).json({ error: 'Invalid username format' });
  }
  // Email format validation
  if (email && !validator.isEmail(email || '')) {
    return res.status(400).json({ error: 'Invalid email' });
  }

  // XSS prevention
  // This prevents JavaScript injection and HTML injection.
  if (username) req.body.username = validator.escape(username);
  if (email) req.body.email = validator.normalizeEmail(email) || '';

  next();
};

// Authentication middleware (supports cookie and Authorization header)
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const bearer = authHeader && authHeader.split(' ')[1];
  const token = req.cookies.auth_token || bearer;

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });

    // Verify token exists in database
    const tokenHash = sha256Hex(token);
    db.get('SELECT * FROM sessions WHERE token = ? AND user_id = ?',
      [tokenHash, user.id], (err, session) => {
        if (err || !session) {
          return res.status(403).json({ error: 'Invalid session' });
        }
        req.user = user;
        next();
      });
  });
};

// Logging middleware
const securityLogger = (req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.path} - IP: ${req.ip} - User-Agent: ${req.get('User-Agent')}`);
  next();
};
app.use(securityLogger);

// Routes

// User Registration
app.post('/register', registerLimiter, validateInput, async (req, res) => {
  try {
    const { username, password, email } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    // Password strength validation
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }
    // Use Bcrypt for Password Secure 
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(password, saltRounds);
    // Encrypt username and email using AES-256
    let encryptedUsername, encryptedEmail;
    try {
      encryptedUsername = JSON.stringify(AESEncryption.encrypt(username, AES_KEY_HEX, null, 'username'));
      const emailNormalized = email ? (validator.normalizeEmail(email) || String(email).trim().toLowerCase()) : '';
      encryptedEmail = emailNormalized ? JSON.stringify(AESEncryption.encrypt(emailNormalized, AES_KEY_HEX, null, 'email')) : '';
    } catch (encError) {
      return res.status(500).json({ error: 'Encryption failed for username/email' });
    }
    db.run('INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)',
      [encryptedUsername, passwordHash, encryptedEmail], function (err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ error: 'Username already exists' });
          }
          return res.status(500).json({ error: 'Database error' });
        }

        res.status(201).json({ message: 'User created successfully', userId: this.lastID });
      });
  } catch (error) {
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// Login with bcrypt verification
app.post('/login', loginLimiter, validateInput, async (req, res) => {
  try {
    const { username, password } = req.body;

    db.all('SELECT * FROM users', async (err, users) => {
      if (err || !users) {
        console.error('Login error - Database fetch failed:', err?.message);
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      let matchedUser = null;
      let decryptedUsername = null;
      for (const user of users) {
        try {
          const decrypted = AESEncryption.decrypt(JSON.parse(user.username), AES_KEY_HEX, user.id, 'username');
          if (decrypted === username) {
            matchedUser = user;
            decryptedUsername = decrypted;
            break;
          }
        } catch (decErr) {
          continue;
        }
      }
      if (!matchedUser) {
        console.warn('Login failed - User not found:', { username });
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      const validPassword = await bcrypt.compare(password, matchedUser.password_hash);
      if (!validPassword) {
        console.warn('Login failed - Invalid password for user:', { username });
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      let decryptedEmail = '';
      try {
        decryptedEmail = matchedUser.email ? AESEncryption.decrypt(JSON.parse(matchedUser.email), AES_KEY_HEX, matchedUser.id, 'email') : '';
      } catch (emailDecErr) {
        decryptedEmail = '';
      }
      const token = jwt.sign(
        { id: matchedUser.id, username: decryptedUsername, email: decryptedEmail },
        JWT_SECRET,
        { expiresIn: '1h' }
      );
      const tokenHash = sha256Hex(token);
      db.run('INSERT INTO sessions (user_id, token) VALUES (?, ?)', [matchedUser.id, tokenHash]);

      // Set httpOnly cookie (secure token storage - XSS protection)
      res.cookie('auth_token', token, {
        httpOnly: true,        // Cannot be accessed by JavaScript
        secure: process.env.NODE_ENV === 'production',  // HTTPS only in production
        sameSite: 'strict',    // CSRF protection
        maxAge: 3600000        // 1 hour (matches JWT expiration)
      });

      // Return user data and token (also set httpOnly cookie above)
      res.json({
        message: 'Login successful',
        token,
        user: { id: matchedUser.id, username: decryptedUsername, email: decryptedEmail }
      });
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error during login' });
  }
});

// Logout endpoint (clears httpOnly cookie and invalidates session)
app.post('/logout', authenticateToken, (req, res) => {
  const token = req.cookies.auth_token;
  const tokenHash = sha256Hex(token);

  // Remove session from database
  db.run('DELETE FROM sessions WHERE token = ?', [tokenHash], function (err) {
    if (err) {
      console.error('Error during logout:', err);
      return res.status(500).json({ error: 'Logout failed' });
    }

    // Clear the httpOnly cookie
    res.clearCookie('auth_token');
    res.json({ message: 'Logout successful' });
  });
});

// Store sensitive data with AES encryption
app.post('/secure-data', authenticateToken, validateInput, (req, res) => {
  const { sensitive_data } = req.body;

  if (typeof sensitive_data !== 'string') {
    return res.status(400).json({ error: 'Sensitive data must be a string' });
  }
  const trimmed = sensitive_data.trim();
  if (!trimmed) {
    return res.status(400).json({ error: 'Sensitive data required' });
  }
  if (Buffer.byteLength(trimmed, 'utf8') > 8 * 1024) {
    return res.status(413).json({ error: 'Sensitive data too large' });
  }

  try {
    const encryptedData = AESEncryption.encrypt(trimmed, AES_KEY_HEX);
    db.run('UPDATE users SET sensitive_data = ? WHERE id = ?',
      [JSON.stringify(encryptedData), req.user.id], function (err) {
        if (err) {
          console.error('DB write error on /secure-data:', { userId: req.user.id, err: err.message });
          return res.status(500).json({ error: 'Failed to store data' });
        }
        res.json({ message: 'Data stored securely' });
      });
  } catch (error) {
    console.error('Encryption error on /secure-data:', { userId: req.user.id, error: error.message, stack: error.stack });
    res.status(500).json({ error: 'Encryption failed' });
  }
});

// Search users (protected)
app.get('/search', searchLimiter, authenticateToken, (req, res) => {
  const { query } = req.query;

  if (!query) {
    return res.status(400).json({ error: 'Search query required' });
  }

  // Using parameterized queries to prevent SQL injection
  db.all('SELECT id, username FROM users WHERE username LIKE ? LIMIT 10',
    [`%${query}%`], (err, rows) => {
      if (err) {
        return res.status(500).json({ error: 'Search failed' });
      }
      res.json({ results: rows });
    });
});

// Retrieve and decrypt sensitive data
app.get('/secure-data', authenticateToken, (req, res) => {
  db.get('SELECT sensitive_data FROM users WHERE id = ?', [req.user.id], (err, row) => {
    if (err || !row || !row.sensitive_data) {
      return res.status(404).json({ error: 'No data found' });
    }

    try {
      const encryptedData = JSON.parse(row.sensitive_data);
      const decryptedData = AESEncryption.decrypt(encryptedData, AES_KEY_HEX);
      res.json({ sensitive_data: decryptedData });
    } catch (error) {
      console.error('Decryption error on GET /secure-data:', { userId: req.user.id, error: error.message, stack: error.stack });
      res.status(500).json({ error: 'Decryption failed' });
    }
  });
});

// ============================================
// VAULT ITEMS API - Multiple Secrets Support
// ============================================

// Create a new vault item
app.post('/vault/items', vaultLimiter, authenticateToken, validateInput, (req, res) => {
  const { title, secret_value } = req.body;

  if (!title || typeof title !== 'string' || !title.trim()) {
    return res.status(400).json({ error: 'Title is required' });
  }
  if (!secret_value || typeof secret_value !== 'string' || !secret_value.trim()) {
    return res.status(400).json({ error: 'Secret value is required' });
  }

  const trimmedTitle = title.trim();
  const trimmedSecret = secret_value.trim();

  if (Buffer.byteLength(trimmedSecret, 'utf8') > 8 * 1024) {
    return res.status(413).json({ error: 'Secret value too large (max 8KB)' });
  }

  try {
    // Encrypt the secret value
    const encryptedData = AESEncryption.encrypt(trimmedSecret, AES_KEY_HEX, req.user.id, 'vault_secret');
    const encryptedJSON = JSON.stringify(encryptedData);

    db.run(
      'INSERT INTO vault_items (user_id, title, secret_value) VALUES (?, ?, ?)',
      [req.user.id, trimmedTitle, encryptedJSON],
      function (err) {
        if (err) {
          console.error('DB error creating vault item:', { userId: req.user.id, err: err.message });
          return res.status(500).json({ error: 'Failed to create vault item' });
        }
        res.status(201).json({
          message: 'Vault item created successfully',
          id: this.lastID,
          title: trimmedTitle,
          created_at: new Date().toISOString()
        });
      }
    );
  } catch (error) {
    console.error('Encryption error creating vault item:', { userId: req.user.id, error: error.message });
    res.status(500).json({ error: 'Encryption failed' });
  }
});

// Get all vault items for the user
app.get('/vault/items', vaultLimiter, authenticateToken, (req, res) => {
  db.all(
    'SELECT id, title, created_at, updated_at FROM vault_items WHERE user_id = ? ORDER BY created_at DESC',
    [req.user.id],
    (err, rows) => {
      if (err) {
        console.error('DB error listing vault items:', { userId: req.user.id, err: err.message });
        return res.status(500).json({ error: 'Failed to retrieve vault items' });
      }
      res.json({ items: rows || [] });
    }
  );
});

// Get single vault item metadata (WITHOUT decrypted secret)
app.get('/vault/items/:id', vaultLimiter, authenticateToken, (req, res) => {
  const itemId = parseInt(req.params.id);

  if (isNaN(itemId)) {
    return res.status(400).json({ error: 'Invalid item ID' });
  }

  db.get(
    'SELECT id, title, created_at, updated_at FROM vault_items WHERE id = ? AND user_id = ?',
    [itemId, req.user.id],
    (err, row) => {
      if (err) {
        console.error('DB error getting vault item:', { userId: req.user.id, itemId, err: err.message });
        return res.status(500).json({ error: 'Failed to retrieve vault item' });
      }
      if (!row) {
        return res.status(404).json({ error: 'Vault item not found' });
      }
      res.json(row);
    }
  );
});

// Decrypt a specific vault item (on-demand)
app.post('/vault/items/:id/decrypt', vaultLimiter, authenticateToken, (req, res) => {
  const itemId = parseInt(req.params.id);

  if (isNaN(itemId)) {
    return res.status(400).json({ error: 'Invalid item ID' });
  }

  db.get(
    'SELECT secret_value FROM vault_items WHERE id = ? AND user_id = ?',
    [itemId, req.user.id],
    (err, row) => {
      if (err) {
        console.error('DB error decrypting vault item:', { userId: req.user.id, itemId, err: err.message });
        return res.status(500).json({ error: 'Failed to retrieve vault item' });
      }
      if (!row || !row.secret_value) {
        return res.status(404).json({ error: 'Vault item not found' });
      }

      try {
        const encryptedData = JSON.parse(row.secret_value);
        const decryptedValue = AESEncryption.decrypt(encryptedData, AES_KEY_HEX, req.user.id, 'vault_secret');

        // Audit log the decrypt operation
        console.log(`[AUDIT] User ${req.user.id} decrypted vault item ${itemId} at ${new Date().toISOString()}`);

        res.json({ secret_value: decryptedValue });
      } catch (error) {
        console.error('Decryption error:', { userId: req.user.id, itemId, error: error.message });
        res.status(500).json({ error: 'Decryption failed' });
      }
    }
  );
});

// Update a vault item
app.put('/vault/items/:id', vaultLimiter, authenticateToken, validateInput, (req, res) => {
  const itemId = parseInt(req.params.id);
  const { title, secret_value } = req.body;

  if (isNaN(itemId)) {
    return res.status(400).json({ error: 'Invalid item ID' });
  }

  if (!title && !secret_value) {
    return res.status(400).json({ error: 'At least one field (title or secret_value) must be provided' });
  }

  // First verify the item exists and belongs to the user
  db.get(
    'SELECT id FROM vault_items WHERE id = ? AND user_id = ?',
    [itemId, req.user.id],
    (err, row) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      if (!row) {
        return res.status(404).json({ error: 'Vault item not found' });
      }

      // Build update query dynamically
      const updates = [];
      const values = [];

      if (title && title.trim()) {
        updates.push('title = ?');
        values.push(title.trim());
      }

      if (secret_value && secret_value.trim()) {
        try {
          const encryptedData = AESEncryption.encrypt(secret_value.trim(), AES_KEY_HEX, req.user.id, 'vault_secret');
          updates.push('secret_value = ?');
          values.push(JSON.stringify(encryptedData));
        } catch (error) {
          return res.status(500).json({ error: 'Encryption failed' });
        }
      }

      updates.push('updated_at = CURRENT_TIMESTAMP');
      values.push(itemId, req.user.id);

      const query = `UPDATE vault_items SET ${updates.join(', ')} WHERE id = ? AND user_id = ?`;

      db.run(query, values, function (err) {
        if (err) {
          console.error('DB error updating vault item:', { userId: req.user.id, itemId, err: err.message });
          return res.status(500).json({ error: 'Failed to update vault item' });
        }
        res.json({ message: 'Vault item updated successfully' });
      });
    }
  );
});

// Delete vault item
app.delete('/vault/items/:id', authenticateToken, (req, res) => {
  const itemId = parseInt(req.params.id);

  if (isNaN(itemId)) {
    return res.status(400).json({ error: 'Invalid item ID' });
  }

  db.run(
    'DELETE FROM vault_items WHERE id = ? AND user_id = ?',
    [itemId, req.user.id],
    function (err) {
      if (err) {
        console.error('DB error deleting vault item:', { userId: req.user.id, itemId, err: err.message });
        return res.status(500).json({ error: 'Failed to delete vault item' });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Vault item not found' });
      }
      res.json({ message: 'Vault item deleted successfully' });
    }
  );
});


// SQL Injection protected search
app.get('/search', authenticateToken, validateInput, (req, res) => {
  const { query } = req.query;

  if (!query) {
    return res.status(400).json({ error: 'Search query required' });
  }

  // Using parameterized queries to prevent SQL injection
  db.all('SELECT id, username FROM users WHERE username LIKE ? LIMIT 10',
    [`%${query}%`], (err, rows) => {
      if (err) {
        return res.status(500).json({ error: 'Search failed' });
      }
      res.json({ results: rows });
    });
});

// Google OAuth Configuration
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || 'http://localhost:3000/auth/google/callback';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';
const GOOGLE_SKIP_VERIFICATION = String(process.env.GOOGLE_SKIP_VERIFICATION || 'false').toLowerCase() === 'true';
const oauth2Client = new OAuth2Client(GOOGLE_CLIENT_ID);

// Generate random state for OAuth security
const generateState = () => crypto.randomBytes(16).toString('hex');

// Store OAuth states (in production, use Redis)
const oauthStates = new Map();

// Initiate Google OAuth flow
app.get('/auth/google', oauthLimiter, (req, res) => {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_REDIRECT_URI) {
    return res.status(500).json({ message: 'Google OAuth is not configured. Please set GOOGLE_CLIENT_ID and GOOGLE_REDIRECT_URI.' });
  }
  const state = generateState();
  const nonce = generateState();

  // Store state for verification
  oauthStates.set(state, {
    nonce,
    createdAt: Date.now()
  });

  // Clear expired states (older than 10 minutes)
  for (const [key, value] of oauthStates.entries()) {
    if (Date.now() - value.createdAt > 10 * 60 * 1000) {
      oauthStates.delete(key);
    }
  }

  const { login_hint } = req.query;
  const prompt = 'select_account consent';

  const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?` + querystring.stringify({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: GOOGLE_REDIRECT_URI,
    response_type: 'code',
    scope: 'openid email profile',
    access_type: 'online',
    include_granted_scopes: 'true',
    prompt,
    state,
    nonce,
    ...(login_hint ? { login_hint } : {})
  });

  res.json({ authUrl });
});

// Google OAuth callback
app.get('/auth/google/callback', async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    return res.redirect(`${FRONTEND_URL}/login?error=${encodeURIComponent(error)}`);
  }

  // Verify state
  const storedState = oauthStates.get(state);
  if (!storedState) {
    return res.redirect(`${FRONTEND_URL}/login?error=${encodeURIComponent('Invalid OAuth state')}`);
  }

  oauthStates.delete(state); // Use state only once

  try {
    // Exchange authorization code for tokens
    const tokenResponse = await axios.post('https://oauth2.googleapis.com/token', querystring.stringify({
      code,
      client_id: GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      redirect_uri: GOOGLE_REDIRECT_URI,
      grant_type: 'authorization_code'
    }));

    const { id_token } = tokenResponse.data;
    const ticket = await oauth2Client.verifyIdToken({ idToken: id_token, audience: GOOGLE_CLIENT_ID });
    const googleUser = ticket.getPayload();
    // Nonce validation is optional - some OAuth flows may not include it
    if (googleUser.nonce && googleUser.nonce !== storedState.nonce) {
      throw new Error('Invalid nonce');
    }

    // Find or create user in database
    const emailNormalized = validator.normalizeEmail(googleUser.email) || String(googleUser.email).trim().toLowerCase();
    const emailHashed = sha256Hex(emailNormalized);
    db.get('SELECT * FROM users WHERE (sso_id = ? AND sso_provider = ?) OR email = ?',
      [`google_${googleUser.sub}`, 'google', emailHashed], async (err, user) => {
        if (err) {
          console.error('Database error:', err);
          return res.redirect(`${FRONTEND_URL}/login?error=${encodeURIComponent('Database error')}`);
        }

        let userId;
        let username;

        if (!user) {
          // Create new user from Google SSO
          username = googleUser.email.split('@')[0] + '_' + Date.now().toString().slice(-4);
          const usernameHashed = sha256Hex(username);

          db.run('INSERT INTO users (username, email, sso_id, sso_provider, profile_picture) VALUES (?, ?, ?, ?, ?)',
            [usernameHashed, emailHashed, `google_${googleUser.sub}`, 'google', googleUser.picture || null],
            function (err) {
              if (err) {
                console.error('Error creating user:', err);
                return res.redirect(`${FRONTEND_URL}/login?error=${encodeURIComponent('Failed to create user')}`);
              }
              userId = this.lastID;
              completeLogin(userId, username, googleUser, res);
            });
        } else {
          // Update existing user with SSO if needed
          if (!user.sso_id || user.sso_provider !== 'google') {
            db.run('UPDATE users SET sso_id = ?, sso_provider = ?, profile_picture = COALESCE(?, profile_picture) WHERE id = ?',
              [`google_${googleUser.sub}`, 'google', googleUser.picture || null, user.id]);
          } else if (googleUser.picture) {
            db.run('UPDATE users SET profile_picture = ? WHERE id = ?', [googleUser.picture, user.id]);
          }
          userId = user.id;
          // Use display username derived from email for UI; DB stores hashed
          username = googleUser.email.split('@')[0] + '_' + Date.now().toString().slice(-4);
          completeLogin(userId, username, googleUser, res);
        }
      });

  } catch (error) {
    console.error('OAuth error:', error.response?.data || error.message);
    res.redirect(`${FRONTEND_URL}/login?error=${encodeURIComponent('Authentication failed')}`);
  }
});

// Helper function to complete login and redirect
function completeLogin(userId, username, googleUser, res) {
  // Generate JWT token
  const token = jwt.sign(
    {
      id: userId,
      username: username,
      email: googleUser.email,
      provider: 'google'
    },
    JWT_SECRET,
    { expiresIn: '1h' }
  );

  // Store session in database
  const tokenHash = sha256Hex(token);
  db.run('INSERT INTO sessions (user_id, token, sso_provider) VALUES (?, ?, ?)',
    [userId, tokenHash, 'google']);

  // Set httpOnly cookie so subsequent API calls include the token automatically
  res.cookie('auth_token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 3600000
  });

  // Redirect to frontend with token
  res.redirect(`${FRONTEND_URL}/auth/callback?token=${token}&username=${encodeURIComponent(username)}&email=${encodeURIComponent(googleUser.email)}`);
}

// Validate SSO token endpoint
app.post('/auth/validate-sso', authenticateToken, (req, res) => {
  // This endpoint validates the JWT token and returns user info
  res.json({
    valid: true,
    user: req.user
  });
});

// Logout (token invalidation)
app.post('/logout', authenticateToken, (req, res) => {
  const token = req.headers['authorization'].split(' ')[1];
  const tokenHash = sha256Hex(token);
  db.run('DELETE FROM sessions WHERE token = ?', [tokenHash], function (err) {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.json({ message: 'Logout successful' });
  });
});

// Centralized error handler
app.use((err, req, res, next) => {
  console.error('Unhandled server error:', { path: req.path, method: req.method, error: err.message, stack: err.stack });
  res.status(500).json({ error: 'Internal server error' });
});

// Development-only Mock OAuth endpoint for testing
if (process.env.NODE_ENV === 'development') {
  app.get('/auth/google/dev-mock', (req, res) => {
    // Simulate Google response for testing without real Google credentials
    const mockToken = jwt.sign(
      {
        id: Math.floor(Math.random() * 1000),
        username: 'google_user_' + Date.now().toString().slice(-6),
        email: 'test@gmail.com',
        provider: 'google'
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.redirect(
      `${FRONTEND_URL}/auth/callback?` +
      querystring.stringify({
        token: mockToken,
        username: 'Google User',
        email: 'test@gmail.com',
        provider: 'google'
      })
    );
  });
}

// Start server
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Secure server running on port ${PORT}`);
    console.log('Security features enabled:');
    console.log('- AES-256-GCM encryption for data at rest');
    console.log('- bcrypt password hashing (12 rounds)');
    console.log('- JWT token-based authentication');
    console.log('- SSO integration ready');
    console.log('- SQL injection protection');
    console.log('- XSS prevention');
    console.log('- Rate limiting for DoS protection');
    console.log('- Security headers with Helmet');
    if (process.env.NODE_ENV === 'development') {
      console.log('- Development mock OAuth endpoint available at /auth/google/dev-mock');
    }
  });
} else {
  module.exports = app;
}
