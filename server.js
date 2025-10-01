'use strict';

const path = require('path');
const fs = require('fs');
const express = require('express');
const session = require('express-session');
const http = require('http');
const { Server } = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');

// Basic config
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'production';
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev_secret_family_care';
const DB_PATH = path.join(__dirname, 'familycare.db');

// Ensure data directory
try {
  fs.accessSync(DB_PATH, fs.constants.F_OK);
} catch (_) {
  // will be created by sqlite on first connect
}

// Init DB
const db = new sqlite3.Database(DB_PATH);
db.serialize(() => {
  db.run(`PRAGMA foreign_keys = ON;`);

  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    phone TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK(role IN ('elderly','family')),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );`);

  db.run(`CREATE TABLE IF NOT EXISTS contacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    contact_user_id INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(user_id, contact_user_id),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(contact_user_id) REFERENCES users(id) ON DELETE CASCADE
  );`);

  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_user_id INTEGER NOT NULL,
    to_user_id INTEGER,
    is_group INTEGER NOT NULL DEFAULT 0,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY(from_user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(to_user_id) REFERENCES users(id) ON DELETE CASCADE
  );`);

  db.run(`CREATE TABLE IF NOT EXISTS exercises (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    date TEXT NOT NULL,
    exercise_type TEXT NOT NULL,
    duration_min INTEGER NOT NULL,
    fatigue_level INTEGER,
    difficulty TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );`);

  db.run(`CREATE TABLE IF NOT EXISTS settings (
    user_id INTEGER PRIMARY KEY,
    elderly_notify_exercise INTEGER NOT NULL DEFAULT 1,
    elderly_notify_checkup INTEGER NOT NULL DEFAULT 1,
    family_notify_parent_done INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );`);

  db.run(`CREATE TABLE IF NOT EXISTS otps (
    phone TEXT PRIMARY KEY,
    code TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  );`);

  db.run(`CREATE TABLE IF NOT EXISTS support_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    is_bot INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );`);
});

// App and HTTP server
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: true, credentials: true }
});

// Middlewares
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 * 7 } // 7 days
}));

// Static
app.use(express.static(path.join(__dirname, 'public')));

// Online presence
const onlineUsers = new Map(); // userId -> { socketId, role }

function requireAuth(req, res, next) {
  if (!req.session || !req.session.user) return res.status(401).json({ error: 'unauthorized' });
  next();
}

function rowToUser(row) {
  return row ? {
    id: row.id,
    firstName: row.first_name,
    lastName: row.last_name,
    phone: row.phone,
    role: row.role
  } : null;
}

// Auth routes
app.post('/api/auth/request-otp', (req, res) => {
  const { firstName, lastName, phone, role } = req.body || {};
  if (!firstName || !lastName || !phone) return res.status(400).json({ error: 'missing_fields' });

  const roleValue = role === 'elderly' ? 'elderly' : role === 'family' ? 'family' : 'elderly';

  db.get(`SELECT * FROM users WHERE phone = ?`, [phone], (err, row) => {
    if (err) return res.status(500).json({ error: 'db_error' });

    if (!row) {
      db.run(`INSERT INTO users (first_name, last_name, phone, role) VALUES (?,?,?,?)`, [firstName, lastName, phone, roleValue], function(insertErr) {
        if (insertErr) return res.status(500).json({ error: 'db_insert_error' });
        ensureSettings(this.lastID);
        generateAndStoreOtp(phone, (code) => {
          console.log(`[OTP][DEV] ${phone} => ${code}`);
          res.json({ ok: true, devCode: NODE_ENV !== 'production' ? code : undefined });
        });
      });
    } else {
      // Optionally update name/role if changed
      db.run(`UPDATE users SET first_name = ?, last_name = ?, role = ? WHERE id = ?`, [firstName, lastName, roleValue, row.id], (uErr) => {
        if (uErr) return res.status(500).json({ error: 'db_update_error' });
        ensureSettings(row.id);
        generateAndStoreOtp(phone, (code) => {
          console.log(`[OTP][DEV] ${phone} => ${code}`);
          res.json({ ok: true, devCode: NODE_ENV !== 'production' ? code : undefined });
        });
      });
    }
  });
});

app.post('/api/auth/verify-otp', (req, res) => {
  const { phone, code } = req.body || {};
  if (!phone || !code) return res.status(400).json({ error: 'missing_fields' });
  const now = Date.now();
  db.get(`SELECT * FROM otps WHERE phone = ?`, [phone], (err, row) => {
    if (err) return res.status(500).json({ error: 'db_error' });
    if (!row) return res.status(400).json({ error: 'otp_not_found' });
    if (row.code !== code) return res.status(400).json({ error: 'otp_invalid' });
    if (row.expires_at < now) return res.status(400).json({ error: 'otp_expired' });

    db.get(`SELECT * FROM users WHERE phone = ?`, [phone], (uErr, uRow) => {
      if (uErr || !uRow) return res.status(500).json({ error: 'user_not_found' });
      req.session.user = rowToUser(uRow);
      // delete OTP
      db.run(`DELETE FROM otps WHERE phone = ?`, [phone]);
      res.json({ ok: true, user: req.session.user });
    });
  });
});

app.get('/api/auth/me', (req, res) => {
  res.json({ user: req.session && req.session.user ? req.session.user : null });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

function ensureSettings(userId) {
  db.run(`INSERT OR IGNORE INTO settings (user_id) VALUES (?)`, [userId]);
}

function generateAndStoreOtp(phone, cb) {
  const code = ('' + Math.floor(100000 + Math.random() * 900000));
  const expires = Date.now() + 1000 * 60 * 5; // 5 minutes
  db.run(`INSERT OR REPLACE INTO otps (phone, code, expires_at) VALUES (?,?,?)`, [phone, code, expires], (err) => {
    if (err) console.error('OTP store error', err);
    cb(code);
  });
}

// Contacts
app.get('/api/contacts', requireAuth, (req, res) => {
  const userId = req.session.user.id;
  const sql = `SELECT u.id, u.first_name, u.last_name, u.phone, u.role FROM contacts c JOIN users u ON u.id = c.contact_user_id WHERE c.user_id = ? ORDER BY u.first_name ASC`;
  db.all(sql, [userId], (err, rows) => {
    if (err) return res.status(500).json({ error: 'db_error' });
    const contacts = rows.map(r => ({ id: r.id, firstName: r.first_name, lastName: r.last_name, phone: r.phone, role: r.role, online: onlineUsers.has(r.id) }));
    res.json({ contacts });
  });
});

app.post('/api/contacts/add', requireAuth, (req, res) => {
  const userId = req.session.user.id;
  const { phone } = req.body || {};
  if (!phone) return res.status(400).json({ error: 'missing_phone' });
  db.get(`SELECT * FROM users WHERE phone = ?`, [phone], (err, row) => {
    if (err) return res.status(500).json({ error: 'db_error' });
    if (!row) return res.status(404).json({ error: 'user_not_found' });
    const otherId = row.id;
    if (otherId === userId) return res.status(400).json({ error: 'cannot_add_self' });

    const addLink = () => {
      db.run(`INSERT OR IGNORE INTO contacts (user_id, contact_user_id) VALUES (?,?)`, [userId, otherId], (e1) => {
        if (e1) return res.status(500).json({ error: 'db_error' });
        db.run(`INSERT OR IGNORE INTO contacts (user_id, contact_user_id) VALUES (?,?)`, [otherId, userId], (e2) => {
          if (e2) return res.status(500).json({ error: 'db_error' });
          res.json({ ok: true });
        });
      });
    };

    // Ensure settings exist for both
    ensureSettings(userId);
    ensureSettings(otherId);
    addLink();
  });
});

// Messages
app.get('/api/messages/:contactId', requireAuth, (req, res) => {
  const userId = req.session.user.id;
  const contactId = parseInt(req.params.contactId, 10);
  if (!contactId) return res.status(400).json({ error: 'invalid_contact' });
  const sql = `SELECT * FROM messages WHERE (from_user_id = ? AND to_user_id = ?) OR (from_user_id = ? AND to_user_id = ?) ORDER BY id ASC`;
  db.all(sql, [userId, contactId, contactId, userId], (err, rows) => {
    if (err) return res.status(500).json({ error: 'db_error' });
    res.json({ messages: rows.map(m => ({ id: m.id, fromUserId: m.from_user_id, toUserId: m.to_user_id, content: m.content, createdAt: m.created_at })) });
  });
});

app.post('/api/messages', requireAuth, (req, res) => {
  const fromUserId = req.session.user.id;
  const { toUserId, content, isGroup } = req.body || {};
  if (!content) return res.status(400).json({ error: 'missing_content' });
  const group = !!isGroup;

  if (group) {
    // Send to all contacts
    const sqlContacts = `SELECT contact_user_id AS id FROM contacts WHERE user_id = ?`;
    db.all(sqlContacts, [fromUserId], (err, rows) => {
      if (err) return res.status(500).json({ error: 'db_error' });
      const recipients = rows.map(r => r.id);
      // store one row per recipient for simplicity
      const stmt = db.prepare(`INSERT INTO messages (from_user_id, to_user_id, is_group, content) VALUES (?,?,1,?)`);
      recipients.forEach(rid => stmt.run([fromUserId, rid, content]));
      stmt.finalize(() => {
        recipients.forEach(rid => emitToUser(rid, 'message:new', { fromUserId, toUserId: rid, content, isGroup: true }));
        res.json({ ok: true });
      });
    });
  } else {
    if (!toUserId) return res.status(400).json({ error: 'missing_toUserId' });
    db.run(`INSERT INTO messages (from_user_id, to_user_id, is_group, content) VALUES (?,?,0,?)`, [fromUserId, toUserId, content], function(err) {
      if (err) return res.status(500).json({ error: 'db_error' });
      emitToUser(toUserId, 'message:new', { id: this.lastID, fromUserId, toUserId, content, isGroup: false });
      res.json({ ok: true, id: this.lastID });
    });
  }
});

// Exercise
app.post('/api/exercise', requireAuth, (req, res) => {
  const userId = req.session.user.id;
  const { exerciseType, duration, fatigueLevel, difficulty } = req.body || {};
  if (!exerciseType || typeof duration !== 'number') return res.status(400).json({ error: 'missing_fields' });
  const date = new Date().toISOString().split('T')[0];
  db.run(`INSERT INTO exercises (user_id, date, exercise_type, duration_min, fatigue_level, difficulty) VALUES (?,?,?,?,?,?)`, [userId, date, exerciseType, Math.max(0, Math.floor(duration)), fatigueLevel || null, difficulty || null], function(err) {
    if (err) return res.status(500).json({ error: 'db_error' });
    // Notify family contacts if enabled
    if (req.session.user.role === 'elderly') {
      db.get(`SELECT family_notify_parent_done FROM settings WHERE user_id = ?`, [userId], (sErr, sRow) => {
        const notifyEnabled = !sErr && sRow && sRow.family_notify_parent_done === 1;
        if (notifyEnabled) notifyFamilyOfExercise(userId, { exerciseType, duration: Math.floor(duration), fatigueLevel: fatigueLevel || null });
      });
    }
    res.json({ ok: true, id: this.lastID });
  });
});

function notifyFamilyOfExercise(elderlyId, payload) {
  // send to all contacts of elderly who are family
  const sql = `SELECT u.id FROM contacts c JOIN users u ON u.id = c.contact_user_id WHERE c.user_id = ? AND u.role = 'family'`;
  db.all(sql, [elderlyId], (err, rows) => {
    if (err) return;
    rows.forEach(r => emitToUser(r.id, 'exercise:completed', { fromUserId: elderlyId, ...payload }));
  });
}

app.get('/api/exercise/today', requireAuth, (req, res) => {
  const userId = req.session.user.id;
  const date = new Date().toISOString().split('T')[0];
  db.get(`SELECT * FROM exercises WHERE user_id = ? AND date = ? ORDER BY id DESC LIMIT 1`, [userId, date], (err, row) => {
    if (err) return res.status(500).json({ error: 'db_error' });
    res.json({ record: row || null });
  });
});

app.get('/api/exercise/records', requireAuth, (req, res) => {
  const userId = req.session.user.id;
  db.all(`SELECT * FROM exercises WHERE user_id = ? ORDER BY date DESC, id DESC`, [userId], (err, rows) => {
    if (err) return res.status(500).json({ error: 'db_error' });
    res.json({ records: rows });
  });
});

app.get('/api/exercise/summary/week', requireAuth, (req, res) => {
  const userId = req.session.user.id;
  const since = new Date();
  since.setDate(since.getDate() - 6);
  const sinceStr = since.toISOString().split('T')[0];
  db.all(`SELECT * FROM exercises WHERE user_id = ? AND date >= ? ORDER BY date ASC`, [userId, sinceStr], (err, rows) => {
    if (err) return res.status(500).json({ error: 'db_error' });
    res.json({ records: rows });
  });
});

app.get('/api/exercise/summary/month', requireAuth, (req, res) => {
  const userId = req.session.user.id;
  const since = new Date();
  since.setDate(since.getDate() - 29);
  const sinceStr = since.toISOString().split('T')[0];
  db.all(`SELECT * FROM exercises WHERE user_id = ? AND date >= ? ORDER BY date ASC`, [userId, sinceStr], (err, rows) => {
    if (err) return res.status(500).json({ error: 'db_error' });
    res.json({ records: rows });
  });
});

// Settings
app.get('/api/settings', requireAuth, (req, res) => {
  const userId = req.session.user.id;
  db.get(`SELECT * FROM settings WHERE user_id = ?`, [userId], (err, row) => {
    if (err) return res.status(500).json({ error: 'db_error' });
    res.json({ settings: row || {} });
  });
});

app.post('/api/settings', requireAuth, (req, res) => {
  const userId = req.session.user.id;
  const { elderly_notify_exercise, elderly_notify_checkup, family_notify_parent_done } = req.body || {};
  db.run(`INSERT INTO settings (user_id, elderly_notify_exercise, elderly_notify_checkup, family_notify_parent_done)
          VALUES (?,?,?,?)
          ON CONFLICT(user_id) DO UPDATE SET
            elderly_notify_exercise=excluded.elderly_notify_exercise,
            elderly_notify_checkup=excluded.elderly_notify_checkup,
            family_notify_parent_done=excluded.family_notify_parent_done`,
    [userId,
     typeof elderly_notify_exercise === 'number' ? elderly_notify_exercise : 1,
     typeof elderly_notify_checkup === 'number' ? elderly_notify_checkup : 1,
     typeof family_notify_parent_done === 'number' ? family_notify_parent_done : 1],
    (err) => {
      if (err) return res.status(500).json({ error: 'db_error' });
      res.json({ ok: true });
    }
  );
});

// Family notify elderly (manual reminder)
app.post('/api/notify/parent', requireAuth, (req, res) => {
  if (req.session.user.role !== 'family') return res.status(403).json({ error: 'forbidden' });
  const { elderlyUserId } = req.body || {};
  if (!elderlyUserId) return res.status(400).json({ error: 'missing_elderlyUserId' });
  emitToUser(parseInt(elderlyUserId, 10), 'exercise:reminder', { fromUserId: req.session.user.id });
  res.json({ ok: true });
});

// Support chat
app.get('/api/support', requireAuth, (req, res) => {
  const userId = req.session.user.id;
  db.all(`SELECT * FROM support_messages WHERE user_id = ? ORDER BY id ASC`, [userId], (err, rows) => {
    if (err) return res.status(500).json({ error: 'db_error' });
    res.json({ messages: rows.map(r => ({ id: r.id, userId: r.user_id, role: r.role, content: r.content, isBot: !!r.is_bot, createdAt: r.created_at })) });
  });
});

app.post('/api/support', requireAuth, (req, res) => {
  const userId = req.session.user.id;
  const role = req.session.user.role;
  const { content } = req.body || {};
  if (!content) return res.status(400).json({ error: 'missing_content' });
  db.run(`INSERT INTO support_messages (user_id, role, content, is_bot) VALUES (?,?,?,0)`, [userId, role, content], function(err) {
    if (err) return res.status(500).json({ error: 'db_error' });
    // simple auto-reply
    const reply = autoReply(content);
    db.run(`INSERT INTO support_messages (user_id, role, content, is_bot) VALUES (?,?,?,1)`, [userId, 'bot', reply], () => {
      res.json({ ok: true });
    });
  });
});

function autoReply(text) {
  const t = (text || '').toLowerCase();
  if (t.includes('รหัสผ่าน') || t.includes('password')) return 'หากลืมรหัสผ่าน ให้เข้าสู่ระบบด้วยเบอร์โทรและยืนยัน OTP ใหม่';
  if (t.includes('ออกกำลังกาย') || t.includes('exercise')) return 'เคล็ดลับ: เริ่มจากท่าง่าย 5-10 นาที แล้วค่อยเพิ่มเวลา';
  if (t.includes('ติดต่อ') || t.includes('contact')) return 'ทีมสนับสนุนจะติดต่อกลับภายใน 1 วันทำการ ขอบคุณค่ะ';
  return 'ขอบคุณสำหรับข้อความ ทีมสนับสนุนได้รับข้อความแล้วค่ะ';
}

// Socket.io
io.use((socket, next) => {
  const { userId, role } = socket.handshake.auth || {};
  if (!userId) return next(new Error('unauthorized'));
  socket.userId = parseInt(userId, 10);
  socket.userRole = role || 'elderly';
  next();
});

io.on('connection', (socket) => {
  onlineUsers.set(socket.userId, { socketId: socket.id, role: socket.userRole });
  io.emit('presence:update', { userId: socket.userId, online: true });

  socket.on('disconnect', () => {
    onlineUsers.delete(socket.userId);
    io.emit('presence:update', { userId: socket.userId, online: false });
  });
});

function emitToUser(userId, event, payload) {
  const target = onlineUsers.get(userId);
  if (target) io.to(target.socketId).emit(event, payload);
}

// Fallback to SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

server.listen(PORT, () => {
  console.log(`Family Care server running on http://localhost:${PORT}`);
});

