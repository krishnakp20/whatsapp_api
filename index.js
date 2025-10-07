// app.js
// ====== Core & deps ======
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const upload = multer({ dest: 'uploads/' });

const path = require('path');
const fs = require('fs');
const mime = require('mime-types');
const cron = require('node-cron');

const swaggerUi = require('swagger-ui-express');
const YAML = require('yamljs');
const swaggerDocument = YAML.load('./swagger.yaml');

const qrcode = require('qrcode');
const { Client, LocalAuth, MessageMedia } = require('whatsapp-web.js');
const { getPool, initSchema } = require('./db');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

// ====== Config (change these) ======
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const API_KEY = process.env.API_KEY || '123456';
const PORT = process.env.PORT || 3001;

// ====== Server ======
const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: 'whatsapp-dashboard-secret',
  resave: false,
  saveUninitialized: true
}));

// ====== Views & static ======
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));   // keep your login.ejs & index.ejs here
app.use(express.static(path.join(__dirname, 'public')));

// ====== Simple auth middlewares ======
function requireLogin(req, res, next) {
  if (req.session?.userId || req.session?.loggedIn) return next();
  res.redirect('/login');
}

function generateApiKey() {
  return crypto.randomBytes(24).toString('hex');
}

async function requireApiKey(req, res, next) {
  try {
    const key = req.headers['x-api-key'];
    if (!key) return res.status(401).json({ error: 'Unauthorized - Invalid API Key' });
    // Allow legacy global API key
    if (key === API_KEY) {
      req.apiUserId = null;
      return next();
    }
    // Accept per-user API key
    const pool = await getPool();
    const [rows] = await pool.query('SELECT id FROM users WHERE api_key = ? LIMIT 1', [key]);
    if (!rows.length) return res.status(401).json({ error: 'Unauthorized - Invalid API Key' });
    req.apiUserId = rows[0].id;
    return next();
  } catch (e) {
    return res.status(500).json({ error: 'Auth middleware failure' });
  }
}

function requireAdmin(req, res, next) {
  if (req.session?.loggedIn) return next();
  return res.redirect('/login');
}

// ====== WhatsApp client store ======
const clients = {};            // sessionId -> Client
const qrCodes = {};            // sessionId -> dataURL (or null after login)
const scheduledJobs = {};      // `${sessionId}-${number}` -> cron job
const sessionOwners = {};      // sessionId -> userId

// ====== Robust readiness helper ======
async function waitUntilConnected(client, timeoutMs = 60000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const state = await client.getState(); // 'CONNECTED' | 'OPENING' | 'UNPAIRED' | etc.
      if (state === 'CONNECTED') return true;
    } catch (_) { /* ignore and keep polling */ }
    await new Promise(r => setTimeout(r, 1000));
  }
  throw new Error('Client not CONNECTED within timeout');
}

// ====== Create / get a WA session ======
async function resolveSessionOwner(sessionId) {
  try {
    const pool = await getPool();
    const [rows] = await pool.query('SELECT user_id FROM wa_sessions WHERE session_id = ?', [sessionId]);
    if (rows.length) {
      sessionOwners[sessionId] = rows[0].user_id;
      return rows[0].user_id;
    }
  } catch (_) {}
  return undefined;
}

function mapAckToStatus(ack) {
  if (ack === 1) return 'sent';
  if (ack === 2) return 'delivered';
  if (ack === 3) return 'read';
  if (ack === 4) return 'played';
  return 'queued';
}

function createSession(sessionId) {
  if (clients[sessionId]) return clients[sessionId];

  const client = new Client({
    authStrategy: new LocalAuth({
      clientId: sessionId,
      dataPath: path.join(__dirname, '.wwebjs_auth')
    }),
    // Keep WhatsApp Web in sync; prevents "authenticated but never ready"
    webVersionCache: {
      type: 'remote',
      remotePath: 'https://raw.githubusercontent.com/wppconnect-team/wa-version/main/last.json'
    },
    puppeteer: {
      headless: 'new',
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-extensions',
        '--disable-gpu',
        '--no-first-run',
        '--no-zygote'
      ]
    },

    takeoverOnConflict: true,
    takeoverTimeoutMs: 0,
    qrTimeoutMs: 0,
    authTimeoutMs: 0
  });

  // ====== Events & logs ======
  client.on('qr', async (qr) => {
    qrCodes[sessionId] = await qrcode.toDataURL(qr);
    console.log(`📲 QR generated for session: ${sessionId}`);
  });

  client.on('authenticated', () => {
    console.log(`🔐 Authenticated session: ${sessionId}`);
  });

  client.on('ready', () => {
    console.log(`✅ Session ${sessionId} is ready!`);
    qrCodes[sessionId] = null;
  });

  client.on('change_state', s => console.log(`🔄 ${sessionId} state:`, s));
  client.on('loading_screen', (p, t) => console.log(`⏳ ${sessionId} loading ${p}% of ${t}`));
  client.on('remote_session_saved', () => console.log(`💾 ${sessionId}: remote session saved`));

  client.on('message', async (msg) => {
    console.log(`📩 [${sessionId}] Message from ${msg.from}: ${msg.body}`);
    // Placeholder: could create inbound records or feed ticketing
  });

  client.on('message_ack', async (msg, ack) => {
    try {
      const userId = sessionOwners[sessionId] || await resolveSessionOwner(sessionId);
      if (!userId) return;
      const pool = await getPool();
      const status = mapAckToStatus(ack);
      await pool.query(
        'UPDATE messages SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ? AND session_id = ? AND wwid = ?',
        [status, userId, sessionId, msg?.id?._serialized || null]
      );
    } catch (e) {
      console.error('ack update failed', e);
    }
  });

  client.on('auth_failure', (msg) => {
    console.error(`🚫 Auth failure on session ${sessionId}:`, msg);
  });

  client.on('disconnected', (reason) => {
    console.log(`❌ Session ${sessionId} disconnected:`, reason);
    delete clients[sessionId];
    qrCodes[sessionId] = null;
    // NOTE: Only delete the local auth if you WANT to force re-login.
    // fs.rmSync(path.join(__dirname, `.wwebjs_auth/session-${sessionId}`), { recursive: true, force: true });
  });

  client.initialize();
  clients[sessionId] = client;
  return client;
}

// =======================
// Login / Logout (UI)
// =======================
app.get('/signup', (req, res) => {
  res.render('signup', { error: null });
});

app.post('/signup', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.render('signup', { error: 'Provide email and password' });
  try {
    const pool = await getPool();
    const [rows] = await pool.query('SELECT id FROM users WHERE email = ?', [String(email).toLowerCase()]);
    if (rows.length) return res.render('signup', { error: 'Email already registered' });
    const passwordHash = bcrypt.hashSync(password, 10);
    const apiKey = generateApiKey();
    const [result] = await pool.query('INSERT INTO users (email, password_hash, api_key) VALUES (?, ?, ?)', [String(email).toLowerCase(), passwordHash, apiKey]);
    req.session.userId = result.insertId;
    res.redirect('/');
  } catch (e) {
    console.error('signup error', e);
    res.render('signup', { error: 'Failed to sign up' });
  }
});

app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email && password === ADMIN_PASSWORD) {
    req.session.loggedIn = true;
    return res.redirect('/');
  }
  if (!email || !password) return res.render('login', { error: 'Enter email and password' });
  try {
    const pool = await getPool();
    const [rows] = await pool.query('SELECT id, password_hash FROM users WHERE email = ?', [String(email).toLowerCase()]);
    if (!rows.length) return res.render('login', { error: 'Invalid credentials' });
    const user = rows[0];
    const ok = bcrypt.compareSync(password, user.password_hash);
    if (!ok) return res.render('login', { error: 'Invalid credentials' });
    req.session.userId = user.id;
    // Preload user's existing sessions
    try {
      const [sess] = await pool.query('SELECT session_id FROM wa_sessions WHERE user_id = ?', [user.id]);
      for (const s of sess) {
        sessionOwners[s.session_id] = user.id;
        if (!clients[s.session_id]) createSession(s.session_id);
      }
    } catch (e) {
      console.error('preload sessions failed', e);
    }
    res.redirect('/');
  } catch (e) {
    console.error('login error', e);
    res.render('login', { error: 'Login failed' });
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// =======================
// Admin Panel (UI)
// =======================
app.get('/admin', requireAdmin, async (req, res) => {
  try {
    const pool = await getPool();
    const [users] = await pool.query('SELECT id, email, api_key, created_at FROM users ORDER BY id DESC');
    const [quotas] = await pool.query('SELECT user_id, free_limit, used_count, period, reset_at FROM quotas');
    const [sessions] = await pool.query('SELECT user_id, session_id, created_at FROM wa_sessions');
    res.render('admin', { users, quotas, sessions, error: null, ok: null });
  } catch (e) {
    console.error('/admin load error', e);
    res.render('admin', { users: [], quotas: [], sessions: [], error: 'Failed to load admin data', ok: null });
  }
});

app.post('/admin/reset-apikey', requireAdmin, async (req, res) => {
  const { userId } = req.body || {};
  try {
    const pool = await getPool();
    const newKey = generateApiKey();
    await pool.query('UPDATE users SET api_key = ? WHERE id = ?', [newKey, userId]);
    res.redirect('/admin');
  } catch (e) {
    console.error('reset-apikey error', e);
    res.redirect('/admin');
  }
});

app.post('/admin/update-quota', requireAdmin, async (req, res) => {
  const { userId, freeLimit } = req.body || {};
  try {
    const pool = await getPool();
    await pool.query('INSERT INTO quotas (user_id, free_limit, used_count, period) VALUES (?, ?, 0, "lifetime") ON DUPLICATE KEY UPDATE free_limit = VALUES(free_limit)', [userId, Number(freeLimit) || 100]);
    res.redirect('/admin');
  } catch (e) {
    console.error('update-quota error', e);
    res.redirect('/admin');
  }
});

app.post('/admin/delete-user', requireAdmin, async (req, res) => {
  const { userId } = req.body || {};
  try {
    const pool = await getPool();
    await pool.query('DELETE FROM users WHERE id = ?', [userId]);
    res.redirect('/admin');
  } catch (e) {
    console.error('delete-user error', e);
    res.redirect('/admin');
  }
});

// =======================
// Dashboard (UI)
// =======================
app.get('/', requireLogin, (req, res) => {
  (async () => {
    const pool = await getPool();
    const [uRows] = await pool.query('SELECT api_key FROM users WHERE id = ? LIMIT 1', [req.session.userId || 0]);
    const userApiKey = (uRows.length ? uRows[0].api_key : API_KEY);
    const [dbSessions] = await pool.query('SELECT session_id FROM wa_sessions WHERE user_id = ?', [req.session.userId || 0]);
    const sessionIds = dbSessions.map(s => s.session_id);
    // ensure in-memory clients exist for each
    for (const sid of sessionIds) {
      sessionOwners[sid] = req.session.userId;
      if (!clients[sid]) createSession(sid);
    }
    res.render('index', {
      sessions: sessionIds,
      qrCodes,
      API_KEY: userApiKey
    });
  })();
});

// =======================
// Chat Panel (UI + APIs)
// =======================
app.get('/chat', requireLogin, async (req, res) => {
  console.log('Chat route accessed by user:', req.session.userId);
  res.render('chat', {});
});

// Threads: dedupe peers by to_jid from messages for this user
app.get('/chat/threads', requireLogin, async (req, res) => {
  try {
    const pool = await getPool();
    const [rows] = await pool.query(
      'SELECT to_jid AS peer, MAX(updated_at) AS last_at FROM messages WHERE user_id = ? GROUP BY to_jid ORDER BY last_at DESC LIMIT 200',
      [req.session.userId]
    );
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// Messages for a peer
app.get('/chat/messages', requireLogin, async (req, res) => {
  const { peer } = req.query || {};
  if (!peer) return res.status(400).json({ error: 'peer required' });
  try {
    const pool = await getPool();
    const [rows] = await pool.query(
      'SELECT id, session_id, to_jid, type, content, status, wwid, created_at FROM messages WHERE user_id = ? AND to_jid = ? ORDER BY id DESC LIMIT 200',
      [req.session.userId, peer]
    );
    res.json(rows.reverse());
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// Send from chat panel
app.post('/chat/send', requireLogin, async (req, res) => {
  const { sessionId, peer, message } = req.body || {};
  if (!sessionId || !peer || !message) return res.status(400).json({ error: 'Missing parameters' });
  try {
    const userId = sessionOwners[sessionId] || await resolveSessionOwner(sessionId);
    if (userId !== req.session.userId) return res.status(403).json({ error: 'Session not owned' });
    const quota = await ensureQuotaAndIncrement(userId);
    if (!quota.allowed) return res.status(402).json({ error: 'Quota exceeded' });
    const client = clients[sessionId] || createSession(sessionId);
    await waitUntilConnected(client, 60000);
    const sent = await client.sendMessage(peer, message);
    await recordMessage(userId, sessionId, peer, 'text', message, sent?.id?._serialized || null, 'sent');
    res.json({ status: 'success', id: sent?.id?._serialized || null });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// Create ticket for peer with a naive summary (last 5 messages)
app.post('/chat/ticket', requireLogin, async (req, res) => {
  const { peer } = req.body || {};
  if (!peer) return res.status(400).json({ error: 'peer required' });
  try {
    const pool = await getPool();
    const [msgs] = await pool.query(
      'SELECT content FROM messages WHERE user_id = ? AND to_jid = ? ORDER BY id DESC LIMIT 5',
      [req.session.userId, peer]
    );
    const lines = msgs.reverse().map(m => (m.content || '').slice(0, 120));
    const summary = `Recent conversation summary:\n- ` + lines.join('\n- ');
    await pool.query('INSERT INTO tickets (user_id, peer, summary) VALUES (?, ?, ?)', [req.session.userId, peer, summary]);
    res.json({ status: 'success' });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// Export messages as CSV
app.get('/export/messages', requireLogin, async (req, res) => {
  try {
    const userId = req.session.userId;
    const isAdmin = req.session.loggedIn;
    console.log('Export request - userId:', userId, 'isAdmin:', isAdmin);
    
    if (!userId && !isAdmin) {
      console.error('No userId in session and not admin');
      return res.status(401).json({ error: 'Not authenticated' });
    }
    
    const { fromDate, toDate, peer } = req.query || {};
    const pool = await getPool();
    
    let query = 'SELECT id, session_id, to_jid, type, content, status, wwid, created_at, updated_at FROM messages';
    const params = [];
    
    // If regular user (not admin), filter by user_id
    if (userId && !isAdmin) {
      query += ' WHERE user_id = ?';
      params.push(userId);
    } else if (isAdmin && !userId) {
      // Admin can see all messages or filter by specific conditions
      query += ' WHERE 1=1';
    } else if (userId) {
      // Logged in user (may or may not be admin)
      query += ' WHERE user_id = ?';
      params.push(userId);
    }
    
    if (fromDate) {
      query += ' AND created_at >= ?';
      params.push(fromDate + ' 00:00:00');
    }
    if (toDate) {
      query += ' AND created_at <= ?';
      params.push(toDate + ' 23:59:59');
    }
    if (peer) {
      query += ' AND to_jid = ?';
      params.push(peer);
    }
    
    query += ' ORDER BY id ASC';
    
    console.log('Export query:', query);
    console.log('Export params:', params);
    
    const [rows] = await pool.query(query, params);
    console.log(`Found ${rows.length} messages to export`);
    
    // Generate CSV
    const headers = ['ID', 'Session ID', 'Recipient', 'Type', 'Content', 'Status', 'WhatsApp ID', 'Created At', 'Updated At'];
    const csvRows = [headers.join(',')];
    
    rows.forEach(row => {
      const values = [
        row.id,
        row.session_id,
        row.to_jid,
        row.type,
        `"${(row.content || '').replace(/"/g, '""')}"`, // Escape quotes in content
        row.status,
        row.wwid || '',
        row.created_at,
        row.updated_at
      ];
      csvRows.push(values.join(','));
    });
    
    const csv = csvRows.join('\n');
    
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="messages_export.csv"');
    res.send(csv);
    console.log('CSV export sent successfully');
  } catch (e) {
    console.error('Export error:', e);
    res.status(500).json({ error: String(e) });
  }
});

app.post('/create-session', requireLogin, async (req, res) => {
  const { sessionId } = req.body || {};
  if (!sessionId) return res.redirect('/');
  try {
    const pool = await getPool();
    await pool.query('INSERT IGNORE INTO wa_sessions (user_id, session_id) VALUES (?, ?)', [req.session.userId, sessionId]);
    sessionOwners[sessionId] = req.session.userId;
    if (!clients[sessionId]) createSession(sessionId);
  } catch (e) {
    console.error('create-session db error', e);
  }
  return res.redirect('/');
});

app.post('/logout-session', requireLogin, async (req, res) => {
  const { sessionId } = req.body || {};
  const client = clients[sessionId];
  if (sessionOwners[sessionId] !== req.session.userId && !req.session.loggedIn) {
    return res.status(403).send('Forbidden');
  }
  if (client) {
    try {
      await client.logout();
      delete clients[sessionId];
      // Optional: remove stored auth to force relogin on next create
      fs.rmSync(path.join(__dirname, `.wwebjs_auth/session-${sessionId}`), { recursive: true, force: true });
    } catch (err) {
      console.error(`❌ Error logging out session ${sessionId}:`, err);
    }
  }
  try {
    const pool = await getPool();
    await pool.query('DELETE FROM wa_sessions WHERE session_id = ? AND user_id = ?', [sessionId, req.session.userId]);
    delete sessionOwners[sessionId];
  } catch (_) {}
  return res.redirect('/');
});

// =======================
// Utility endpoints
// =======================

// Check current WA state
app.get('/state/:sessionId', async (req, res) => {
  const { sessionId } = req.params;
  const client = clients[sessionId] || createSession(sessionId);
  try {
    const state = await client.getState();
    res.json({
      sessionId,
      state,
      wid: client?.info?.wid?._serialized || null,
      pushname: client?.info?.pushname || null
    });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// Get QR (data URL) for a session
app.get('/get-qr/:sessionId', (req, res) => {
  const sessionId = req.params.sessionId;
  if (!clients[sessionId]) createSession(sessionId);
  res.json({ sessionId, qr: qrCodes[sessionId] || '✅ Already logged in' });
});

// List sessions
app.get('/sessions', (req, res) => {
  res.json({ activeSessions: Object.keys(clients) });
});

// =======================
// Public API (no API key)
// =======================

// optional helper (put near the top once and reuse)
function normalizeMsisdn(n) {
  // keep digits only, e.g. "91 98765-43210" -> "919876543210"
  return String(n).replace(/\D/g, '');
}

async function ensureQuotaAndIncrement(userId) {
  const pool = await getPool();
  const [rows] = await pool.query('SELECT free_limit, used_count FROM quotas WHERE user_id = ? FOR UPDATE', [userId]);
  if (!rows.length) {
    await pool.query('INSERT INTO quotas (user_id, free_limit, used_count, period) VALUES (?, 100, 0, "lifetime")', [userId]);
    return { allowed: true };
  }
  const q = rows[0];
  if (q.used_count >= q.free_limit) {
    return { allowed: false };
  }
  await pool.query('UPDATE quotas SET used_count = used_count + 1 WHERE user_id = ?', [userId]);
  return { allowed: true };
}

async function recordMessage(userId, sessionId, toJid, type, content, wwid, status) {
  try {
    const pool = await getPool();
    await pool.query(
      'INSERT INTO messages (user_id, session_id, to_jid, type, content, status, wwid) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [userId, sessionId, toJid, type, content || null, status || 'queued', wwid || null]
    );
  } catch (e) {
    console.error('recordMessage error', e);
  }
}

app.post('/send-text', async (req, res) => {
  const { sessionId, number, message } = req.body || {};
  if (!sessionId || !number || !message) {
    return res.status(400).json({ error: 'Missing parameters' });
  }

  try {
    const userId = sessionOwners[sessionId] || await resolveSessionOwner(sessionId);
    if (!userId) return res.status(403).json({ error: 'Session not owned' });
    const quota = await ensureQuotaAndIncrement(userId);
    if (!quota.allowed) return res.status(402).json({ error: 'Quota exceeded' });
    const client = clients[sessionId] || createSession(sessionId);
    await waitUntilConnected(client, 60000);

    const raw = normalizeMsisdn(number);          // "9198xxxxxxx"
    const numId = await client.getNumberId(raw);  // { _serialized: '9198...@c.us' } or null
    if (!numId) {
      return res.status(400).json({ error: 'Number is not on WhatsApp or invalid format' });
    }

    const sent = await client.sendMessage(numId._serialized, message);
    await recordMessage(userId, sessionId, numId._serialized, 'text', message, sent?.id?._serialized || null, 'sent');
    return res.json({ status: 'success', message: 'Text sent', id: sent?.id?._serialized || null });
  } catch (err) {
    console.error('❌ /send-text:', err);
    return res.status(500).json({ error: String(err) });
  }
});
app.post('/send-text-group', async (req, res) => {
  const { sessionId, groupName, message } = req.body || {};
  if (!sessionId || !groupName || !message) return res.status(400).json({ error: 'Missing parameters' });

  try {
    const userId = sessionOwners[sessionId] || await resolveSessionOwner(sessionId);
    if (!userId) return res.status(403).json({ error: 'Session not owned' });
    const quota = await ensureQuotaAndIncrement(userId);
    if (!quota.allowed) return res.status(402).json({ error: 'Quota exceeded' });
    const client = clients[sessionId] || createSession(sessionId);
    await waitUntilConnected(client, 60000);
    const chats = await client.getChats();
    const group = chats.find(c => c.isGroup && c.name === groupName);
    if (!group) return res.status(404).json({ error: 'Group not found' });

    const sent = await client.sendMessage(group.id._serialized, message);
    await recordMessage(userId, sessionId, group.id._serialized, 'text', message, sent?.id?._serialized || null, 'sent');
    res.json({ status: 'success', message: 'Text sent to group', id: sent?.id?._serialized || null });
  } catch (err) {
    console.error('❌ /send-text-group:', err);
    res.status(500).json({ error: String(err) });
  }
});

app.post('/send-media', upload.single('file'), async (req, res) => {
  const { sessionId, number, caption } = req.body || {};
  if (!req.file) return res.status(400).send('No file uploaded');
  if (!sessionId || !number) return res.status(400).send('Missing parameters');

  try {
    const userId = sessionOwners[sessionId] || await resolveSessionOwner(sessionId);
    if (!userId) return res.status(403).json({ error: 'Session not owned' });
    const quota = await ensureQuotaAndIncrement(userId);
    if (!quota.allowed) return res.status(402).json({ error: 'Quota exceeded' });
    const client = clients[sessionId] || createSession(sessionId);
    await waitUntilConnected(client, 60000);

    const filePath = path.join(__dirname, req.file.path);
    const mimeType = mime.lookup(filePath);
    const fileData = fs.readFileSync(filePath, { encoding: 'base64' });
    const media = new MessageMedia(mimeType, fileData, req.file.originalname);

    const whatsappId = number.includes('@c.us') ? number : `${number}@c.us`;
    const sent = await client.sendMessage(whatsappId, media, { caption: caption || '' });

    fs.unlinkSync(filePath);
    await recordMessage(userId, sessionId, whatsappId, 'media', caption || req.file.originalname, sent?.id?._serialized || null, 'sent');
    res.json({ status: 'success', message: 'Media sent!', id: sent?.id?._serialized || null });
  } catch (err) {
    console.error('❌ /send-media:', err);
    res.status(500).json({ error: String(err) });
  }
});

app.post('/send-media-group', upload.single('file'), async (req, res) => {
  const { sessionId, groupName, caption } = req.body || {};
  if (!req.file) return res.status(400).send('No file uploaded');
  if (!sessionId || !groupName) return res.status(400).send('Missing parameters');

  try {
    const userId = sessionOwners[sessionId] || await resolveSessionOwner(sessionId);
    if (!userId) return res.status(403).json({ error: 'Session not owned' });
    const quota = await ensureQuotaAndIncrement(userId);
    if (!quota.allowed) return res.status(402).json({ error: 'Quota exceeded' });
    const client = clients[sessionId] || createSession(sessionId);
    await waitUntilConnected(client, 60000);

    const filePath = path.join(__dirname, req.file.path);
    const mimeType = mime.lookup(filePath);
    const fileData = fs.readFileSync(filePath, { encoding: 'base64' });
    const media = new MessageMedia(mimeType, fileData, req.file.originalname);

    const chats = await client.getChats();
    const group = chats.find(c => c.isGroup && c.name === groupName);
    if (!group) {
      fs.unlinkSync(filePath);
      return res.status(404).json({ error: 'Group not found' });
    }
    const sent = await client.sendMessage(group.id._serialized, media, { caption: caption || '' });

    fs.unlinkSync(filePath);
    await recordMessage(userId, sessionId, group.id._serialized, 'media', caption || req.file.originalname, sent?.id?._serialized || null, 'sent');
    res.json({ status: 'success', message: `Media sent to group ${groupName}`, id: sent?.id?._serialized || null });
  } catch (err) {
    console.error('❌ /send-media-group:', err);
    res.status(500).json({ error: String(err) });
  }
});

app.post('/create-group', async (req, res) => {
  const { sessionId, groupName, participants } = req.body || {};
  if (!sessionId || !groupName || !participants) return res.status(400).json({ error: 'Missing parameters' });

  try {
    const client = clients[sessionId] || createSession(sessionId);
    await waitUntilConnected(client, 60000);

    const participantArray = participants.split(',').map(n => `${n.trim()}@c.us`);
    const { gid } = await client.createGroup(groupName, []); // return shape may vary by version

    const chatId = gid?._serialized || (gid?.user ? `${gid.user}@g.us` : gid);
    const groupChat = await client.getChatById(chatId);

    for (const member of participantArray) {
      try {
        await groupChat.addParticipants([member]);
        await new Promise(r => setTimeout(r, 1500)); // rate-limit friendly
      } catch (e) {
        console.error(`⚠️ Add failed ${member}:`, e?.message || e);
      }
    }

    res.json({ status: 'success', groupId: chatId, added: participantArray });
  } catch (err) {
    console.error('❌ /create-group:', err);
    res.status(500).json({ error: String(err) });
  }
});

app.post('/add-member', async (req, res) => {
  const { sessionId, groupName, number } = req.body || {};
  if (!sessionId || !groupName || !number) return res.status(400).json({ error: 'Missing parameters' });

  try {
    const client = clients[sessionId] || createSession(sessionId);
    await waitUntilConnected(client, 60000);

    const chats = await client.getChats();
    const group = chats.find(c => c.isGroup && c.name === groupName);
    if (!group) return res.status(404).json({ error: 'Group not found' });

    await group.addParticipants([`${number}@c.us`]);
    res.json({ status: 'success', message: 'Member added' });
  } catch (err) {
    console.error('❌ /add-member:', err);
    res.status(500).json({ error: String(err) });
  }
});

app.post('/schedule-message', async (req, res) => {
  const { sessionId, number, message, cronTime } = req.body || {};
  if (!sessionId || !number || !message || !cronTime) return res.status(400).json({ error: 'Missing parameters' });

  try {
    const client = clients[sessionId] || createSession(sessionId);
    // do not wait here; the cron job will check at send time
    const key = `${sessionId}-${number}`;

    if (scheduledJobs[key]) {
      scheduledJobs[key].stop();
      delete scheduledJobs[key];
    }

    const job = cron.schedule(cronTime, async () => {
      try {
        await waitUntilConnected(client, 60000);
        const whatsappId = number.includes('@c.us') ? number : `${number}@c.us`;
        await client.sendMessage(whatsappId, message);
        console.log(`📆 Scheduled message sent via ${sessionId} -> ${number}`);
      } catch (e) {
        console.error(`❌ Scheduled send failed ${sessionId} -> ${number}:`, e);
      }
    });

    scheduledJobs[key] = job;
    res.json({ status: 'success', message: 'Message scheduled' });
  } catch (err) {
    console.error('❌ /schedule-message:', err);
    res.status(500).json({ error: String(err) });
  }
});

// ✅ Broadcast message to multiple numbers (UI / Dashboard)
app.post('/broadcast', requireLogin, async (req, res) => {
  const { sessionId, numbers, message } = req.body || {};
  if (!sessionId || !numbers || !message) {
    return res.status(400).json({ error: "Missing parameters" });
  }

  try {
    const client = clients[sessionId] || createSession(sessionId);
    await waitUntilConnected(client, 60000);

    const numberList = numbers.split(',').map(num => num.trim()).filter(num => num);

    if (numberList.length === 0) {
      return res.status(400).json({ error: "No valid numbers provided" });
    }

    const results = [];
    for (const number of numberList) {
      try {
        const whatsappId = number.includes('@c.us') ? number : `${number}@c.us`;
        await client.sendMessage(whatsappId, message);
        results.push({ number, status: 'success' });
        console.log(`📤 Broadcast sent to ${number}`);
      } catch (err) {
        results.push({ number, status: 'failed', error: err.message });
        console.error(`❌ Failed to send to ${number}:`, err.message);
      }
    }

    const successCount = results.filter(r => r.status === 'success').length;
    const failCount = results.filter(r => r.status === 'failed').length;

    res.json({
      status: 'completed',
      message: `Broadcast completed: ${successCount} sent, ${failCount} failed`,
      results
    });
  } catch (err) {
    console.error('❌ /broadcast:', err);
    res.status(500).json({ error: err.toString() });
  }
});








// =======================
// Secured API (Swagger)
// =======================
app.use('/swagger', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// Mirrored endpoints with API key
app.post('/api/send-text', requireApiKey, async (req, res) => {
  const { sessionId, number, message } = req.body || {};
  if (!sessionId || !number || !message) return res.status(400).json({ error: 'Missing parameters' });

  try {
    const pool = await getPool();
    const key = req.headers['x-api-key'];
    const [[owner]] = await pool.query('SELECT id FROM users WHERE api_key = ? LIMIT 1', [key]);
    const [rows] = await pool.query('SELECT user_id FROM wa_sessions WHERE session_id = ? LIMIT 1', [sessionId]);
    if (!owner || !rows.length || rows[0].user_id !== owner.id) return res.status(403).json({ error: 'Session not owned' });
    const quota = await ensureQuotaAndIncrement(owner.id);
    if (!quota.allowed) return res.status(402).json({ error: 'Quota exceeded' });
    const client = clients[sessionId] || createSession(sessionId);
    await waitUntilConnected(client, 60000);

    const whatsappId = number.includes('@c.us') ? number : `${number}@c.us`;
    const sent = await client.sendMessage(whatsappId, message);
    await recordMessage(owner.id, sessionId, whatsappId, 'text', message, sent?.id?._serialized || null, 'sent');
    res.json({ status: 'success', message: 'Text sent', id: sent?.id?._serialized || null });
  } catch (err) {
    console.error('❌ /api/send-text:', err);
    res.status(500).json({ error: String(err) });
  }
});

app.post('/api/send-text-group', requireApiKey, async (req, res) => {
  const { sessionId, groupName, message } = req.body || {};
  if (!sessionId || !groupName || !message) return res.status(400).json({ error: 'Missing parameters' });

  try {
    const client = clients[sessionId] || createSession(sessionId);
    await waitUntilConnected(client, 60000);

    const chats = await client.getChats();
    const group = chats.find(c => c.isGroup && c.name === groupName);
    if (!group) return res.status(404).json({ error: 'Group not found' });

    await client.sendMessage(group.id._serialized, message);
    res.json({ status: 'success', message: 'Text sent to group' });
  } catch (err) {
    console.error('❌ /api/send-text-group:', err);
    res.status(500).json({ error: String(err) });
  }
});

app.post('/api/send-media', requireApiKey, upload.single('file'), async (req, res) => {
  const { sessionId, number, caption } = req.body || {};
  if (!req.file) return res.status(400).send('No file uploaded');
  if (!sessionId || !number) return res.status(400).send('Missing parameters');

  try {
    const pool = await getPool();
    const key = req.headers['x-api-key'];
    const [[owner]] = await pool.query('SELECT id FROM users WHERE api_key = ? LIMIT 1', [key]);
    const [rows] = await pool.query('SELECT user_id FROM wa_sessions WHERE session_id = ? LIMIT 1', [sessionId]);
    if (!owner || !rows.length || rows[0].user_id !== owner.id) return res.status(403).send('Session not owned');
    const quota = await ensureQuotaAndIncrement(owner.id);
    if (!quota.allowed) return res.status(402).send('Quota exceeded');
    const client = clients[sessionId] || createSession(sessionId);
    await waitUntilConnected(client, 60000);

    const filePath = path.join(__dirname, req.file.path);
    const mimeType = mime.lookup(filePath);
    const fileData = fs.readFileSync(filePath, { encoding: 'base64' });
    const media = new MessageMedia(mimeType, fileData, req.file.originalname);

    const whatsappId = number.includes('@c.us') ? number : `${number}@c.us`;
    const sent = await client.sendMessage(whatsappId, media, { caption: caption || '' });

    fs.unlinkSync(filePath);
    await recordMessage(owner.id, sessionId, whatsappId, 'media', caption || req.file.originalname, sent?.id?._serialized || null, 'sent');
    res.json({ status: 'success', message: '✅ Media sent!', id: sent?.id?._serialized || null });
  } catch (err) {
    console.error('❌ /api/send-media:', err);
    res.status(500).json({ error: String(err) });
  }
});

app.post('/api/send-media-group', requireApiKey, upload.single('file'), async (req, res) => {
  const { sessionId, groupName, caption } = req.body || {};
  if (!req.file) return res.status(400).send('No file uploaded');
  if (!sessionId || !groupName) return res.status(400).send('Missing parameters');

  try {
    const client = clients[sessionId] || createSession(sessionId);
    await waitUntilConnected(client, 60000);

    const filePath = path.join(__dirname, req.file.path);
    const mimeType = mime.lookup(filePath);
    const fileData = fs.readFileSync(filePath, { encoding: 'base64' });
    const media = new MessageMedia(mimeType, fileData, req.file.originalname);

    const chats = await client.getChats();
    const group = chats.find(c => c.isGroup && c.name === groupName);
    if (!group) {
      fs.unlinkSync(filePath);
      return res.status(404).send('Group not found');
    }

    await client.sendMessage(group.id._serialized, media, { caption: caption || '' });

    fs.unlinkSync(filePath);
    res.json({ status: 'success', message: `Media sent to group ${groupName}` });
  } catch (err) {
    console.error('❌ /api/send-media-group:', err);
    res.status(500).json({ error: String(err) });
  }
});

app.post('/api/create-group', requireApiKey, async (req, res) => {
  const { sessionId, groupName, participants } = req.body || {};
  if (!sessionId || !groupName || !participants) return res.status(400).json({ error: 'Missing parameters' });

  try {
    const client = clients[sessionId] || createSession(sessionId);
    await waitUntilConnected(client, 60000);

    const participantArray = participants.split(',').map(n => `${n.trim()}@c.us`);
    const { gid } = await client.createGroup(groupName, []);

    const chatId = gid?._serialized || (gid?.user ? `${gid.user}@g.us` : gid);
    const groupChat = await client.getChatById(chatId);

    for (const member of participantArray) {
      try {
        await groupChat.addParticipants([member]);
        await new Promise(r => setTimeout(r, 1500));
      } catch (e) {
        console.error(`⚠️ Add failed ${member}:`, e?.message || e);
      }
    }

    res.json({ status: 'success', groupId: chatId, added: participantArray });
  } catch (err) {
    console.error('❌ /api/create-group:', err);
    res.status(500).json({ error: String(err) });
  }
});

app.post('/api/add-member', requireApiKey, async (req, res) => {
  const { sessionId, groupName, number } = req.body || {};
  if (!sessionId || !groupName || !number) return res.status(400).json({ error: 'Missing parameters' });

  try {
    const client = clients[sessionId] || createSession(sessionId);
    await waitUntilConnected(client, 60000);

    const chats = await client.getChats();
    const group = chats.find(c => c.isGroup && c.name === groupName);
    if (!group) return res.status(404).json({ error: 'Group not found' });

    await group.addParticipants([`${number}@c.us`]);
    res.json({ status: 'success', message: 'Member added' });
  } catch (err) {
    console.error('❌ /api/add-member:', err);
    res.status(500).json({ error: String(err) });
  }
});

app.post('/api/schedule-message', requireApiKey, async (req, res) => {
  const { sessionId, number, message, cronTime } = req.body || {};
  if (!sessionId || !number || !message || !cronTime) return res.status(400).json({ error: 'Missing parameters' });

  try {
    const client = clients[sessionId] || createSession(sessionId);
    const key = `${sessionId}-${number}`;

    if (scheduledJobs[key]) {
      scheduledJobs[key].stop();
      delete scheduledJobs[key];
    }

    const job = cron.schedule(cronTime, async () => {
      try {
        await waitUntilConnected(client, 60000);
        const whatsappId = number.includes('@c.us') ? number : `${number}@c.us`;
        await client.sendMessage(whatsappId, message);
        console.log(`📆 Scheduled message sent via ${sessionId} -> ${number}`);
      } catch (e) {
        console.error(`❌ Scheduled send failed ${sessionId} -> ${number}:`, e);
      }
    });

    scheduledJobs[key] = job;
    res.json({ status: 'success', message: 'Message scheduled' });
  } catch (err) {
    console.error('❌ /api/schedule-message:', err);
    res.status(500).json({ error: String(err) });
  }
});


// ✅ Broadcast message via API key
app.post('/api/broadcast', requireApiKey, async (req, res) => {
  const { sessionId, numbers, message } = req.body || {};
  if (!sessionId || !numbers || !message) {
    return res.status(400).json({ error: "Missing parameters" });
  }

  try {
    const client = clients[sessionId] || createSession(sessionId);
    await waitUntilConnected(client, 60000);

    const numberList = numbers.split(',').map(num => num.trim()).filter(num => num);

    if (numberList.length === 0) {
      return res.status(400).json({ error: "No valid numbers provided" });
    }

    const results = [];
    for (const number of numberList) {
      try {
        const whatsappId = number.includes('@c.us') ? number : `${number}@c.us`;
        await client.sendMessage(whatsappId, message);
        results.push({ number, status: 'success' });
        console.log(`📤 Broadcast sent to ${number}`);
      } catch (err) {
        results.push({ number, status: 'failed', error: err.message });
        console.error(`❌ Failed to send to ${number}:`, err.message);
      }
    }

    const successCount = results.filter(r => r.status === 'success').length;
    const failCount = results.filter(r => r.status === 'failed').length;

    res.json({
      status: 'completed',
      message: `Broadcast completed: ${successCount} sent, ${failCount} failed`,
      results
    });
  } catch (err) {
    console.error('❌ /api/broadcast:', err);
    res.status(500).json({ error: err.toString() });
  }
});




// =======================
// Groups & contacts (public + mirrored /api/*)
// =======================
app.get('/groups/:sessionId', async (req, res) => {
  const { sessionId } = req.params;
  try {
    const client = clients[sessionId] || createSession(sessionId);
    await waitUntilConnected(client, 60000);
    const chats = await client.getChats();
    const groups = chats.filter(c => c.isGroup).map(c => c.name);
    res.json(groups);
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

app.get('/contacts/:sessionId', async (req, res) => {
  const { sessionId } = req.params;
  try {
    const client = clients[sessionId] || createSession(sessionId);
    await waitUntilConnected(client, 60000);
    const contacts = await client.getContacts();
    res.json(contacts.map(c => ({
      name: c.name || c.pushname || c.number,
      number: c.number
    })));
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

app.get('/api/groups/:sessionId', requireApiKey, async (req, res) => {
  const { sessionId } = req.params;
  try {
    const pool = await getPool();
    if (req.apiUserId) {
      const [rows] = await pool.query('SELECT user_id FROM wa_sessions WHERE session_id = ? LIMIT 1', [sessionId]);
      if (!rows.length || rows[0].user_id !== req.apiUserId) return res.status(403).json({ error: 'Session not owned' });
    }
    const client = clients[sessionId] || createSession(sessionId);
    await waitUntilConnected(client, 60000);
    const chats = await client.getChats();
    const groups = chats.filter(c => c.isGroup).map(c => c.name);
    res.json(groups);
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

app.get('/api/contacts/:sessionId', requireApiKey, async (req, res) => {
  const { sessionId } = req.params;
  try {
    const pool = await getPool();
    if (req.apiUserId) {
      const [rows] = await pool.query('SELECT user_id FROM wa_sessions WHERE session_id = ? LIMIT 1', [sessionId]);
      if (!rows.length || rows[0].user_id !== req.apiUserId) return res.status(403).json({ error: 'Session not owned' });
    }
    const client = clients[sessionId] || createSession(sessionId);
    await waitUntilConnected(client, 60000);
    const contacts = await client.getContacts();
    res.json(contacts.map(c => ({
      name: c.name || c.pushname || c.number,
      number: c.number
    })));
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

// Simple JSON docs for quick testing
app.get('/api-docs', (req, res) => {
  res.json({
    auth: 'All API calls require header: x-api-key',
    api_key: API_KEY,
    endpoints: {
      'POST /send-text': '{ sessionId, number, message }',
      'POST /send-text-group': '{ sessionId, groupName, message }',
      'POST /send-media': '{ sessionId, number, file(multipart), caption }',
      'POST /send-media-group': '{ sessionId, groupName, file(multipart), caption }',
      'POST /create-group': '{ sessionId, groupName, participants }',
      'POST /add-member': '{ sessionId, groupName, number }',
      'POST /broadcast': '{ sessionId, numbers(comma-separated), message }',
      'GET  /groups/:sessionId': 'Returns all groups',
      'GET  /contacts/:sessionId': 'Returns all contacts',
      'GET  /state/:sessionId': 'Current WA state for session'
    }
  });
});

// User quota endpoint for dashboard card
app.get('/me/quota', requireLogin, async (req, res) => {
  try {
    const pool = await getPool();
    const [rows] = await pool.query('SELECT free_limit, used_count FROM quotas WHERE user_id = ? LIMIT 1', [req.session.userId]);
    if (!rows.length) return res.json({ free_limit: 100, used_count: 0 });
    res.json(rows[0]);
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// ====== Start server ======
app.listen(PORT, async () => {
  try {
    await initSchema();
    console.log('✅ MySQL connected and schema ensured');
  } catch (e) {
    console.error('❌ MySQL init failed:', e);
  }
  console.log(`🚀 Full WhatsApp API + Dashboard running at http://localhost:${PORT}`);
});
