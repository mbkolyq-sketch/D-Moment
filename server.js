'use strict';
require('dotenv').config();
const path = require('path'), fs = require('fs'), crypto = require('crypto');
const express = require('express'), helmet = require('helmet'), rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken'), multer = require('multer');
const Database = require('better-sqlite3');
const { OAuth2Client } = require('google-auth-library');

const PORT = +process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;
const MIN_AGE = 13, ADULT_AGE = 18;

let JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  const f = path.join(DATA_DIR, 'jwt.secret');
  if (!fs.existsSync(f)) fs.writeFileSync(f, crypto.randomBytes(48).toString('hex'), { mode: 0o600 });
  JWT_SECRET = fs.readFileSync(f, 'utf8').trim();
}

/* ---------------- database ---------------- */
const db = new Database(path.join(DATA_DIR, 'lahzatak.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  email TEXT UNIQUE COLLATE NOCASE,
  password_hash TEXT, google_id TEXT UNIQUE,
  display_name TEXT, bio TEXT NOT NULL DEFAULT '', avatar_url TEXT,
  birth_date TEXT NOT NULL,
  is_private INTEGER NOT NULL DEFAULT 0,
  role TEXT NOT NULL DEFAULT 'user',
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS posts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  media_url TEXT NOT NULL, media_type TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  allow_comments INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'published',
  created_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE INDEX IF NOT EXISTS idx_posts_user ON posts(user_id, id);
CREATE TABLE IF NOT EXISTS hashtags(id INTEGER PRIMARY KEY AUTOINCREMENT, tag TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS post_tags(
  post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  tag_id INTEGER NOT NULL REFERENCES hashtags(id) ON DELETE CASCADE,
  PRIMARY KEY(post_id, tag_id));
CREATE TABLE IF NOT EXISTS likes(
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  PRIMARY KEY(user_id, post_id));
CREATE TABLE IF NOT EXISTS saves(
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  PRIMARY KEY(user_id, post_id));
CREATE TABLE IF NOT EXISTS shares(
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  PRIMARY KEY(user_id, post_id));
CREATE TABLE IF NOT EXISTS views(
  post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  completed INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(post_id, user_id));
CREATE TABLE IF NOT EXISTS comments(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  text TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'visible',
  created_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE INDEX IF NOT EXISTS idx_comments_post ON comments(post_id, id);
CREATE TABLE IF NOT EXISTS follows(
  follower_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  following_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'accepted',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY(follower_id, following_id), CHECK(follower_id <> following_id));
CREATE INDEX IF NOT EXISTS idx_follows_following ON follows(following_id);
CREATE TABLE IF NOT EXISTS blocks(
  blocker_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  blocked_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY(blocker_id, blocked_id));
CREATE TABLE IF NOT EXISTS stories(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  media_url TEXT NOT NULL, media_type TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS story_views(
  story_id INTEGER NOT NULL REFERENCES stories(id) ON DELETE CASCADE,
  viewer_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY(story_id, viewer_id));
CREATE TABLE IF NOT EXISTS notifications(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  actor_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
  is_read INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE INDEX IF NOT EXISTS idx_notif_user ON notifications(user_id, id);
CREATE TABLE IF NOT EXISTS reports(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  reporter_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target_type TEXT NOT NULL, target_id INTEGER NOT NULL,
  reason TEXT NOT NULL, details TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(reporter_id, target_type, target_id));
`);

/* ---------------- helpers ---------------- */
const bad = (res, code, msg) => res.status(code).json({ error: msg });
const toSql = d => d.toISOString().slice(0, 19).replace('T', ' ');
const ageOf = b => Math.floor((Date.now() - new Date(b).getTime()) / (365.25 * 864e5));
const isMinor = u => ageOf(u.birth_date) < ADULT_AGE;
const SQL_MINOR = a => `((julianday('now') - julianday(${a}.birth_date)) / 365.25 < ${ADULT_AGE})`;
const likeEsc = s => '%' + s.replace(/[\\%_]/g, m => '\\' + m) + '%';
const USERNAME_RE = /^[A-Za-z0-9_.]{3,20}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing', 10);

function parseTags(text) {
  const set = new Set();
  for (const m of text.matchAll(/#([\p{L}\p{N}_]{1,40})/gu)) { set.add(m[1].toLowerCase()); if (set.size >= 10) break; }
  return [...set];
}
function validBirth(b) {
  if (typeof b !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(b)) return null;
  const t = new Date(b + 'T00:00:00Z').getTime();
  if (Number.isNaN(t) || t > Date.now()) return null;
  const a = ageOf(b);
  return a > 120 ? null : a;
}
function userStats(id) {
  const c = (sql) => db.prepare(sql).get(id).c;
  return {
    followers: c("SELECT COUNT(*) c FROM follows WHERE following_id=? AND status='accepted'"),
    following: c("SELECT COUNT(*) c FROM follows WHERE follower_id=? AND status='accepted'"),
    posts: c("SELECT COUNT(*) c FROM posts WHERE user_id=? AND status='published'"),
    likes: c("SELECT COUNT(*) c FROM likes l JOIN posts p ON p.id=l.post_id WHERE p.user_id=? AND p.status='published'")
  };
}
const pubUser = u => ({ id: u.id, username: u.username, display_name: u.display_name || u.username, avatar_url: u.avatar_url });
const meView = u => ({ ...pubUser(u), email: u.email, bio: u.bio, is_private: !!u.is_private, role: u.role, is_minor: isMinor(u), has_password: !!u.password_hash, stats: userStats(u.id) });
const signToken = u => jwt.sign({ id: u.id }, JWT_SECRET, { expiresIn: '60d' });

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return bad(res, 401, 'يلزم تسجيل الدخول');
  try {
    const p = jwt.verify(h.slice(7), JWT_SECRET);
    const u = db.prepare('SELECT * FROM users WHERE id=?').get(p.id);
    if (!u || u.status !== 'active') return bad(res, 401, 'الحساب غير متاح');
    req.user = u; next();
  } catch (e) { return bad(res, 401, 'انتهت الجلسة، سجّل الدخول من جديد'); }
}
const adminOnly = (req, res, next) => req.user.role === 'admin' ? next() : bad(res, 403, 'غير مصرّح');

function notify(userId, actorId, type, postId = null) {
  if (userId === actorId) return;
  if (db.prepare('SELECT 1 FROM blocks WHERE blocker_id=? AND blocked_id=?').get(userId, actorId)) return;
  if (type === 'like' || type === 'follow') {
    const ex = db.prepare('SELECT 1 FROM notifications WHERE user_id=? AND actor_id=? AND type=? AND IFNULL(post_id,0)=IFNULL(?,0)').get(userId, actorId, type, postId);
    if (ex) return;
  }
  db.prepare('INSERT INTO notifications(user_id,actor_id,type,post_id) VALUES(?,?,?,?)').run(userId, actorId, type, postId);
}

/* visibility: privacy + blocks + moderation status */
const VISIBLE = `p.status='published' AND u.status='active'
 AND (u.is_private=0 OR u.id=@me OR EXISTS(SELECT 1 FROM follows f WHERE f.follower_id=@me AND f.following_id=u.id AND f.status='accepted'))
 AND NOT EXISTS(SELECT 1 FROM blocks b WHERE (b.blocker_id=@me AND b.blocked_id=u.id) OR (b.blocker_id=u.id AND b.blocked_id=@me))`;
const POST_SELECT = `SELECT p.id,p.user_id,p.media_url,p.media_type,p.description,p.allow_comments,p.created_at,
 u.username,u.display_name,u.avatar_url,
 (SELECT COUNT(*) FROM likes WHERE post_id=p.id) likes,
 (SELECT COUNT(*) FROM comments WHERE post_id=p.id AND status='visible') comments,
 (SELECT COUNT(*) FROM views WHERE post_id=p.id) views,
 (SELECT COUNT(*) FROM shares WHERE post_id=p.id) shares,
 EXISTS(SELECT 1 FROM likes WHERE post_id=p.id AND user_id=@me) liked,
 EXISTS(SELECT 1 FROM saves WHERE post_id=p.id AND user_id=@me) saved,
 EXISTS(SELECT 1 FROM follows WHERE follower_id=@me AND following_id=p.user_id AND status='accepted') following
 FROM posts p JOIN users u ON u.id=p.user_id`;
const mapPost = (r, me) => ({ ...r, display_name: r.display_name || r.username, allow_comments: !!r.allow_comments, liked: !!r.liked, saved: !!r.saved, following: !!r.following, mine: r.user_id === me });
const postsQuery = (extraWhere, params, tail, me) =>
  db.prepare(`${POST_SELECT} WHERE ${VISIBLE} ${extraWhere} ${tail}`).all({ me, ...params }).map(r => mapPost(r, me));
const getPost = (id, me) => {
  const r = db.prepare(`${POST_SELECT} WHERE p.id=@id AND ${VISIBLE}`).get({ me, id });
  return r ? mapPost(r, me) : null;
};

/* ---------------- uploads ---------------- */
const MIME_EXT = { 'video/mp4': '.mp4', 'video/webm': '.webm', 'video/quicktime': '.mov', 'video/3gpp': '.3gp', 'image/jpeg': '.jpg', 'image/png': '.png', 'image/webp': '.webp' };
function sniff(file) {
  const fd = fs.openSync(file, 'r'); const b = Buffer.alloc(16); fs.readSync(fd, b, 0, 16, 0); fs.closeSync(fd);
  if (b[0] === 0xFF && b[1] === 0xD8 && b[2] === 0xFF) return 'image/jpeg';
  if (b.subarray(0, 4).equals(Buffer.from([0x89, 0x50, 0x4E, 0x47]))) return 'image/png';
  if (b.subarray(0, 4).toString() === 'RIFF' && b.subarray(8, 12).toString() === 'WEBP') return 'image/webp';
  if (b.subarray(4, 8).toString() === 'ftyp') return 'video/ftyp';
  if (b.subarray(0, 4).equals(Buffer.from([0x1A, 0x45, 0xDF, 0xA3]))) return 'video/webm';
  return null;
}
function mediaOk(file) {
  const s = sniff(file.path); if (!s) return false;
  if (s === 'video/ftyp') return ['video/mp4', 'video/quicktime', 'video/3gpp'].includes(file.mimetype);
  return s === file.mimetype;
}
function uploader(maxMB, imagesOnly) {
  const up = multer({
    storage: multer.diskStorage({ destination: UPLOAD_DIR, filename: (req, f, cb) => cb(null, crypto.randomBytes(16).toString('hex') + MIME_EXT[f.mimetype]) }),
    limits: { fileSize: maxMB * 1024 * 1024, files: 1 },
    fileFilter: (req, f, cb) => (MIME_EXT[f.mimetype] && (!imagesOnly || f.mimetype.startsWith('image/'))) ? cb(null, true) : cb(new Error('نوع الملف غير مدعوم'))
  });
  return field => (req, res, next) => up.single(field)(req, res, err => {
    if (err) return bad(res, 400, err.code === 'LIMIT_FILE_SIZE' ? `الملف أكبر من ${maxMB}MB` : err.message);
    if (req.file && !mediaOk(req.file)) { fs.unlink(req.file.path, () => {}); return bad(res, 400, 'الملف تالف أو نوعه لا يطابق امتداده'); }
    next();
  });
}
const mediaUpload = uploader(100, false), avatarUpload = uploader(5, true);
const dropFile = url => { if (url && url.startsWith('/uploads/')) fs.unlink(path.join(UPLOAD_DIR, path.basename(url)), () => {}); };

/* ---------------- app ---------------- */
const app = express();
if (process.env.TRUST_PROXY) app.set('trust proxy', +process.env.TRUST_PROXY);
app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: false,
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", 'https://accounts.google.com'],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com', 'https://accounts.google.com'],
      fontSrc: ['https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:', 'blob:', 'https://*.googleusercontent.com'],
      mediaSrc: ["'self'", 'blob:'],
      connectSrc: ["'self'", 'https://accounts.google.com'],
      frameSrc: ['https://accounts.google.com'],
      objectSrc: ["'none'"], baseUri: ["'self'"]
    }
  },
  crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' }
}));
app.use(express.json({ limit: '50kb' }));
app.use('/api/', rateLimit({ windowMs: 15 * 60e3, limit: 900, standardHeaders: true, legacyHeaders: false, message: { error: 'طلبات كثيرة، حاول لاحقًا' } }));
const authLimiter = rateLimit({ windowMs: 15 * 60e3, limit: 30, standardHeaders: true, legacyHeaders: false, message: { error: 'محاولات كثيرة، حاول بعد قليل' } });
app.use('/uploads', express.static(UPLOAD_DIR, { maxAge: '7d', immutable: true, setHeaders: r => r.setHeader('X-Content-Type-Options', 'nosniff') }));
app.use(express.static(path.join(__dirname, 'public')));
app.get('/p/:id', (q, r) => r.sendFile(path.join(__dirname, 'public', 'index.html')));

app.get('/api/config', (q, r) => r.json({ googleClientId: GOOGLE_CLIENT_ID, minAge: MIN_AGE }));

/* ---- auth ---- */
function createUser({ username, email, hash, googleId, display, avatar, birth }) {
  const age = ageOf(birth);
  const info = db.prepare('INSERT INTO users(username,email,password_hash,google_id,display_name,avatar_url,birth_date,is_private) VALUES(?,?,?,?,?,?,?,?)')
    .run(username, email, hash || null, googleId || null, display || username, avatar || null, birth, age < ADULT_AGE ? 1 : 0);
  return db.prepare('SELECT * FROM users WHERE id=?').get(info.lastInsertRowid);
}
app.post('/api/auth/register', authLimiter, async (req, res) => {
  const { username, email, password, birth_date } = req.body || {};
  if (!USERNAME_RE.test(username || '')) return bad(res, 400, 'اسم المستخدم 3-20 حرفًا (أحرف إنجليزية وأرقام و _ و .)');
  if (!EMAIL_RE.test(email || '')) return bad(res, 400, 'بريد إلكتروني غير صالح');
  if (typeof password !== 'string' || password.length < 8 || password.length > 100) return bad(res, 400, 'كلمة المرور 8 أحرف على الأقل');
  const age = validBirth(birth_date);
  if (age === null) return bad(res, 400, 'تاريخ ميلاد غير صالح');
  if (age < MIN_AGE) return bad(res, 403, `يجب أن يكون عمرك ${MIN_AGE} سنة فأكثر`);
  if (db.prepare('SELECT 1 FROM users WHERE username=? OR email=?').get(username, email)) return bad(res, 409, 'اسم المستخدم أو البريد مستخدم مسبقًا');
  const u = createUser({ username, email, hash: await bcrypt.hash(password, 10), birth: birth_date });
  res.json({ token: signToken(u), user: meView(u) });
});
app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { identifier, password } = req.body || {};
  if (typeof identifier !== 'string' || typeof password !== 'string') return bad(res, 400, 'أدخل البيانات كاملة');
  const u = db.prepare('SELECT * FROM users WHERE email=? OR username=?').get(identifier.trim(), identifier.trim());
  const ok = await bcrypt.compare(password, (u && u.password_hash) || DUMMY_HASH);
  if (!u || !u.password_hash || !ok) return bad(res, 401, 'بيانات الدخول غير صحيحة (إذا سجّلت عبر Google استخدم زر Google)');
  if (u.status !== 'active') return bad(res, 403, 'هذا الحساب معطّل');
  res.json({ token: signToken(u), user: meView(u) });
});
app.post('/api/auth/google', authLimiter, async (req, res) => {
  if (!googleClient) return bad(res, 501, 'تسجيل Google غير مفعّل على هذا الخادم (GOOGLE_CLIENT_ID غير مضبوط)');
  const { credential, username, birth_date } = req.body || {};
  let p;
  try { p = (await googleClient.verifyIdToken({ idToken: String(credential || ''), audience: GOOGLE_CLIENT_ID })).getPayload(); }
  catch (e) { return bad(res, 401, 'تعذّر التحقق من حساب Google'); }
  if (!p.email || !p.email_verified) return bad(res, 401, 'بريد Google غير موثّق');
  let u = db.prepare('SELECT * FROM users WHERE google_id=?').get(p.sub) || db.prepare('SELECT * FROM users WHERE email=?').get(p.email);
  if (u) {
    if (u.status !== 'active') return bad(res, 403, 'هذا الحساب معطّل');
    if (!u.google_id) db.prepare('UPDATE users SET google_id=? WHERE id=?').run(p.sub, u.id);
    return res.json({ token: signToken(u), user: meView(u) });
  }
  const suggested = (p.email.split('@')[0].replace(/[^A-Za-z0-9_.]/g, '').slice(0, 14) || 'user') + crypto.randomInt(100, 999);
  if (!birth_date) return res.json({ needs_signup: true, email: p.email, suggested_username: suggested });
  const age = validBirth(birth_date);
  if (age === null) return bad(res, 400, 'تاريخ ميلاد غير صالح');
  if (age < MIN_AGE) return bad(res, 403, `يجب أن يكون عمرك ${MIN_AGE} سنة فأكثر`);
  const name = (username || suggested).trim();
  if (!USERNAME_RE.test(name)) return bad(res, 400, 'اسم المستخدم غير صالح');
  if (db.prepare('SELECT 1 FROM users WHERE username=?').get(name)) return bad(res, 409, 'اسم المستخدم مستخدم مسبقًا');
  u = createUser({ username: name, email: p.email, googleId: p.sub, display: p.name, avatar: p.picture, birth: birth_date });
  res.json({ token: signToken(u), user: meView(u) });
});

/* ---- me ---- */
app.get('/api/me', auth, (req, res) => res.json(meView(req.user)));
app.patch('/api/me', auth, avatarUpload('avatar'), (req, res) => {
  const u = req.user, b = req.body || {};
  const display = typeof b.display_name === 'string' ? b.display_name.trim().slice(0, 40) : u.display_name;
  const bio = typeof b.bio === 'string' ? b.bio.trim().slice(0, 160) : u.bio;
  let priv = b.is_private === undefined ? u.is_private : (b.is_private === '1' || b.is_private === true || b.is_private === 'true' ? 1 : 0);
  if (isMinor(u)) priv = 1; // حماية القاصرين: الحساب يبقى خاصًا
  let avatar = u.avatar_url;
  if (req.file) { dropFile(avatar); avatar = '/uploads/' + req.file.filename; }
  db.prepare('UPDATE users SET display_name=?, bio=?, is_private=?, avatar_url=? WHERE id=?').run(display || u.username, bio, priv, avatar, u.id);
  res.json(meView(db.prepare('SELECT * FROM users WHERE id=?').get(u.id)));
});
app.get('/api/me/streak', auth, (req, res) => {
  const set = new Set(db.prepare("SELECT DISTINCT date(created_at) d FROM posts WHERE user_id=? AND status='published'").all(req.user.id).map(r => r.d));
  const fmt = d => d.toISOString().slice(0, 10);
  let cur = new Date(), streak = 0;
  const today = set.has(fmt(cur));
  if (!today) cur = new Date(Date.now() - 864e5);
  while (set.has(fmt(cur))) { streak++; cur = new Date(cur.getTime() - 864e5); }
  res.json({ streak, posted_today: today });
});

/* ---- users / follow / block ---- */
const findUser = name => db.prepare("SELECT * FROM users WHERE username=? AND status='active'").get(name);
const blockedEither = (a, b) => !!db.prepare('SELECT 1 FROM blocks WHERE (blocker_id=? AND blocked_id=?) OR (blocker_id=? AND blocked_id=?)').get(a, b, b, a);
const followRow = (a, b) => db.prepare('SELECT status FROM follows WHERE follower_id=? AND following_id=?').get(a, b);

app.get('/api/users/:username', auth, (req, res) => {
  const t = findUser(req.params.username);
  if (!t || (t.id !== req.user.id && blockedEither(req.user.id, t.id))) return bad(res, 404, 'المستخدم غير موجود');
  const rel = followRow(req.user.id, t.id);
  const posts = postsQuery('AND p.user_id=@uid', { uid: t.id }, 'ORDER BY p.id DESC LIMIT 60', req.user.id);
  const canSee = !t.is_private || t.id === req.user.id || (rel && rel.status === 'accepted');
  res.json({
    user: { ...pubUser(t), bio: t.bio, is_private: !!t.is_private, stats: userStats(t.id) },
    me: t.id === req.user.id, follow: rel ? rel.status : null, locked: !canSee, posts
  });
});
function userList(req, res, col, other) {
  const t = findUser(req.params.username);
  if (!t || (t.id !== req.user.id && blockedEither(req.user.id, t.id))) return bad(res, 404, 'المستخدم غير موجود');
  const rel = followRow(req.user.id, t.id);
  if (t.is_private && t.id !== req.user.id && !(rel && rel.status === 'accepted')) return bad(res, 403, 'الحساب خاص');
  const rows = db.prepare(`SELECT u.id,u.username,u.display_name,u.avatar_url FROM follows f JOIN users u ON u.id=f.${other}
    WHERE f.${col}=? AND f.status='accepted' AND u.status='active' ORDER BY f.created_at DESC LIMIT 200`).all(t.id);
  res.json(rows.map(pubUser));
}
app.get('/api/users/:username/followers', auth, (q, r) => userList(q, r, 'following_id', 'follower_id'));
app.get('/api/users/:username/following', auth, (q, r) => userList(q, r, 'follower_id', 'following_id'));
app.post('/api/users/:username/follow', auth, (req, res) => {
  const t = findUser(req.params.username);
  if (!t || t.id === req.user.id || blockedEither(req.user.id, t.id)) return bad(res, 404, 'المستخدم غير موجود');
  const status = (t.is_private || isMinor(t)) ? 'pending' : 'accepted';
  const r = db.prepare('INSERT OR IGNORE INTO follows(follower_id,following_id,status) VALUES(?,?,?)').run(req.user.id, t.id, status);
  if (r.changes) notify(t.id, req.user.id, status === 'pending' ? 'follow_request' : 'follow');
  res.json({ follow: followRow(req.user.id, t.id).status, stats: userStats(t.id) });
});
app.delete('/api/users/:username/follow', auth, (req, res) => {
  const t = findUser(req.params.username); if (!t) return bad(res, 404, 'المستخدم غير موجود');
  db.prepare('DELETE FROM follows WHERE follower_id=? AND following_id=?').run(req.user.id, t.id);
  res.json({ follow: null, stats: userStats(t.id) });
});
app.get('/api/follow-requests', auth, (req, res) => res.json(db.prepare(
  "SELECT u.id,u.username,u.display_name,u.avatar_url FROM follows f JOIN users u ON u.id=f.follower_id WHERE f.following_id=? AND f.status='pending' AND u.status='active'").all(req.user.id).map(pubUser)));
app.post('/api/follow-requests/:id/:action', auth, (req, res) => {
  const fid = +req.params.id;
  if (req.params.action === 'accept') {
    const r = db.prepare("UPDATE follows SET status='accepted' WHERE follower_id=? AND following_id=? AND status='pending'").run(fid, req.user.id);
    if (r.changes) notify(fid, req.user.id, 'follow_accepted');
  } else if (req.params.action === 'reject') {
    db.prepare("DELETE FROM follows WHERE follower_id=? AND following_id=? AND status='pending'").run(fid, req.user.id);
  } else return bad(res, 400, 'إجراء غير صالح');
  res.json({ ok: true });
});
app.post('/api/users/:username/block', auth, (req, res) => {
  const t = findUser(req.params.username);
  if (!t || t.id === req.user.id) return bad(res, 404, 'المستخدم غير موجود');
  db.transaction(() => {
    db.prepare('INSERT OR IGNORE INTO blocks(blocker_id,blocked_id) VALUES(?,?)').run(req.user.id, t.id);
    db.prepare('DELETE FROM follows WHERE (follower_id=? AND following_id=?) OR (follower_id=? AND following_id=?)').run(req.user.id, t.id, t.id, req.user.id);
  })();
  res.json({ ok: true });
});
app.delete('/api/users/:username/block', auth, (req, res) => {
  const t = db.prepare('SELECT id FROM users WHERE username=?').get(req.params.username);
  if (t) db.prepare('DELETE FROM blocks WHERE blocker_id=? AND blocked_id=?').run(req.user.id, t.id);
  res.json({ ok: true });
});
app.get('/api/blocks', auth, (req, res) => res.json(db.prepare(
  'SELECT u.id,u.username,u.display_name,u.avatar_url FROM blocks b JOIN users u ON u.id=b.blocked_id WHERE b.blocker_id=?').all(req.user.id).map(pubUser)));

/* ---- posts ---- */
app.get('/api/feed', auth, (req, res) => {
  const cursor = +req.query.cursor || null, LIMIT = 8;
  const items = postsQuery('AND (@cursor IS NULL OR p.id < @cursor)', { cursor }, `ORDER BY p.id DESC LIMIT ${LIMIT}`, req.user.id);
  res.json({ items, next: items.length === LIMIT ? items[items.length - 1].id : null });
});
app.get('/api/random', auth, (req, res) => {
  const items = postsQuery('', {}, 'ORDER BY RANDOM() LIMIT 1', req.user.id);
  res.json(items[0] || null);
});
app.get('/api/saved', auth, (req, res) => res.json(postsQuery(
  'AND EXISTS(SELECT 1 FROM saves s WHERE s.post_id=p.id AND s.user_id=@me)', {}, 'ORDER BY p.id DESC LIMIT 60', req.user.id)));
app.get('/api/posts/:id', auth, (req, res) => {
  const p = getPost(+req.params.id, req.user.id);
  return p ? res.json(p) : bad(res, 404, 'المنشور غير متاح');
});
app.post('/api/posts', auth, mediaUpload('media'), (req, res) => {
  if (!req.file) return bad(res, 400, 'اختر صورة أو فيديو');
  const recent = db.prepare("SELECT COUNT(*) c FROM posts WHERE user_id=? AND created_at > datetime('now','-1 hour')").get(req.user.id).c;
  if (recent >= 20) { fs.unlink(req.file.path, () => {}); return bad(res, 429, 'وصلت الحد الأقصى للنشر في الساعة'); }
  const desc = String((req.body || {}).description || '').trim().slice(0, 500);
  const allow = (req.body || {}).allow_comments === '0' ? 0 : 1;
  const type = req.file.mimetype.startsWith('image/') ? 'image' : 'video';
  const id = db.transaction(() => {
    const pid = db.prepare('INSERT INTO posts(user_id,media_url,media_type,description,allow_comments) VALUES(?,?,?,?,?)')
      .run(req.user.id, '/uploads/' + req.file.filename, type, desc, allow).lastInsertRowid;
    for (const t of parseTags(desc)) {
      db.prepare('INSERT OR IGNORE INTO hashtags(tag) VALUES(?)').run(t);
      db.prepare('INSERT OR IGNORE INTO post_tags(post_id,tag_id) SELECT ?, id FROM hashtags WHERE tag=?').run(pid, t);
    }
    return Number(pid);
  })();
  res.json(getPost(id, req.user.id));
});
app.delete('/api/posts/:id', auth, (req, res) => {
  const p = db.prepare('SELECT * FROM posts WHERE id=?').get(+req.params.id);
  if (!p) return bad(res, 404, 'غير موجود');
  if (p.user_id !== req.user.id && req.user.role !== 'admin') return bad(res, 403, 'غير مصرّح');
  db.prepare('DELETE FROM posts WHERE id=?').run(p.id); dropFile(p.media_url);
  res.json({ ok: true });
});
const needPost = (req, res) => { const p = getPost(+req.params.id, req.user.id); if (!p) bad(res, 404, 'المنشور غير متاح'); return p; };
app.post('/api/posts/:id/view', auth, (req, res) => {
  const p = needPost(req, res); if (!p) return;
  db.prepare('INSERT INTO views(post_id,user_id,completed) VALUES(?,?,?) ON CONFLICT(post_id,user_id) DO UPDATE SET completed=MAX(completed,excluded.completed)')
    .run(p.id, req.user.id, (req.body || {}).completed ? 1 : 0);
  res.json({ ok: true });
});
function toggle(table, notifType) {
  return [
    (req, res) => {
      const p = needPost(req, res); if (!p) return;
      const r = db.prepare(`INSERT OR IGNORE INTO ${table}(user_id,post_id) VALUES(?,?)`).run(req.user.id, p.id);
      if (r.changes && notifType) notify(p.user_id, req.user.id, notifType, p.id);
      res.json(getPost(p.id, req.user.id));
    },
    (req, res) => {
      const p = needPost(req, res); if (!p) return;
      db.prepare(`DELETE FROM ${table} WHERE user_id=? AND post_id=?`).run(req.user.id, p.id);
      res.json(getPost(p.id, req.user.id));
    }];
}
const [likeAdd, likeDel] = toggle('likes', 'like'), [saveAdd, saveDel] = toggle('saves', null);
app.post('/api/posts/:id/like', auth, likeAdd); app.delete('/api/posts/:id/like', auth, likeDel);
app.post('/api/posts/:id/save', auth, saveAdd); app.delete('/api/posts/:id/save', auth, saveDel);
app.post('/api/posts/:id/share', auth, (req, res) => {
  const p = needPost(req, res); if (!p) return;
  db.prepare('INSERT OR IGNORE INTO shares(user_id,post_id) VALUES(?,?)').run(req.user.id, p.id);
  res.json(getPost(p.id, req.user.id));
});

/* ---- comments ---- */
app.get('/api/posts/:id/comments', auth, (req, res) => {
  const p = needPost(req, res); if (!p) return;
  const rows = db.prepare(`SELECT c.id,c.text,c.created_at,c.user_id,u.username,u.display_name,u.avatar_url FROM comments c JOIN users u ON u.id=c.user_id
    WHERE c.post_id=? AND c.status='visible' AND u.status='active'
    AND NOT EXISTS(SELECT 1 FROM blocks b WHERE (b.blocker_id=? AND b.blocked_id=u.id) OR (b.blocker_id=u.id AND b.blocked_id=?))
    ORDER BY c.id ASC LIMIT 200`).all(p.id, req.user.id, req.user.id);
  res.json({ items: rows.map(r => ({ ...r, display_name: r.display_name || r.username, mine: r.user_id === req.user.id })), can_delete_all: p.mine });
});
app.post('/api/posts/:id/comments', auth, (req, res) => {
  const p = needPost(req, res); if (!p) return;
  const text = String((req.body || {}).text || '').trim().slice(0, 300);
  if (!text) return bad(res, 400, 'اكتب تعليقًا');
  if (!p.allow_comments) return bad(res, 403, 'التعليقات مغلقة على هذا المنشور');
  const owner = db.prepare('SELECT * FROM users WHERE id=?').get(p.user_id);
  if (!p.mine && isMinor(owner)) {
    const rel = followRow(req.user.id, owner.id);
    if (!(rel && rel.status === 'accepted')) return bad(res, 403, 'التعليق متاح للمتابعين فقط على حسابات القاصرين');
  }
  const burst = db.prepare("SELECT COUNT(*) c FROM comments WHERE user_id=? AND created_at > datetime('now','-10 minutes')").get(req.user.id).c;
  if (burst >= 20) return bad(res, 429, 'تعليقات كثيرة، انتظر قليلًا');
  if (db.prepare("SELECT 1 FROM comments WHERE user_id=? AND text=? AND created_at > datetime('now','-1 minute')").get(req.user.id, text)) return bad(res, 429, 'تعليق مكرر');
  const id = db.prepare('INSERT INTO comments(post_id,user_id,text) VALUES(?,?,?)').run(p.id, req.user.id, text).lastInsertRowid;
  notify(p.user_id, req.user.id, 'comment', p.id);
  const seen = new Set([p.user_id, req.user.id]);
  for (const m of text.matchAll(/@([A-Za-z0-9_.]{3,20})/g)) {
    const mu = findUser(m[1]);
    if (mu && !seen.has(mu.id) && !blockedEither(req.user.id, mu.id)) { seen.add(mu.id); notify(mu.id, req.user.id, 'mention', p.id); }
    if (seen.size > 6) break;
  }
  res.json({ id: Number(id), text, created_at: toSql(new Date()), user_id: req.user.id, username: req.user.username,
    display_name: req.user.display_name || req.user.username, avatar_url: req.user.avatar_url, mine: true });
});
app.delete('/api/comments/:id', auth, (req, res) => {
  const c = db.prepare('SELECT c.*, p.user_id owner FROM comments c JOIN posts p ON p.id=c.post_id WHERE c.id=?').get(+req.params.id);
  if (!c) return bad(res, 404, 'غير موجود');
  if (c.user_id !== req.user.id && c.owner !== req.user.id && req.user.role !== 'admin') return bad(res, 403, 'غير مصرّح');
  db.prepare("UPDATE comments SET status='removed' WHERE id=?").run(c.id);
  res.json({ ok: true });
});

/* ---- search / hashtags ---- */
app.get('/api/search', auth, (req, res) => {
  const raw = String(req.query.q || '').trim().replace(/^[#@]/, '').slice(0, 50);
  const type = req.query.type;
  if (!raw) return res.json([]);
  const q = likeEsc(raw), me = req.user.id;
  if (type === 'users') {
    const rows = db.prepare(`SELECT u.id,u.username,u.display_name,u.avatar_url,
      (SELECT status FROM follows WHERE follower_id=@me AND following_id=u.id) follow FROM users u
      WHERE u.status='active' AND u.id<>@me AND (u.username LIKE @q ESCAPE '\\' OR u.display_name LIKE @q ESCAPE '\\')
      AND NOT EXISTS(SELECT 1 FROM blocks b WHERE (b.blocker_id=@me AND b.blocked_id=u.id) OR (b.blocker_id=u.id AND b.blocked_id=@me))
      AND (NOT ${SQL_MINOR('u')} OR EXISTS(SELECT 1 FROM follows f WHERE f.follower_id=@me AND f.following_id=u.id AND f.status='accepted'))
      ORDER BY (u.username LIKE @exact) DESC, u.username LIMIT 30`).all({ me, q, exact: likeEsc(raw).slice(1) });
    return res.json(rows.map(r => ({ ...pubUser(r), follow: r.follow || null })));
  }
  if (type === 'hashtags') {
    return res.json(db.prepare(`SELECT h.tag, COUNT(*) count FROM hashtags h JOIN post_tags pt ON pt.tag_id=h.id JOIN posts p ON p.id=pt.post_id JOIN users u ON u.id=p.user_id
      WHERE h.tag LIKE @q ESCAPE '\\' AND p.status='published' AND u.status='active' AND u.is_private=0 GROUP BY h.id ORDER BY count DESC LIMIT 30`).all({ q }));
  }
  res.json(postsQuery("AND p.description LIKE @q ESCAPE '\\'", { q }, 'ORDER BY p.id DESC LIMIT 60', me));
});
app.get('/api/hashtags/trending', auth, (req, res) => res.json(db.prepare(
  `SELECT h.tag, COUNT(*) count FROM hashtags h JOIN post_tags pt ON pt.tag_id=h.id JOIN posts p ON p.id=pt.post_id JOIN users u ON u.id=p.user_id
   WHERE p.status='published' AND u.status='active' AND u.is_private=0 AND p.created_at > datetime('now','-7 days')
   GROUP BY h.id ORDER BY count DESC LIMIT 10`).all()));
app.get('/api/hashtags/:tag/posts', auth, (req, res) => res.json(postsQuery(
  'AND EXISTS(SELECT 1 FROM post_tags pt JOIN hashtags h ON h.id=pt.tag_id WHERE pt.post_id=p.id AND h.tag=@tag)',
  { tag: String(req.params.tag).toLowerCase() }, 'ORDER BY p.id DESC LIMIT 60', req.user.id)));

/* ---- stories ---- */
app.post('/api/stories', auth, mediaUpload('media'), (req, res) => {
  if (!req.file) return bad(res, 400, 'اختر صورة أو فيديو');
  const n = db.prepare("SELECT COUNT(*) c FROM stories WHERE user_id=? AND created_at > datetime('now','-1 day')").get(req.user.id).c;
  if (n >= 30) { fs.unlink(req.file.path, () => {}); return bad(res, 429, 'وصلت الحد اليومي للقصص'); }
  const type = req.file.mimetype.startsWith('image/') ? 'image' : 'video';
  db.prepare('INSERT INTO stories(user_id,media_url,media_type,expires_at) VALUES(?,?,?,?)')
    .run(req.user.id, '/uploads/' + req.file.filename, type, toSql(new Date(Date.now() + 864e5)));
  res.json({ ok: true });
});
app.get('/api/stories', auth, (req, res) => {
  const me = req.user.id;
  const rows = db.prepare(`SELECT s.id,s.user_id,s.media_url,s.media_type,s.created_at,u.username,u.display_name,u.avatar_url,
    EXISTS(SELECT 1 FROM story_views v WHERE v.story_id=s.id AND v.viewer_id=@me) seen
    FROM stories s JOIN users u ON u.id=s.user_id
    WHERE s.expires_at > datetime('now') AND u.status='active'
    AND (u.id=@me OR EXISTS(SELECT 1 FROM follows f WHERE f.follower_id=@me AND f.following_id=u.id AND f.status='accepted'))
    AND NOT EXISTS(SELECT 1 FROM blocks b WHERE (b.blocker_id=@me AND b.blocked_id=u.id) OR (b.blocker_id=u.id AND b.blocked_id=@me))
    ORDER BY s.id ASC`).all({ me });
  const groups = new Map();
  for (const r of rows) {
    if (!groups.has(r.user_id)) groups.set(r.user_id, { user: pubUser(r), mine: r.user_id === me, stories: [] });
    groups.get(r.user_id).stories.push({ id: r.id, media_url: r.media_url, media_type: r.media_type, created_at: r.created_at, seen: !!r.seen });
  }
  const out = [...groups.values()].map(g => ({ ...g, all_seen: g.stories.every(s => s.seen) }));
  out.sort((a, b) => (b.mine - a.mine) || (a.all_seen - b.all_seen));
  res.json(out);
});
app.post('/api/stories/:id/view', auth, (req, res) => {
  db.prepare("INSERT OR IGNORE INTO story_views(story_id,viewer_id) SELECT s.id, ? FROM stories s WHERE s.id=? AND s.expires_at > datetime('now')").run(req.user.id, +req.params.id);
  res.json({ ok: true });
});

/* ---- notifications ---- */
app.get('/api/notifications', auth, (req, res) => {
  const rows = db.prepare(`SELECT n.id,n.type,n.post_id,n.is_read,n.created_at,u.username,u.display_name,u.avatar_url FROM notifications n
    LEFT JOIN users u ON u.id=n.actor_id WHERE n.user_id=? ORDER BY n.id DESC LIMIT 60`).all(req.user.id);
  res.json(rows.map(r => ({ ...r, is_read: !!r.is_read, display_name: r.display_name || r.username })));
});
app.get('/api/notifications/unread', auth, (req, res) =>
  res.json({ count: db.prepare('SELECT COUNT(*) c FROM notifications WHERE user_id=? AND is_read=0').get(req.user.id).c }));
app.post('/api/notifications/read', auth, (req, res) => { db.prepare('UPDATE notifications SET is_read=1 WHERE user_id=?').run(req.user.id); res.json({ ok: true }); });

/* ---- reports / moderation ---- */
const REASONS = ['inappropriate', 'harassment', 'impersonation', 'fraud', 'copyright', 'minor_safety', 'spam', 'other'];
const TARGETS = { post: 'posts', comment: 'comments', user: 'users', story: 'stories' };
app.post('/api/reports', auth, (req, res) => {
  const { target_type, target_id, reason, details } = req.body || {};
  if (!TARGETS[target_type] || !REASONS.includes(reason)) return bad(res, 400, 'بيانات البلاغ غير صالحة');
  const tid = +target_id;
  if (!db.prepare(`SELECT 1 FROM ${TARGETS[target_type]} WHERE id=?`).get(tid)) return bad(res, 404, 'المحتوى غير موجود');
  const r = db.prepare('INSERT OR IGNORE INTO reports(reporter_id,target_type,target_id,reason,details) VALUES(?,?,?,?,?)')
    .run(req.user.id, target_type, tid, reason, String(details || '').slice(0, 500));
  if (r.changes && (target_type === 'post' || target_type === 'comment')) {
    const n = db.prepare("SELECT COUNT(*) c FROM reports WHERE target_type=? AND target_id=? AND status='pending'").get(target_type, tid).c;
    if (n >= (reason === 'minor_safety' ? 1 : 3)) { // إخفاء احترازي بانتظار مراجعة المشرف
      if (target_type === 'post') db.prepare("UPDATE posts SET status='under_review' WHERE id=? AND status='published'").run(tid);
      else db.prepare("UPDATE comments SET status='under_review' WHERE id=? AND status='visible'").run(tid);
    }
  }
  res.json({ ok: true });
});
app.get('/api/admin/stats', auth, adminOnly, (req, res) => {
  const c = t => db.prepare(`SELECT COUNT(*) c FROM ${t}`).get().c;
  res.json({ users: c('users'), posts: c('posts'), comments: c('comments'), pending_reports: db.prepare("SELECT COUNT(*) c FROM reports WHERE status='pending'").get().c });
});
app.get('/api/admin/reports', auth, adminOnly, (req, res) => {
  const rows = db.prepare(`SELECT r.*, u.username reporter FROM reports r JOIN users u ON u.id=r.reporter_id WHERE r.status='pending' ORDER BY r.id ASC LIMIT 50`).all();
  res.json(rows.map(r => {
    let preview = '';
    if (r.target_type === 'post') { const p = db.prepare('SELECT description,media_url FROM posts WHERE id=?').get(r.target_id); preview = p ? `${p.description} ${p.media_url}` : '(محذوف)'; }
    else if (r.target_type === 'comment') { const c = db.prepare('SELECT text FROM comments WHERE id=?').get(r.target_id); preview = c ? c.text : '(محذوف)'; }
    else if (r.target_type === 'user') { const u = db.prepare('SELECT username FROM users WHERE id=?').get(r.target_id); preview = u ? '@' + u.username : '(محذوف)'; }
    return { ...r, preview };
  }));
});
app.post('/api/admin/reports/:id/resolve', auth, adminOnly, (req, res) => {
  const r = db.prepare('SELECT * FROM reports WHERE id=?').get(+req.params.id);
  const action = (req.body || {}).action;
  if (!r || !['dismiss', 'remove'].includes(action)) return bad(res, 400, 'طلب غير صالح');
  db.transaction(() => {
    if (action === 'dismiss') {
      if (r.target_type === 'post') db.prepare("UPDATE posts SET status='published' WHERE id=? AND status='under_review'").run(r.target_id);
      if (r.target_type === 'comment') db.prepare("UPDATE comments SET status='visible' WHERE id=? AND status='under_review'").run(r.target_id);
    } else if (r.target_type === 'post') db.prepare("UPDATE posts SET status='removed' WHERE id=?").run(r.target_id);
    else if (r.target_type === 'comment') db.prepare("UPDATE comments SET status='removed' WHERE id=?").run(r.target_id);
    else if (r.target_type === 'story') db.prepare('DELETE FROM stories WHERE id=?').run(r.target_id);
    else if (r.target_type === 'user') db.prepare("UPDATE users SET status='disabled' WHERE id=? AND role<>'admin'").run(r.target_id);
    db.prepare("UPDATE reports SET status=? WHERE target_type=? AND target_id=? AND status='pending'").run(action === 'dismiss' ? 'dismissed' : 'actioned', r.target_type, r.target_id);
  })();
  res.json({ ok: true });
});

app.use('/api', (q, r) => bad(r, 404, 'مسار غير موجود'));
app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: 'خطأ في الخادم' }); });

/* ---- cleanup: expired stories ---- */
function cleanup() {
  const old = db.prepare("SELECT id,media_url FROM stories WHERE expires_at <= datetime('now')").all();
  for (const s of old) { db.prepare('DELETE FROM stories WHERE id=?').run(s.id); dropFile(s.media_url); }
}
cleanup(); setInterval(cleanup, 60 * 60e3).unref();

app.listen(PORT, () => console.log(`لحظتك تعمل على http://localhost:${PORT}`));
