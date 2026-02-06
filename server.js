const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcrypt');
const multer = require('multer');
const db = require('./db');

const app = express();
const port = process.env.PORT || 3000;
const uploadDir = path.join(__dirname, 'uploads');

if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(
  session({
    store: new SQLiteStore({ db: 'sessions.db', dir: path.join(__dirname, 'data') }),
    secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: 'lax' }
  })
);

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, uploadDir);
  },
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname);
    const name = crypto.randomBytes(16).toString('hex');
    cb(null, `${name}${ext}`);
  }
});

const upload = multer({ storage });

function getCurrentUser(req) {
  if (!req.session.userId) {
    return null;
  }
  return db
    .prepare('SELECT id, email, can_upload, is_admin FROM users WHERE id = ?')
    .get(req.session.userId);
}

function requireAuth(req, res, next) {
  const user = getCurrentUser(req);
  if (!user) {
    return res.redirect('/login');
  }
  req.user = user;
  return next();
}

function requireUploader(req, res, next) {
  const user = getCurrentUser(req);
  if (!user) {
    return res.redirect('/login');
  }
  if (!user.can_upload && !user.is_admin) {
    return res.status(403).render('error', {
      user,
      message: 'У вас нет прав на загрузку.'
    });
  }
  req.user = user;
  return next();
}

function ensureAdminOrOwner(user, ownerId) {
  if (!user) return false;
  return user.is_admin || user.id === ownerId;
}

app.use((req, _res, next) => {
  req.user = getCurrentUser(req);
  next();
});

app.get('/', (req, res) => {
  if (!req.user) {
    return res.render('index', { user: null, folders: [] });
  }
  const folders = db
    .prepare('SELECT * FROM folders WHERE owner_id = ? ORDER BY created_at DESC')
    .all(req.user.id);
  return res.render('index', { user: req.user, folders });
});

app.get('/register', (_req, res) => {
  res.render('register', { error: null });
});

app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.render('register', { error: 'Укажите email и пароль.' });
  }
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) {
    return res.render('register', { error: 'Email уже зарегистрирован.' });
  }
  const passwordHash = await bcrypt.hash(password, 10);
  const isFirst = db.prepare('SELECT COUNT(*) as count FROM users').get().count === 0;
  const stmt = db.prepare(
    'INSERT INTO users (email, password_hash, can_upload, is_admin) VALUES (?, ?, ?, ?)'
  );
  stmt.run(email, passwordHash, isFirst ? 1 : 0, isFirst ? 1 : 0);
  return res.redirect('/login');
});

app.get('/login', (_req, res) => {
  res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user) {
    return res.render('login', { error: 'Неверные учетные данные.' });
  }
  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) {
    return res.render('login', { error: 'Неверные учетные данные.' });
  }
  req.session.userId = user.id;
  return res.redirect('/');
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

app.get('/admin', requireAuth, (req, res) => {
  if (!req.user.is_admin) {
    return res.status(403).render('error', { user: req.user, message: 'Доступ запрещен.' });
  }
  const users = db.prepare('SELECT id, email, can_upload, is_admin FROM users').all();
  return res.render('admin', { user: req.user, users });
});

app.post('/admin/grant', requireAuth, (req, res) => {
  if (!req.user.is_admin) {
    return res.status(403).render('error', { user: req.user, message: 'Доступ запрещен.' });
  }
  const { userId, canUpload } = req.body;
  db.prepare('UPDATE users SET can_upload = ? WHERE id = ?').run(canUpload ? 1 : 0, userId);
  return res.redirect('/admin');
});

app.get('/folders/new', requireUploader, (req, res) => {
  res.render('folder_new', { user: req.user, error: null });
});

app.post('/folders', requireUploader, (req, res) => {
  const { name } = req.body;
  if (!name) {
    return res.render('folder_new', { user: req.user, error: 'Название обязательно.' });
  }
  db.prepare('INSERT INTO folders (owner_id, name, visibility) VALUES (?, ?, ?)').run(
    req.user.id,
    name,
    'private'
  );
  return res.redirect('/');
});

app.get('/folders/:id', requireAuth, (req, res) => {
  const folder = db.prepare('SELECT * FROM folders WHERE id = ?').get(req.params.id);
  if (!folder || !ensureAdminOrOwner(req.user, folder.owner_id)) {
    return res.status(404).render('error', { user: req.user, message: 'Папка не найдена.' });
  }
  const files = db.prepare('SELECT * FROM files WHERE folder_id = ?').all(folder.id);
  return res.render('folder', { user: req.user, folder, files, req });
});

app.post('/folders/:id/visibility', requireAuth, (req, res) => {
  const folder = db.prepare('SELECT * FROM folders WHERE id = ?').get(req.params.id);
  if (!folder || !ensureAdminOrOwner(req.user, folder.owner_id)) {
    return res.status(404).render('error', { user: req.user, message: 'Папка не найдена.' });
  }
  const visibility = req.body.visibility;
  let shareToken = folder.share_token;
  if (visibility === 'link' && !shareToken) {
    shareToken = crypto.randomBytes(12).toString('hex');
  }
  if (visibility === 'private') {
    shareToken = null;
  }
  db.prepare('UPDATE folders SET visibility = ?, share_token = ? WHERE id = ?').run(
    visibility,
    shareToken,
    folder.id
  );
  return res.redirect(`/folders/${folder.id}`);
});

app.post('/folders/:id/upload', requireUploader, upload.array('files', 10), (req, res) => {
  const folder = db.prepare('SELECT * FROM folders WHERE id = ?').get(req.params.id);
  if (!folder || !ensureAdminOrOwner(req.user, folder.owner_id)) {
    return res.status(404).render('error', { user: req.user, message: 'Папка не найдена.' });
  }
  const stmt = db.prepare(
    'INSERT INTO files (folder_id, owner_id, original_name, storage_name, mime_type, size) VALUES (?, ?, ?, ?, ?, ?)'
  );
  for (const file of req.files) {
    stmt.run(folder.id, req.user.id, file.originalname, file.filename, file.mimetype, file.size);
  }
  return res.redirect(`/folders/${folder.id}`);
});

app.get('/share/:token', (req, res) => {
  const folder = db.prepare('SELECT * FROM folders WHERE share_token = ?').get(req.params.token);
  if (!folder || folder.visibility !== 'link') {
    return res.status(404).render('error', { user: req.user, message: 'Ссылка недоступна.' });
  }
  const files = db.prepare('SELECT * FROM files WHERE folder_id = ?').all(folder.id);
  return res.render('share', { user: req.user, folder, files, shareType: 'link' });
});

app.get('/public/:id', (req, res) => {
  const folder = db.prepare('SELECT * FROM folders WHERE id = ?').get(req.params.id);
  if (!folder || folder.visibility !== 'public') {
    return res.status(404).render('error', { user: req.user, message: 'Папка недоступна.' });
  }
  const files = db.prepare('SELECT * FROM files WHERE folder_id = ?').all(folder.id);
  return res.render('share', { user: req.user, folder, files, shareType: 'public' });
});

app.get('/media/:id', (req, res) => {
  const file = db.prepare('SELECT * FROM files WHERE id = ?').get(req.params.id);
  if (!file) {
    return res.status(404).render('error', { user: req.user, message: 'Файл не найден.' });
  }
  const folder = db.prepare('SELECT * FROM folders WHERE id = ?').get(file.folder_id);
  const user = getCurrentUser(req);
  const canAccessPrivate = user && ensureAdminOrOwner(user, folder.owner_id);
  if (folder.visibility === 'private' && !canAccessPrivate) {
    return res.status(403).render('error', { user, message: 'Нет доступа.' });
  }
  if (folder.visibility === 'link' && folder.share_token) {
    const token = req.query.token;
    if (!token || token !== folder.share_token) {
      return res.status(403).render('error', { user, message: 'Нет доступа.' });
    }
  }
  const filePath = path.join(uploadDir, file.storage_name);
  res.setHeader('Content-Type', file.mime_type);
  res.setHeader('Content-Disposition', `inline; filename="${file.original_name}"`);
  return fs.createReadStream(filePath).pipe(res);
});

app.listen(port, () => {
  console.log(`LolzShare running on http://localhost:${port}`);
});
