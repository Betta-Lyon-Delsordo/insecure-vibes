const express = require('express');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const expressLayouts = require('express-ejs-layouts');

const db = require('./db');
const auth = require('./auth');
const utils = require('./utils');

const app = express();
const BASE_DIR = __dirname;
app.set('views', path.join(BASE_DIR, 'views'));
app.set('view engine', 'ejs');
app.use(expressLayouts);
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(BASE_DIR, 'static')));

app.use(session({
  secret: 'dev-secret-key', // development secret key
  resave: false,
  saveUninitialized: true
}));

const uploadFolder = path.join(BASE_DIR, 'uploads');
if (!fs.existsSync(uploadFolder)) fs.mkdirSync(uploadFolder, { recursive: true });

const upload = multer({ storage: multer.memoryStorage() });

app.get('/', (req, res) => {
  res.render('index', { username: req.session.username });
});

app.get('/initdb', async (req, res) => {
  await db.init_db();
  // Add a couple of demo users to start quickly! 🚀🚀🚀
  await auth.add_user('alice', 'password123');
  await auth.add_user('bob', 'hunter2');
  res.send('Database initialized with demo users.');
});

app.get('/search', async (req, res) => {
  const query = req.query.q || '';
  const results = await db.search_users(query);
  res.render('search', { results, query });
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', express.urlencoded({ extended: true }), async (req, res) => {
  const username = req.body.username || '';
  const password = req.body.password || '';
  const ok = await auth.check_login(username, password);
  if (ok) {
    req.session.username = username;
    return res.redirect('/');
  }
  res.status(401).send('Login failed');
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {});
  res.render('logout');
});


app.get('/secret', (req, res) => {
  // Secret page for more important info
  res.render('secret');
});

app.get('/upload', (req, res) => {
  res.render('upload');
});

app.post('/upload', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).send('No file uploaded');
  const filename = req.file.originalname;
  utils.save_upload(filename, req.file.buffer, uploadFolder);
  res.redirect(`/uploads/${encodeURIComponent(filename)}`);
});

app.get('/uploads/:filename', (req, res) => {
  const filename = req.params.filename;
  const filePath = path.join(uploadFolder, filename);
  if (!fs.existsSync(filePath)) return res.status(404).send('Not found');
  try {
    const content = fs.readFileSync(filePath, { encoding: 'utf8' });
    res.send(content);
  } catch (e) {
    res.status(500).send('Error reading file');
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
