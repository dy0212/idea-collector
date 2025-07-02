require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');

const app = express();
const db = new sqlite3.Database('./db.sqlite');

app.use(cors({
  origin: process.env.CLIENT_ORIGIN || 'http://localhost:3000',
  credentials: true
}));
app.use(express.json());
app.use(session({
  store: new SQLiteStore({ db: 'sessions.sqlite' }),
  secret: process.env.SESSION_SECRET || 'default_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true }
}));

// ✅ 이메일 전송 설정 (gmail 기준)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASS
  }
});

// ✅ DB 초기화
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    passwordHash TEXT,
    email TEXT UNIQUE,
    verified INTEGER DEFAULT 0,
    role TEXT DEFAULT 'user'
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS ideas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    description TEXT,
    date TEXT,
    userId INTEGER,
    FOREIGN KEY(userId) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS verifications (
    id TEXT PRIMARY KEY,
    email TEXT,
    code TEXT
  )`);

  // ✅ 초기 superadmin 계정 (이메일 인증 제외)
  db.get(`SELECT * FROM users WHERE username = 'siasia212@gmail.com'`, (err, row) => {
    if (!row) {
      bcrypt.hash('ehdduf0625!@#', 10, (err, hash) => {
        db.run(`INSERT INTO users (username, passwordHash, email, verified, role)
                VALUES (?, ?, ?, 1, 'superadmin')`,
                ['siasia212@gmail.com', hash, 'siasia212@gmail.com']);
      });
    }
  });
});

// ✅ 회원가입 (개인정보 동의 + 이메일 인증)
app.post('/register', async (req, res) => {
  const { username, password, agree } = req.body;
  const email = username;

  if (!agree) return res.status(400).json({ error: '개인정보 수집에 동의해야 합니다.' });

  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, row) => {
    if (row) return res.status(400).json({ error: '이미 존재하는 사용자입니다.' });
    const hash = await bcrypt.hash(password, 10);
    const code = uuidv4().slice(0, 6).toUpperCase();

    // 이메일 인증코드 저장
    const id = uuidv4();
    db.run(`INSERT INTO verifications (id, email, code) VALUES (?, ?, ?)`, [id, email, code]);

    // 메일 전송
    await transporter.sendMail({
      from: process.env.MAIL_USER,
      to: email,
      subject: '[아이디어 묘지] 이메일 인증코드',
      text: `인증코드는 다음과 같습니다: ${code}`
    });

    res.json({ verifyId: id, message: '인증 메일이 전송되었습니다.' });
  });
});

// ✅ 인증 코드 확인 후 회원 생성
app.post('/verify', async (req, res) => {
  const { verifyId, code, username, password } = req.body;

  db.get(`SELECT * FROM verifications WHERE id = ? AND code = ?`, [verifyId, code], async (err, row) => {
    if (!row) return res.status(400).json({ error: '인증 실패' });

    const hash = await bcrypt.hash(password, 10);
    db.run(`INSERT INTO users (username, passwordHash, email, verified)
            VALUES (?, ?, ?, 1)`, [username, hash, username], function(err) {
      if (err) return res.status(500).json({ error: '계정 생성 실패' });

      db.run(`DELETE FROM verifications WHERE id = ?`, [verifyId]);
      res.json({ success: true });
    });
  });
});

// ✅ 로그인
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).json({ error: '로그인 실패' });
    }
    if (!user.verified) return res.status(403).json({ error: '이메일 인증이 필요합니다.' });

    req.session.user = { id: user.id, username: user.username, role: user.role };
    res.json({ success: true });
  });
});

// ✅ 로그아웃
app.post('/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

// ✅ 현재 로그인 사용자 정보
app.get('/me', (req, res) => {
  if (!req.session.user) return res.status(401).end();
  res.set('Cache-Control', 'no-store');
  res.json(req.session.user);
});

// ✅ 사용자 목록
app.get('/users', (req, res) => {
  const currentUser = req.session.user;
  if (!currentUser || (currentUser.role !== 'admin' && currentUser.role !== 'superadmin')) {
    return res.status(403).json({ error: '권한 없음' });
  }
  db.all(`SELECT id, username, role FROM users`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: '조회 실패' });
    res.json(rows);
  });
});

// ✅ 권한 변경 (superadmin만)
app.put('/users/:id/role', (req, res) => {
  const currentUser = req.session.user;
  if (!currentUser || currentUser.role !== 'superadmin') {
    return res.status(403).json({ error: '권한 없음' });
  }

  const userId = req.params.id;
  db.get(`SELECT role FROM users WHERE id = ?`, [userId], (err, row) => {
    if (err || !row) return res.status(404).json({ error: '사용자 없음' });
    const newRole = row.role === 'admin' ? 'user' : 'admin';
    db.run(`UPDATE users SET role = ? WHERE id = ?`, [newRole, userId], function(err) {
      if (err) return res.status(500).json({ error: '업데이트 실패' });
      res.json({ success: true, newRole });
    });
  });
});

// ✅ 사용자 삭제
app.delete('/users/:id', (req, res) => {
  const currentUser = req.session.user;
  if (!currentUser || (currentUser.role !== 'admin' && currentUser.role !== 'superadmin')) {
    return res.status(403).json({ error: '권한 없음' });
  }
  db.run(`DELETE FROM users WHERE id = ?`, [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: '삭제 실패' });
    res.json({ success: true });
  });
});

// ✅ 아이디어 목록 조회 (작성자 포함)
app.get('/ideas', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: '로그인이 필요합니다.' });
  db.all(`
    SELECT ideas.id, ideas.title, ideas.description, ideas.date, ideas.userId, users.username AS author
    FROM ideas
    LEFT JOIN users ON ideas.userId = users.id
  `, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB 조회 실패' });

    // 프론트가 기대하는 구조로 변환
    const ideas = rows.map(idea => ({
      id: idea.id,
      title: idea.title,
      description: idea.description,
      date: idea.date,
      userId: idea.userId,
      user: { username: idea.author }
    }));
    res.json(ideas);
  });
});

// ✅ 아이디어 저장
app.post('/ideas', (req, res) => {
  if (!req.session.user) return res.status(401).end();
  const { title, description } = req.body;
  const date = new Date().toISOString();
  db.run(`INSERT INTO ideas (title, description, date, userId) VALUES (?, ?, ?, ?)`,
    [title, description, date, req.session.user.id],
    function(err) {
      if (err) return res.status(500).json({ error: '저장 실패' });
      res.json({ success: true });
    });
});

// ✅ 아이디어 삭제
app.delete('/ideas/:id', (req, res) => {
  if (!req.session.user || (req.session.user.role !== 'admin' && req.session.user.role !== 'superadmin')) {
    return res.status(403).end();
  }
  db.run(`DELETE FROM ideas WHERE id = ?`, [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: '삭제 실패' });
    res.json({ success: true });
  });
});

// ✅ 서버 실행
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on http://localhost:${PORT}`));
