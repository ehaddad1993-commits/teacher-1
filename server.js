'use strict';
const express = require('express');
const { Pool } = require('pg');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.set('trust proxy', 1);

const PASSWORD = process.env.TEACHER_PASSWORD || '';
// Open editing: anyone with the link can add and change things, no password.
// To require the teacher password again, set the environment variable REQUIRE_PASSWORD=true.
const OPEN = process.env.REQUIRE_PASSWORD !== 'true';
const SECRET = process.env.SESSION_SECRET || crypto.createHash('sha256').update('fc:' + PASSWORD).digest('hex');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

/* ---------- helpers ---------- */
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
const safeEq = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));
const makeToken = () => crypto.createHmac('sha256', SECRET).update('teacher').digest('hex');
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const clip = (v, n) => String(v == null ? '' : v).trim().slice(0, n);
const okLink = (u) => !u || /^(https?:\/\/|\/files\/)/i.test(u);
const KINDS = ['log', 'homework', 'notes'];

const fails = new Map(); // ip -> {n, t}
function throttled(ip) {
  const f = fails.get(ip);
  if (!f) return false;
  if (Date.now() - f.t > 15 * 60 * 1000) { fails.delete(ip); return false; }
  return f.n >= 10;
}

function requireTeacher(req, res, next) {
  if (OPEN) return next();
  const h = req.get('authorization') || '';
  const tok = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (PASSWORD && tok && safeEq(tok, makeToken())) return next();
  res.status(401).json({ error: 'Please log in as the teacher.' });
}

const wrap = (fn) => (req, res) => fn(req, res).catch((e) => {
  console.error(e);
  res.status(500).json({ error: 'Something went wrong on the server.' });
});

/* ---------- database ---------- */
async function initDb() {
  await pool.query(`
    create table if not exists settings (key text primary key, value text not null);
    create table if not exists students (id serial primary key, name text not null);
    create table if not exists attendance (
      day date not null,
      student_id int not null references students(id) on delete cascade,
      status char(1) not null check (status in ('P','A','L')),
      primary key (day, student_id)
    );
    create table if not exists entries (
      id serial primary key,
      kind text not null check (kind in ('log','homework','notes')),
      day date,
      due date,
      title text not null default '',
      body text not null default '',
      link text not null default '',
      created_at timestamptz not null default now()
    );
    create table if not exists files (
      id text primary key,
      name text not null,
      mime text not null,
      data bytea not null,
      created_at timestamptz not null default now()
    );
  `);
}

/* ---------- public ---------- */
app.get('/healthz', (req, res) => res.send('ok'));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'app.html')));

app.get('/api/data', wrap(async (req, res) => {
  const [cn, st, at, en] = await Promise.all([
    pool.query("select value from settings where key='className'"),
    pool.query('select id, name from students order by id'),
    pool.query("select to_char(day,'YYYY-MM-DD') as d, student_id, status from attendance"),
    pool.query(`select id, kind, to_char(day,'YYYY-MM-DD') as date, to_char(due,'YYYY-MM-DD') as due, title, body, link
                from entries order by day desc nulls last, id desc`)
  ]);
  const attendance = {};
  at.rows.forEach((r) => { (attendance[r.d] = attendance[r.d] || {})[r.student_id] = r.status; });
  res.set('Cache-Control', 'no-store');
  res.json({
    open: OPEN,
    className: cn.rows[0] ? cn.rows[0].value : 'French Class',
    students: st.rows,
    attendance,
    entries: en.rows
  });
}));

const FILE_TYPES = {
  pdf: 'application/pdf', png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg',
  txt: 'text/plain; charset=utf-8', csv: 'text/csv; charset=utf-8',
  xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  xls: 'application/vnd.ms-excel',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
};

app.get('/files/:id', wrap(async (req, res) => {
  const r = await pool.query('select name, mime, data from files where id=$1', [req.params.id]);
  if (!r.rows[0]) return res.status(404).send('File not found');
  const f = r.rows[0];
  const inline = f.mime === 'application/pdf' || f.mime.startsWith('image/');
  res.set({
    'Content-Type': f.mime,
    'Content-Disposition': (inline ? 'inline' : 'attachment') + "; filename*=UTF-8''" + encodeURIComponent(f.name),
    'X-Content-Type-Options': 'nosniff',
    'Content-Security-Policy': 'sandbox',
    'Cache-Control': 'public, max-age=3600'
  });
  res.send(f.data);
}));

app.post('/api/login', express.json({ limit: '10kb' }), (req, res) => {
  if (throttled(req.ip)) return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  const given = req.body && req.body.password;
  if (PASSWORD && typeof given === 'string' && safeEq(given, PASSWORD)) {
    fails.delete(req.ip);
    return res.json({ token: makeToken() });
  }
  const f = fails.get(req.ip) || { n: 0, t: Date.now() };
  f.n += 1; f.t = Date.now();
  fails.set(req.ip, f);
  res.status(401).json({ error: 'Wrong password.' });
});

/* ---------- teacher only ---------- */
const json = express.json({ limit: '200kb' });

app.put('/api/class-name', requireTeacher, json, wrap(async (req, res) => {
  const name = clip(req.body.name, 100) || 'French Class';
  await pool.query(`insert into settings(key,value) values('className',$1)
                    on conflict (key) do update set value=excluded.value`, [name]);
  res.status(204).end();
}));

app.post('/api/students', requireTeacher, json, wrap(async (req, res) => {
  const names = (Array.isArray(req.body.names) ? req.body.names : []).map((n) => clip(n, 100)).filter(Boolean).slice(0, 200);
  for (const n of names) await pool.query('insert into students(name) values($1)', [n]);
  res.status(204).end();
}));

app.patch('/api/students/:id', requireTeacher, json, wrap(async (req, res) => {
  const name = clip(req.body.name, 100);
  if (!name) return res.status(400).json({ error: 'Name cannot be empty.' });
  await pool.query('update students set name=$1 where id=$2', [name, parseInt(req.params.id, 10) || 0]);
  res.status(204).end();
}));

app.delete('/api/students/:id', requireTeacher, wrap(async (req, res) => {
  await pool.query('delete from students where id=$1', [parseInt(req.params.id, 10) || 0]);
  res.status(204).end();
}));

app.put('/api/attendance', requireTeacher, json, wrap(async (req, res) => {
  const { date, student_id, status } = req.body || {};
  const sid = parseInt(student_id, 10);
  if (!DATE_RE.test(date || '') || !sid) return res.status(400).json({ error: 'Bad request.' });
  if (status === null || status === undefined) {
    await pool.query('delete from attendance where day=$1 and student_id=$2', [date, sid]);
  } else if (['P', 'A', 'L'].includes(status)) {
    await pool.query(`insert into attendance(day,student_id,status) values($1,$2,$3)
                      on conflict (day,student_id) do update set status=excluded.status`, [date, sid, status]);
  } else return res.status(400).json({ error: 'Bad status.' });
  res.status(204).end();
}));

app.post('/api/attendance/all-present', requireTeacher, json, wrap(async (req, res) => {
  const date = req.body && req.body.date;
  if (!DATE_RE.test(date || '')) return res.status(400).json({ error: 'Bad date.' });
  await pool.query(`insert into attendance(day,student_id,status)
                    select $1, id, 'P' from students
                    on conflict (day,student_id) do update set status='P'`, [date]);
  res.status(204).end();
}));

app.post('/api/entries', requireTeacher, json, wrap(async (req, res) => {
  const b = req.body || {};
  if (!KINDS.includes(b.kind)) return res.status(400).json({ error: 'Bad kind.' });
  const day = DATE_RE.test(b.date || '') ? b.date : null;
  const due = DATE_RE.test(b.due || '') ? b.due : null;
  const link = clip(b.link, 2000);
  if (!okLink(link)) return res.status(400).json({ error: 'Links must start with http:// or https://' });
  const title = clip(b.title, 200), body = clip(b.body, 10000);
  if (!title && !body) return res.status(400).json({ error: 'Add a title or some text.' });
  await pool.query('insert into entries(kind,day,due,title,body,link) values($1,$2,$3,$4,$5,$6)',
    [b.kind, day, due, title, body, link]);
  res.status(204).end();
}));

app.delete('/api/entries/:id', requireTeacher, wrap(async (req, res) => {
  await pool.query('delete from entries where id=$1', [parseInt(req.params.id, 10) || 0]);
  res.status(204).end();
}));

app.post('/api/upload', requireTeacher, express.raw({ type: '*/*', limit: '8mb' }), wrap(async (req, res) => {
  let name = 'file';
  try { name = decodeURIComponent(req.get('x-filename') || 'file'); } catch (e) {}
  name = name.replace(/[\r\n"\\/]/g, '_').slice(0, 150);
  const ext = (name.split('.').pop() || '').toLowerCase();
  const mime = FILE_TYPES[ext];
  if (!mime) return res.status(400).json({ error: 'File type not allowed. Use PDF, Excel, Word, PowerPoint, CSV, TXT or an image.' });
  if (!Buffer.isBuffer(req.body) || !req.body.length) return res.status(400).json({ error: 'Empty file.' });
  const id = crypto.randomBytes(12).toString('hex');
  await pool.query('insert into files(id,name,mime,data) values($1,$2,$3,$4)', [id, name, mime, req.body]);
  res.json({ url: '/files/' + id, name });
}));

/* ---------- start ---------- */
const port = process.env.PORT || 3000;
(async () => {
  for (let i = 0; i < 10; i++) {
    try { await initDb(); break; }
    catch (e) { console.error('Database not ready, retrying…', e.message); await new Promise((r) => setTimeout(r, 3000)); }
  }
  app.listen(port, '0.0.0.0', () => console.log('French class site listening on ' + port));
})();
