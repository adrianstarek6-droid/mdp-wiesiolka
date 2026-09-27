const express = require("express");
const path = require("path");
const { Pool } = require("pg");

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const PORT = process.env.PORT || 3000;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

const CODES = {
  member: process.env.MEMBER_CODE || "2018",
  guardian: process.env.GUARDIAN_CODE || "9982018",
  admin: process.env.ADMIN_CODE || "0000"
};

async function init() {
  if (!process.env.DATABASE_URL) {
    console.warn("DATABASE_URL nie jest ustawione. Na Renderze dodaj bazę PostgreSQL.");
    return;
  }
  await pool.query(`
    CREATE TABLE IF NOT EXISTS events (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      event_date TEXT NOT NULL,
      event_time TEXT NOT NULL,
      place TEXT NOT NULL,
      description TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS news (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS members (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      role TEXT DEFAULT 'Członek MDP',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS attendance (
      id SERIAL PRIMARY KEY,
      event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
      member_name TEXT NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('yes','maybe','no')),
      UNIQUE(event_id, member_name)
    );
  `);

  const count = await pool.query("SELECT COUNT(*)::int AS n FROM events");
  if (count.rows[0].n === 0) {
    await pool.query(
      `INSERT INTO events (title,event_date,event_time,place,description)
       VALUES ($1,$2,$3,$4,$5)`,
      ["Najbliższa zbiórka MDP", "2026-10-03", "17:00", "Remiza OSP Wiesiółka", "Pierwsza zbiórka w aplikacji."]
    );
  }
  const newsCount = await pool.query("SELECT COUNT(*)::int AS n FROM news");
  if (newsCount.rows[0].n === 0) {
    await pool.query(
      `INSERT INTO news (title,body) VALUES ($1,$2)`,
      ["Witamy w aplikacji MDP!", "Tutaj będą pojawiać się najważniejsze informacje dla MDP Wiesiółka."]
    );
  }
}

function auth(req, res, next) {
  const role = req.headers["x-role"];
  const code = req.headers["x-code"];
  if (!["member","guardian","admin"].includes(role) || code !== CODES[role]) {
    return res.status(401).json({ error: "Brak uprawnień." });
  }
  req.role = role;
  next();
}
function staff(req, res, next) {
  if (!["guardian","admin"].includes(req.role)) return res.status(403).json({error:"Tylko opiekun lub administrator."});
  next();
}
function admin(req, res, next) {
  if (req.role !== "admin") return res.status(403).json({error:"Tylko administrator."});
  next();
}

app.get("/api/health", async (req,res) => {
  try { await pool.query("SELECT 1"); res.json({ok:true}); }
  catch(e) { res.status(500).json({ok:false}); }
});

app.post("/api/login", (req,res) => {
  const {role, code} = req.body || {};
  if (!CODES[role] || code !== CODES[role]) return res.status(401).json({error:"Nieprawidłowy kod."});
  res.json({ok:true, role});
});

app.get("/api/data", auth, async (req,res) => {
  try {
    const [events, news, members] = await Promise.all([
      pool.query("SELECT * FROM events ORDER BY event_date ASC, event_time ASC"),
      pool.query("SELECT * FROM news ORDER BY created_at DESC"),
      pool.query("SELECT * FROM members ORDER BY name ASC")
    ]);
    res.json({events:events.rows, news:news.rows, members:members.rows});
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.post("/api/events", auth, staff, async (req,res) => {
  const {title,event_date,event_time,place,description=""} = req.body;
  if (!title || !event_date || !event_time || !place) return res.status(400).json({error:"Uzupełnij wymagane pola."});
  const r = await pool.query(
    `INSERT INTO events(title,event_date,event_time,place,description)
     VALUES($1,$2,$3,$4,$5) RETURNING *`,
    [title,event_date,event_time,place,description]
  );
  res.json(r.rows[0]);
});
app.delete("/api/events/:id", auth, staff, async (req,res) => {
  await pool.query("DELETE FROM events WHERE id=$1",[req.params.id]);
  res.json({ok:true});
});

app.post("/api/news", auth, staff, async (req,res) => {
  const {title,body} = req.body;
  if (!title || !body) return res.status(400).json({error:"Uzupełnij tytuł i treść."});
  const r = await pool.query(
    `INSERT INTO news(title,body) VALUES($1,$2) RETURNING *`,
    [title,body]
  );
  res.json(r.rows[0]);
});
app.delete("/api/news/:id", auth, staff, async (req,res) => {
  await pool.query("DELETE FROM news WHERE id=$1",[req.params.id]);
  res.json({ok:true});
});

app.post("/api/members", auth, staff, async (req,res) => {
  const {name,role="Członek MDP"} = req.body;
  if (!name) return res.status(400).json({error:"Podaj imię i nazwisko."});
  const r = await pool.query(
    `INSERT INTO members(name,role) VALUES($1,$2) RETURNING *`, [name,role]
  );
  res.json(r.rows[0]);
});
app.delete("/api/members/:id", auth, staff, async (req,res) => {
  await pool.query("DELETE FROM members WHERE id=$1",[req.params.id]);
  res.json({ok:true});
});

app.post("/api/attendance", auth, async (req,res) => {
  const {event_id,member_name,status} = req.body;
  if (!event_id || !member_name || !["yes","maybe","no"].includes(status))
    return res.status(400).json({error:"Nieprawidłowe dane."});
  const r = await pool.query(
    `INSERT INTO attendance(event_id,member_name,status)
     VALUES($1,$2,$3)
     ON CONFLICT(event_id,member_name)
     DO UPDATE SET status=EXCLUDED.status
     RETURNING *`,
    [event_id,member_name,status]
  );
  res.json(r.rows[0]);
});

app.get("/api/attendance/:eventId", auth, staff, async (req,res) => {
  const r = await pool.query(
    `SELECT * FROM attendance WHERE event_id=$1 ORDER BY member_name`,
    [req.params.eventId]
  );
  res.json(r.rows);
});

app.get("*", (req,res) => {
  res.sendFile(path.join(__dirname,"public","index.html"));
});

init().then(() => {
  app.listen(PORT, () => console.log(`MDP Wiesiółka działa na porcie ${PORT}`));
}).catch(err => {
  console.error(err);
  process.exit(1);
});