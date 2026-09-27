const express = require("express");
const path = require("path");
const { Pool } = require("pg");

const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

/* =========================
   KODY LOGOWANIA
========================= */

const CODES = {
  member: process.env.MEMBER_CODE || "2018",
  guardian: process.env.GUARDIAN_CODE || "9982018",
  admin: process.env.ADMIN_CODE || "0000"
};

/* =========================
   BAZA DANYCH
========================= */

async function initDatabase() {
  if (!process.env.DATABASE_URL) {
    console.log("Brak DATABASE_URL - baza nie jest jeszcze podłączona.");
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
      status TEXT NOT NULL CHECK (status IN ('yes', 'maybe', 'no')),
      UNIQUE(event_id, member_name)
    );
  `);

  const events = await pool.query(
    "SELECT COUNT(*)::int AS count FROM events"
  );

  if (events.rows[0].count === 0) {
    await pool.query(
      `
      INSERT INTO events
      (title, event_date, event_time, place, description)
      VALUES ($1, $2, $3, $4, $5)
      `,
      [
        "Najbliższa zbiórka MDP",
        "2026-10-03",
        "17:00",
        "Remiza OSP Wiesiółka",
        "Pierwsza zbiórka w aplikacji."
      ]
    );
  }

  const news = await pool.query(
    "SELECT COUNT(*)::int AS count FROM news"
  );

  if (news.rows[0].count === 0) {
    await pool.query(
      `
      INSERT INTO news (title, body)
      VALUES ($1, $2)
      `,
      [
        "Witamy w aplikacji MDP!",
        "Tutaj będą pojawiać się najważniejsze informacje dla MDP Wiesiółka."
      ]
    );
  }
}

/* =========================
   LOGOWANIE
========================= */

app.post("/api/login", (req, res) => {
  const { role, code } = req.body || {};

  if (!CODES[role]) {
    return res.status(400).json({
      error: "Nieprawidłowa rola."
    });
  }

  if (code !== CODES[role]) {
    return res.status(401).json({
      error: "Nieprawidłowy kod."
    });
  }

  res.json({
    ok: true,
    role
  });
});

/* =========================
   UPRAWNIENIA
========================= */

function auth(req, res, next) {
  const role = req.headers["x-role"];
  const code = req.headers["x-code"];

  if (!["member", "guardian", "admin"].includes(role)) {
    return res.status(401).json({
      error: "Brak uprawnień."
    });
  }

  if (code !== CODES[role]) {
    return res.status(401).json({
      error: "Nieprawidłowy kod."
    });
  }

  req.role = role;
  next();
}

function staff(req, res, next) {
  if (!["guardian", "admin"].includes(req.role)) {
    return res.status(403).json({
      error: "Tylko opiekun lub administrator może wykonać tę operację."
    });
  }

  next();
}

function admin(req, res, next) {
  if (req.role !== "admin") {
    return res.status(403).json({
      error: "Tylko administrator może wykonać tę operację."
    });
  }

  next();
}

/* =========================
   HEALTH CHECK
========================= */

app.get("/api/health", async (req, res) => {
  try {
    if (!process.env.DATABASE_URL) {
      return res.json({
        ok: true,
        database: false
      });
    }

    await pool.query("SELECT 1");

    res.json({
      ok: true,
      database: true
    });
  } catch (error) {
    res.status(500).json({
      ok: false,
      database: false
    });
  }
});

/* =========================
   POBIERANIE DANYCH
========================= */

app.get("/api/data", auth, async (req, res) => {
  try {
    if (!process.env.DATABASE_URL) {
      return res.status(503).json({
        error: "Baza danych nie jest jeszcze podłączona."
      });
    }

    const events = await pool.query(`
      SELECT *
      FROM events
      ORDER BY event_date ASC, event_time ASC
    `);

    const news = await pool.query(`
      SELECT *
      FROM news
      ORDER BY created_at DESC
    `);

    const members = await pool.query(`
      SELECT *
      FROM members
      ORDER BY name ASC
    `);

    res.json({
      events: events.rows,
      news: news.rows,
      members: members.rows
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Nie udało się pobrać danych."
    });
  }
});

/* =========================
   ZBIÓRKI
========================= */

app.post("/api/events", auth, staff, async (req, res) => {
  try {
    const {
      title,
      event_date,
      event_time,
      place,
      description = ""
    } = req.body;

    if (!title || !event_date || !event_time || !place) {
      return res.status(400).json({
        error: "Uzupełnij wszystkie wymagane pola."
      });
    }

    const result = await pool.query(
      `
      INSERT INTO events
      (title, event_date, event_time, place, description)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *
      `,
      [
        title,
        event_date,
        event_time,
        place,
        description
      ]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Nie udało się dodać zbiórki."
    });
  }
});

app.delete("/api/events/:id", auth, staff, async (req, res) => {
  try {
    await pool.query(
      "DELETE FROM events WHERE id = $1",
      [req.params.id]
    );

    res.json({
      ok: true
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Nie udało się usunąć zbiórki."
    });
  }
});

/* =========================
   OGŁOSZENIA
========================= */

app.post("/api/news", auth, staff, async (req, res) => {
  try {
    const { title, body } = req.body;

    if (!title || !body) {
      return res.status(400).json({
        error: "Uzupełnij tytuł i treść."
      });
    }

    const result = await pool.query(
      `
      INSERT INTO news (title, body)
      VALUES ($1, $2)
      RETURNING *
      `,
      [title, body]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Nie udało się dodać ogłoszenia."
    });
  }
});

app.delete("/api/news/:id", auth, staff, async (req, res) => {
  try {
    await pool.query(
      "DELETE FROM news WHERE id = $1",
      [req.params.id]
    );

    res.json({
      ok: true
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Nie udało się usunąć ogłoszenia."
    });
  }
});

/* =========================
   CZŁONKOWIE
========================= */

app.post("/api/members", auth, staff, async (req, res) => {
  try {
    const {
      name,
      role = "Członek MDP"
    } = req.body;

    if (!name) {
      return res.status(400).json({
        error: "Podaj imię i nazwisko."
      });
    }

    const result = await pool.query(
      `
      INSERT INTO members (name, role)
      VALUES ($1, $2)
      RETURNING *
      `,
      [name, role]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Nie udało się dodać członka."
    });
  }
});

app.delete("/api/members/:id", auth, staff, async (req, res) => {
  try {
    await pool.query(
      "DELETE FROM members WHERE id = $1",
      [req.params.id]
    );

    res.json({
      ok: true
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Nie udało się usunąć członka."
    });
  }
});

/* =========================
   OBECNOŚĆ
========================= */

app.post("/api/attendance", auth, async (req, res) => {
  try {
    const {
      event_id,
      member_name,
      status
    } = req.body;

    if (
      !event_id ||
      !member_name ||
      !["yes", "maybe", "no"].includes(status)
    ) {
      return res.status(400).json({
        error: "Nieprawidłowe dane."
      });
    }

    const result = await pool.query(
      `
      INSERT INTO attendance
      (event_id, member_name, status)
      VALUES ($1, $2, $3)
      ON CONFLICT (event_id, member_name)
      DO UPDATE SET status = EXCLUDED.status
      RETURNING *
      `,
      [
        event_id,
        member_name,
        status
      ]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Nie udało się zapisać obecności."
    });
  }
});

/* =========================
   PODGLĄD OBECNOŚCI
========================= */

app.get(
  "/api/attendance/:eventId",
  auth,
  staff,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT *
        FROM attendance
        WHERE event_id = $1
        ORDER BY member_name
        `,
        [req.params.eventId]
      );

      res.json(result.rows);
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Nie udało się pobrać obecności."
      });
    }
  }
);

/* =========================
   APLIKACJA WWW
========================= */

app.get("/{*splat}", (req, res) => {
  res.sendFile(
    path.join(__dirname, "public", "index.html")
  );
});

/* =========================
   START
========================= */

async function startServer() {
  try {
    await initDatabase();

    app.listen(PORT, () => {
      console.log(
        `MDP Wiesiółka działa na porcie ${PORT}`
      );
    });
  } catch (error) {
    console.error(
      "Błąd uruchamiania serwera:",
      error
    );

    process.exit(1);
  }
}

startServer();
