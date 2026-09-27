const express = require("express");
const path = require("path");
const { Pool } = require("pg");
const webpush = require("web-push");

const app = express();
const PORT = process.env.PORT || 3000;

/* =========================
   EXPRESS
========================= */

app.use(express.json({ limit: "2mb" }));
app.use(express.static(path.join(__dirname, "public")));

/* =========================
   DATABASE
========================= */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

/* =========================
   LOGIN CODES
========================= */

const CODES = {
  member: process.env.MEMBER_CODE || "2018",
  guardian: process.env.GUARDIAN_CODE || "9982018",
  admin: process.env.ADMIN_CODE || "0000"
};

/* =========================
   WEB PUSH
========================= */

const pushEnabled =
  !!process.env.VAPID_EMAIL &&
  !!process.env.VAPID_PUBLIC_KEY &&
  !!process.env.VAPID_PRIVATE_KEY;

if (pushEnabled) {
  webpush.setVapidDetails(
    process.env.VAPID_EMAIL,
    process.env.VAPID_PUBLIC_KEY,
    process.env.VAPID_PRIVATE_KEY
  );

  console.log("Web Push: VAPID aktywny.");
} else {
  console.log("Web Push: VAPID nie jest skonfigurowany.");
}

/* =========================
   DATABASE INITIALIZATION
========================= */

async function initDatabase() {
  if (!process.env.DATABASE_URL) {
    console.log("Brak DATABASE_URL.");
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
      event_id INTEGER NOT NULL
        REFERENCES events(id)
        ON DELETE CASCADE,
      member_name TEXT NOT NULL,
      status TEXT NOT NULL
        CHECK (status IN ('yes', 'maybe', 'no')),
      UNIQUE(event_id, member_name)
    );

    CREATE TABLE IF NOT EXISTS push_subscriptions (
      id SERIAL PRIMARY KEY,
      endpoint TEXT NOT NULL UNIQUE,
      subscription JSONB NOT NULL,
      role TEXT DEFAULT 'member',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  console.log("Baza danych gotowa.");
}

/* =========================
   AUTH
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
   LOGIN
========================= */

app.post("/api/login", (req, res) => {
  const { role, code } = req.body || {};

  if (!["member", "guardian", "admin"].includes(role)) {
    return res.status(400).json({
      error: "Nieprawidłowa rola."
    });
  }

  if (String(code || "") !== String(CODES[role])) {
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
   GET ALL DATA
========================= */

app.get("/api/data", auth, async (req, res) => {
  try {
    if (!process.env.DATABASE_URL) {
      return res.json({
        events: [],
        news: [],
        members: []
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
    console.error("GET /api/data:", error);

    res.status(500).json({
      error: "Nie udało się pobrać danych."
    });
  }
});

/* =========================
   PUSH SEND
========================= */

async function sendPushNotification(title, body) {
  if (!pushEnabled) {
    console.log("Push pominięty - brak VAPID.");
    return;
  }

  if (!process.env.DATABASE_URL) {
    console.log("Push pominięty - brak DATABASE_URL.");
    return;
  }

  const result = await pool.query(`
    SELECT id, subscription
    FROM push_subscriptions
  `);

  for (const row of result.rows) {
    try {
      await webpush.sendNotification(
        row.subscription,
        JSON.stringify({
          title,
          body,
          icon: "/icon-192-2.png",
          badge: "/icon-192-2.png"
        })
      );
    } catch (error) {
      console.error(
        "Push error:",
        error.statusCode || error.message
      );

      if (
        error.statusCode === 404 ||
        error.statusCode === 410
      ) {
        await pool.query(
          "DELETE FROM push_subscriptions WHERE id = $1",
          [row.id]
        );
      }
    }
  }
}

/* =========================
   PUSH PUBLIC KEY
========================= */

app.get("/api/push/public-key", (req, res) => {
  if (!pushEnabled) {
    return res.status(503).json({
      error: "Powiadomienia push nie są skonfigurowane."
    });
  }

  res.json({
    publicKey: process.env.VAPID_PUBLIC_KEY
  });
});

/* =========================
   PUSH SUBSCRIBE
========================= */

app.post("/api/push/subscribe", auth, async (req, res) => {
  try {
    if (!process.env.DATABASE_URL) {
      return res.status(503).json({
        error: "Baza danych nie jest podłączona."
      });
    }

    const { subscription } = req.body || {};

    if (
      !subscription ||
      !subscription.endpoint ||
      !subscription.keys
    ) {
      return res.status(400).json({
        error: "Nieprawidłowa subskrypcja."
      });
    }

    await pool.query(
      `
      INSERT INTO push_subscriptions
      (endpoint, subscription, role)
      VALUES ($1, $2, $3)
      ON CONFLICT (endpoint)
      DO UPDATE SET
        subscription = EXCLUDED.subscription,
        role = EXCLUDED.role
      `,
      [
        subscription.endpoint,
        JSON.stringify(subscription),
        req.role
      ]
    );

    res.json({
      ok: true
    });
  } catch (error) {
    console.error("POST /api/push/subscribe:", error);

    res.status(500).json({
      error: "Nie udało się zapisać subskrypcji."
    });
  }
});

/* =========================
   PUSH UNSUBSCRIBE
========================= */

app.post("/api/push/unsubscribe", auth, async (req, res) => {
  try {
    const { endpoint } = req.body || {};

    if (!endpoint) {
      return res.status(400).json({
        error: "Brak endpointu."
      });
    }

    await pool.query(
      "DELETE FROM push_subscriptions WHERE endpoint = $1",
      [endpoint]
    );

    res.json({
      ok: true
    });
  } catch (error) {
    console.error("POST /api/push/unsubscribe:", error);

    res.status(500).json({
      error: "Nie udało się wyłączyć powiadomień."
    });
  }
});

/* =========================
   PUSH TEST
========================= */

app.post("/api/push/test", auth, async (req, res) => {
  try {
    await sendPushNotification(
      "MDP Wiesiółka 🚒",
      "Powiadomienia push działają!"
    );

    res.json({
      ok: true
    });
  } catch (error) {
    console.error("POST /api/push/test:", error);

    res.status(500).json({
      error: "Nie udało się wysłać powiadomienia."
    });
  }
});

/* =========================
   EVENTS
========================= */

app.post("/api/events", auth, staff, async (req, res) => {
  try {
    const {
      title,
      event_date,
      event_time,
      place,
      description
    } = req.body || {};

    if (
      !title ||
      !event_date ||
      !event_time ||
      !place
    ) {
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
        String(title).trim(),
        String(event_date).trim(),
        String(event_time).trim(),
        String(place).trim(),
        String(description || "").trim()
      ]
    );

    const event = result.rows[0];

    await sendPushNotification(
      "📅 Nowa zbiórka MDP",
      `${event.title} — ${event.event_date} o ${event.event_time}`
    );

    res.json({
      ok: true,
      event
    });
  } catch (error) {
    console.error("POST /api/events:", error);

    res.status(500).json({
      error: "Nie udało się dodać zbiórki."
    });
  }
});

app.delete("/api/events/:id", auth, staff, async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!Number.isInteger(id)) {
      return res.status(400).json({
        error: "Nieprawidłowe ID."
      });
    }

    await pool.query(
      "DELETE FROM events WHERE id = $1",
      [id]
    );

    res.json({
      ok: true
    });
  } catch (error) {
    console.error("DELETE /api/events:", error);

    res.status(500).json({
      error: "Nie udało się usunąć zbiórki."
    });
  }
});

/* =========================
   NEWS
========================= */

app.post("/api/news", auth, staff, async (req, res) => {
  try {
    const { title, body } = req.body || {};

    if (!title || !body) {
      return res.status(400).json({
        error: "Podaj tytuł i treść ogłoszenia."
      });
    }

    const result = await pool.query(
      `
      INSERT INTO news
      (title, body)
      VALUES ($1, $2)
      RETURNING *
      `,
      [
        String(title).trim(),
        String(body).trim()
      ]
    );

    const news = result.rows[0];

    await sendPushNotification(
      "📢 Nowe ogłoszenie MDP",
      news.title
    );

    res.json({
      ok: true,
      news
    });
  } catch (error) {
    console.error("POST /api/news:", error);

    res.status(500).json({
      error: "Nie udało się dodać ogłoszenia."
    });
  }
});

app.delete("/api/news/:id", auth, staff, async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!Number.isInteger(id)) {
      return res.status(400).json({
        error: "Nieprawidłowe ID."
      });
    }

    await pool.query(
      "DELETE FROM news WHERE id = $1",
      [id]
    );

    res.json({
      ok: true
    });
  } catch (error) {
    console.error("DELETE /api/news:", error);

    res.status(500).json({
      error: "Nie udało się usunąć ogłoszenia."
    });
  }
});

/* =========================
   MEMBERS
========================= */

app.post("/api/members", auth, staff, async (req, res) => {
  try {
    const { name, role } = req.body || {};

    if (!name) {
      return res.status(400).json({
        error: "Podaj imię i nazwisko."
      });
    }

    const result = await pool.query(
      `
      INSERT INTO members
      (name, role)
      VALUES ($1, $2)
      RETURNING *
      `,
      [
        String(name).trim(),
        String(role || "Członek MDP").trim()
      ]
    );

    res.json({
      ok: true,
      member: result.rows[0]
    });
  } catch (error) {
    console.error("POST /api/members:", error);

    res.status(500).json({
      error: "Nie udało się dodać członka."
    });
  }
});

app.delete("/api/members/:id", auth, staff, async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!Number.isInteger(id)) {
      return res.status(400).json({
        error: "Nieprawidłowe ID."
      });
    }

    await pool.query(
      "DELETE FROM members WHERE id = $1",
      [id]
    );

    res.json({
      ok: true
    });
  } catch (error) {
    console.error("DELETE /api/members:", error);

    res.status(500).json({
      error: "Nie udało się usunąć członka."
    });
  }
});

/* =========================
   ATTENDANCE
========================= */

app.post("/api/attendance", auth, async (req, res) => {
  try {
    const {
      event_id,
      member_name,
      status
    } = req.body || {};

    if (
      !event_id ||
      !member_name ||
      !["yes", "maybe", "no"].includes(status)
    ) {
      return res.status(400).json({
        error: "Nieprawidłowe dane obecności."
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
        Number(event_id),
        String(member_name).trim(),
        status
      ]
    );

    res.json({
      ok: true,
      attendance: result.rows[0]
    });
  } catch (error) {
    console.error("POST /api/attendance:", error);

    res.status(500).json({
      error: "Nie udało się zapisać obecności."
    });
  }
});

app.get(
  "/api/attendance/:eventId",
  auth,
  async (req, res) => {
    try {
      const eventId = Number(req.params.eventId);

      if (!Number.isInteger(eventId)) {
        return res.status(400).json({
          error: "Nieprawidłowe ID zbiórki."
        });
      }

      const result = await pool.query(
        `
        SELECT *
        FROM attendance
        WHERE event_id = $1
        ORDER BY member_name ASC
        `,
        [eventId]
      );

      res.json(result.rows);
    } catch (error) {
      console.error("GET /api/attendance:", error);

      res.status(500).json({
        error: "Nie udało się pobrać obecności."
      });
    }
  }
);

/* =========================
   HEALTH CHECK
========================= */

app.get("/api/health", async (req, res) => {
  try {
    if (!process.env.DATABASE_URL) {
      return res.json({
        ok: true,
        database: false,
        push: pushEnabled
      });
    }

    await pool.query("SELECT 1");

    res.json({
      ok: true,
      database: true,
      push: pushEnabled
    });
  } catch (error) {
    console.error("Health check:", error);

    res.status(500).json({
      ok: false,
      database: false,
      push: pushEnabled
    });
  }
});

/* =========================
   FRONTEND FALLBACK
========================= */

app.get("*", (req, res) => {
  res.sendFile(
    path.join(__dirname, "public", "index.html")
  );
});

/* =========================
   START SERVER
========================= */

async function startServer() {
  try {
    await initDatabase();

    app.listen(PORT, () => {
      console.log(
        `MDP Wiesiółka działa na porcie ${PORT}.`
      );
    });
  } catch (error) {
    console.error(
      "Nie udało się uruchomić serwera:",
      error
    );

    process.exit(1);
  }
}

startServer();
