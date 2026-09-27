const express = require("express");
const path = require("path");
const { Pool } = require("pg");
const webpush = require("web-push");

const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const PORT = process.env.PORT || 3000;

/* =========================
   WEB PUSH
========================= */

if (
  process.env.VAPID_EMAIL &&
  process.env.VAPID_PUBLIC_KEY &&
  process.env.VAPID_PRIVATE_KEY
) {
  webpush.setVapidDetails(
    process.env.VAPID_EMAIL,
    process.env.VAPID_PUBLIC_KEY,
    process.env.VAPID_PRIVATE_KEY
  );

  console.log("Web Push: VAPID aktywny.");
} else {
  console.log("Web Push: brak konfiguracji VAPID.");
}

/* =========================
   BAZA DANYCH
========================= */

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
    console.log(
      "Brak DATABASE_URL - baza nie jest jeszcze podłączona."
    );
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

    CREATE TABLE IF NOT EXISTS push_subscriptions (
      id SERIAL PRIMARY KEY,
      endpoint TEXT NOT NULL UNIQUE,
      subscription JSONB NOT NULL,
      role TEXT DEFAULT 'member',
      created_at TIMESTAMPTZ DEFAULT NOW()
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
      error:
        "Tylko opiekun lub administrator może wykonać tę operację."
    });
  }

  next();
}

function admin(req, res, next) {
  if (req.role !== "admin") {
    return res.status(403).json({
      error:
        "Tylko administrator może wykonać tę operację."
    });
  }

  next();
}

/* =========================
   PUSH - WYSYŁANIE
========================= */

async function sendPushNotification(title, body) {
  if (
    !process.env.VAPID_EMAIL ||
    !process.env.VAPID_PUBLIC_KEY ||
    !process.env.VAPID_PRIVATE_KEY
  ) {
    console.log(
      "Push pominięty - brak konfiguracji VAPID."
    );
    return;
  }

  if (!process.env.DATABASE_URL) {
    console.log(
      "Push pominięty - brak bazy danych."
    );
    return;
  }

  try {
    const result = await pool.query(
      "SELECT id, endpoint, subscription FROM push_subscriptions"
    );

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
          "Błąd wysyłania push:",
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
  } catch (error) {
    console.error(
      "Błąd pobierania subskrypcji push:",
      error
    );
  }
}

/* =========================
   KLUCZ PUBLICZNY PUSH
========================= */

app.get("/api/push/public-key", (req, res) => {
  if (!process.env.VAPID_PUBLIC_KEY) {
    return res.status(503).json({
      error: "Push nie jest skonfigurowany."
    });
  }

  res.json({
    publicKey: process.env.VAPID_PUBLIC_KEY
  });
});

/* =========================
   REJESTRACJA PUSH
========================= */

app.post(
  "/api/push/subscribe",
  auth,
  async (req, res) => {
    try {
      const { subscription } = req.body || {};

      if (
        !subscription ||
        !subscription.endpoint ||
        !subscription.keys
      ) {
        return res.status(400).json({
          error: "Nieprawidłowa subskrypcja push."
        });
      }

      if (!process.env.DATABASE_URL) {
        return res.status(503).json({
          error:
            "Baza danych nie jest jeszcze podłączona."
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
      console.error(error);

      res.status(500).json({
        error:
          "Nie udało się zapisać powiadomień push."
      });
    }
  }
);

/* =========================
   WYREJESTROWANIE PUSH
========================= */

app.post(
  "/api/push/unsubscribe",
  auth,
  async (req, res) => {
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
      console.error(error);

      res.status(500).json({
        error:
          "Nie udało się wyłączyć powiadomień."
      });
    }
  }
);

/* =========================
   TEST PUSH
========================= */

app.post(
  "/api/push/test",
  auth,
  async (req, res) => {
    try {
      await sendPushNotification(
        "MDP Wiesiółka 🚒",
        "Powiadomienia push działają!"
      );

      res.json({
        ok: true
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "Nie udało się wysłać powiadomienia."
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
        database: false
      });
    }

    await pool.query("SELECT 1");

    res.json({
      ok: true,
      database: true
