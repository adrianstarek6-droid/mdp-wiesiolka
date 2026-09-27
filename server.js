const express = require("express");
const path = require("path");
const crypto = require("crypto");
const webpush = require("web-push");
const { Pool } = require("pg");

const app = express();

app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

/* =========================
   KODY ADMINA
========================= */

const ADMIN_CODE = process.env.ADMIN_CODE || "0000";

/* =========================
   POWIADOMIENIA PUSH
========================= */

if (
  process.env.VAPID_PUBLIC_KEY &&
  process.env.VAPID_PRIVATE_KEY &&
  process.env.VAPID_SUBJECT
) {
  webpush.setVapidDetails(
    process.env.VAPID_SUBJECT,
    process.env.VAPID_PUBLIC_KEY,
    process.env.VAPID_PRIVATE_KEY
  );
}

/* =========================
   HASŁA / KODY KONT
========================= */

function hashCode(code) {
  return crypto
    .createHash("sha256")
    .update(String(code))
    .digest("hex");
}

function makeAccountCode() {
  return String(
    Math.floor(100000 + Math.random() * 900000)
  );
}

/* =========================
   BAZA DANYCH
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

    CREATE TABLE IF NOT EXISTS accounts (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('member', 'guardian')),
      code_hash TEXT NOT NULL UNIQUE,
      active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS attendance (
      id SERIAL PRIMARY KEY,
      event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
      account_id INTEGER REFERENCES accounts(id) ON DELETE CASCADE,
      member_name TEXT NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('yes', 'maybe', 'no')),
      UNIQUE(event_id, account_id)
    );

    CREATE TABLE IF NOT EXISTS push_subscriptions (
      id SERIAL PRIMARY KEY,
      account_id INTEGER REFERENCES accounts(id) ON DELETE CASCADE,
      endpoint TEXT NOT NULL UNIQUE,
      p256dh TEXT NOT NULL,
      auth TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  /* =========================
     STARE DANE - ZACHOWANIE
  ========================= */

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

app.post("/api/login", async (req, res) => {
  try {
    const { role, code } = req.body || {};

    if (!["member", "guardian", "admin"].includes(role)) {
      return res.status(400).json({
        error: "Nieprawidłowa rola."
      });
    }

    /* ADMIN */
    if (role === "admin") {
      if (String(code) !== String(ADMIN_CODE)) {
        return res.status(401).json({
          error: "Nieprawidłowy kod administratora."
        });
      }

      return res.json({
        ok: true,
        role: "admin",
        name: "Administrator",
        accountId: null
      });
    }

    /* CZŁONEK / OPIEKUN */

    if (!process.env.DATABASE_URL) {
      return res.status(503).json({
        error: "Baza danych nie jest podłączona."
      });
    }

    const codeHash = hashCode(code);

    const result = await pool.query(
      `
      SELECT id, name, role, active
      FROM accounts
      WHERE code_hash = $1
        AND role = $2
      `,
      [codeHash, role]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: "Nieprawidłowy kod."
      });
    }

    const account = result.rows[0];

    if (!account.active) {
      return res.status(403).json({
        error: "To konto jest nieaktywne."
      });
    }

    res.json({
      ok: true,
      role: account.role,
      name: account.name,
      accountId: account.id
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Błąd logowania."
    });
  }
});

/* =========================
   AUTORYZACJA
========================= */

async function auth(req, res, next) {
  try {
    const role = req.headers["x-role"];
    const code = req.headers["x-code"];

    if (!["member", "guardian", "admin"].includes(role)) {
      return res.status(401).json({
        error: "Brak uprawnień."
      });
    }

    /* ADMIN */
    if (role === "admin") {
      if (String(code) !== String(ADMIN_CODE)) {
        return res.status(401).json({
          error: "Nieprawidłowy kod administratora."
        });
      }

      req.role = "admin";
      req.accountId = null;
      req.accountName = "Administrator";

      return next();
    }

    /* KONTA */
    if (!process.env.DATABASE_URL) {
      return res.status(503).json({
        error: "Baza danych nie jest podłączona."
      });
    }

    const codeHash = hashCode(code);

    const result = await pool.query(
      `
      SELECT id, name, role, active
      FROM accounts
      WHERE code_hash = $1
        AND role = $2
      `,
      [codeHash, role]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: "Nieprawidłowy kod."
      });
    }

    const account = result.rows[0];

    if (!account.active) {
      return res.status(403).json({
        error: "Konto jest nieaktywne."
      });
    }

    req.role = account.role;
    req.accountId = account.id;
    req.accountName = account.name;

    next();
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Błąd autoryzacji."
    });
  }
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
   HEALTH
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
   DANE
========================= */

app.get("/api/data", auth, async (req, res) => {
  try {
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

    const accounts = await pool.query(`
      SELECT id, name, role, active, created_at
      FROM accounts
      ORDER BY name ASC
    `);

    res.json({
      events: events.rows,
      news: news.rows,
      members: members.rows,
      accounts: req.role === "admin" ? accounts.rows : [],
      me: {
        id: req.accountId,
        name: req.accountName,
        role: req.role
      }
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Nie udało się pobrać danych."
    });
  }
});

/* =========================
   KONTA
   TYLKO ADMIN
========================= */

app.post("/api/accounts", auth, admin, async (req, res) => {
  try {
    const {
      name,
      role
    } = req.body || {};

    if (!name || !["member", "guardian"].includes(role)) {
      return res.status(400).json({
        error: "Podaj imię, nazwisko i prawidłową rolę."
      });
    }

    const code = makeAccountCode();
    const codeHash = hashCode(code);

    const result = await pool.query(
      `
      INSERT INTO accounts
      (name, role, code_hash)
      VALUES ($1, $2, $3)
      RETURNING id, name, role, active, created_at
      `,
      [name.trim(), role, codeHash]
    );

    res.json({
      ok: true,
      account: result.rows[0],
      code
    });
  } catch (error) {
    console.error(error);

    if (error.code === "23505") {
      return res.status(409).json({
        error: "Wygenerowany kod już istnieje. Spróbuj ponownie."
      });
    }

    res.status(500).json({
      error: "Nie udało się utworzyć konta."
    });
  }
});

/* =========================
   USUWANIE KONTA
========================= */

app.delete("/api/accounts/:id", auth, admin, async (req, res) => {
  try {
    await pool.query(
      "DELETE FROM accounts WHERE id = $1",
      [req.params.id]
    );

    res.json({
      ok: true
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Nie udało się usunąć konta."
    });
  }
});

/* =========================
   AKTYWACJA / DEZAKTYWACJA
========================= */

app.patch("/api/accounts/:id", auth, admin, async (req, res) => {
  try {
    const { active } = req.body || {};

    if (typeof active !== "boolean") {
      return res.status(400).json({
        error: "Nieprawidłowy status."
      });
    }

    const result = await pool.query(
      `
      UPDATE accounts
      SET active = $1
      WHERE id = $2
      RETURNING id, name, role, active
      `,
      [active, req.params.id]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Nie udało się zmienić statusu konta."
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
    } = req.body || {};

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

    await sendPushToAll(
      "Nowa zbiórka MDP",
      `${title} • ${event_date} ${event_time}`
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
    const { title, body } = req.body || {};

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

    await sendPushToAll(
      title,
      body
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
    } = req.body || {};

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
      status
    } = req.body || {};

    if (
      !event_id ||
      !["yes", "maybe", "no"].includes(status)
    ) {
      return res.status(400).json({
        error: "Nieprawidłowe dane."
      });
    }

    if (req.role === "member") {
      const result = await pool.query(
        `
        INSERT INTO attendance
        (event_id, account_id, member_name, status)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (event_id, account_id)
        DO UPDATE SET status = EXCLUDED.status
        RETURNING *
        `,
        [
          event_id,
          req.accountId,
          req.accountName,
          status
        ]
      );

      return res.json(result.rows[0]);
    }

    if (req.role === "guardian" || req.role === "admin") {
      const { account_id, member_name } = req.body || {};

      if (!account_id || !member_name) {
        return res.status(400).json({
          error: "Brak członka."
        });
      }

      const result = await pool.query(
        `
        INSERT INTO attendance
        (event_id, account_id, member_name, status)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (event_id, account_id)
        DO UPDATE SET status = EXCLUDED.status
        RETURNING *
        `,
        [
          event_id,
          account_id,
          member_name,
          status
        ]
      );

      return res.json(result.rows[0]);
    }

    res.status(403).json({
      error: "Brak uprawnień."
    });
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
   PUSH - KLUCZ PUBLICZNY
========================= */

app.get("/api/push/public-key", auth, (req, res) => {
  if (!process.env.VAPID_PUBLIC_KEY) {
    return res.status(503).json({
      error: "Powiadomienia nie są jeszcze skonfigurowane."
    });
  }

  res.json({
    publicKey: process.env.VAPID_PUBLIC_KEY
  });
});

/* =========================
   PUSH - ZAPIS SUBSKRYPCJI
========================= */

app.post("/api/push/subscribe", auth, async (req, res) => {
  try {
    const subscription = req.body;

    if (
      !subscription ||
      !subscription.endpoint ||
      !subscription.keys ||
      !subscription.keys.p256dh ||
      !subscription.keys.auth
    ) {
      return res.status(400).json({
        error: "Nieprawidłowa subskrypcja."
      });
    }

    await pool.query(
      `
      INSERT INTO push_subscriptions
      (account_id, endpoint, p256dh, auth)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (endpoint)
      DO UPDATE SET
        account_id = EXCLUDED.account_id,
        p256dh = EXCLUDED.p256dh,
        auth = EXCLUDED.auth
      `,
      [
        req.accountId,
        subscription.endpoint,
        subscription.keys.p256dh,
        subscription.keys.auth
      ]
    );

    res.json({
      ok: true
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Nie udało się włączyć powiadomień."
    });
  }
});

/* =========================
   PUSH - WYSYŁANIE
========================= */

async function sendPushToAll(title, body) {
  try {
    if (
      !process.env.VAPID_PUBLIC_KEY ||
      !process.env.VAPID_PRIVATE_KEY ||
      !process.env.VAPID_SUBJECT
    ) {
      console.log("Push: brak konfiguracji VAPID.");
      return;
    }

    const result = await pool.query(`
      SELECT *
      FROM push_subscriptions
    `);

    for (const sub of result.rows) {
      const payload = JSON.stringify({
        title,
        body,
        url: "/"
      });

      try {
        await webpush.sendNotification(
          {
            endpoint: sub.endpoint,
            keys: {
              p256dh: sub.p256dh,
              auth: sub.auth
            }
          },
          payload
        );
      } catch (error) {
        console.log(
          "Nie udało się wysłać push:",
          error.statusCode
        );

        if (
          error.statusCode === 404 ||
          error.statusCode === 410
        ) {
          await pool.query(
            "DELETE FROM push_subscriptions WHERE id = $1",
            [sub.id]
          );
        }
      }
    }
  } catch (error) {
    console.error("Błąd push:", error);
  }
}

/* =========================
   APLIKACJA
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
