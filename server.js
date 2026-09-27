const express = require("express");
const path = require("path");
const { Pool } = require("pg");
const webpush = require("web-push");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

/* =========================
   EXPRESS
========================= */

app.use(express.json({ limit: "3mb" }));
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
  guardian: process.env.GUARDIAN_CODE || "9982018",
  admin: process.env.ADMIN_CODE || "0000"
};

/* =========================
   WEB PUSH
========================= */

const pushEnabled =
  Boolean(process.env.VAPID_EMAIL) &&
  Boolean(process.env.VAPID_PUBLIC_KEY) &&
  Boolean(process.env.VAPID_PRIVATE_KEY);

if (pushEnabled) {
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
   PASSWORD / CODE HELPERS
========================= */

function hashCode(code) {
  const salt = crypto.randomBytes(16).toString("hex");

  const hash = crypto
    .scryptSync(String(code), salt, 64)
    .toString("hex");

  return `${salt}:${hash}`;
}

function verifyCode(code, storedHash) {
  try {
    if (!storedHash || !storedHash.includes(":")) {
      return false;
    }

    const [salt, originalHash] = storedHash.split(":");

    const hash = crypto
      .scryptSync(String(code), salt, 64)
      .toString("hex");

    const a = Buffer.from(hash, "hex");
    const b = Buffer.from(originalHash, "hex");

    if (a.length !== b.length) {
      return false;
    }

    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

/* =========================
   DATABASE INIT
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

  /* =========================
     NOWE KOLUMNY CZŁONKÓW
  ========================= */

  await pool.query(`
    ALTER TABLE members
    ADD COLUMN IF NOT EXISTS first_name TEXT;

    ALTER TABLE members
    ADD COLUMN IF NOT EXISTS last_name TEXT;

    ALTER TABLE members
    ADD COLUMN IF NOT EXISTS code_hash TEXT;

    ALTER TABLE members
    ADD COLUMN IF NOT EXISTS photo TEXT;
  `);

  /* =========================
     UZUPEŁNIENIE STARYCH CZŁONKÓW
  ========================= */

  await pool.query(`
    UPDATE members
    SET
      first_name = COALESCE(
        NULLIF(split_part(name, ' ', 1), ''),
        'Członek'
      ),
      last_name = COALESCE(
        NULLIF(
          regexp_replace(name, '^\\S+\\s*', ''),
          ''
        ),
        ''
      )
    WHERE first_name IS NULL;
  `);

  console.log("Baza danych gotowa.");

  /* =========================
     STARTOWE DANE
  ========================= */

  const eventsCount = await pool.query(
    "SELECT COUNT(*)::int AS count FROM events"
  );

  if (eventsCount.rows[0].count === 0) {
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

  const newsCount = await pool.query(
    "SELECT COUNT(*)::int AS count FROM news"
  );

  if (newsCount.rows[0].count === 0) {
    await pool.query(
      `
      INSERT INTO news
      (title, body)
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
   AUTH
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

    /* =========================
       CZŁONEK MDP
    ========================= */

    if (role === "member") {
      const memberId = Number(req.headers["x-member-id"]);

      if (!Number.isInteger(memberId)) {
        return res.status(401).json({
          error: "Brak identyfikatora członka."
        });
      }

      const result = await pool.query(
        `
        SELECT *
        FROM members
        WHERE id = $1
        `,
        [memberId]
      );

      if (result.rows.length === 0) {
        return res.status(401).json({
          error: "Nie znaleziono konta członka."
        });
      }

      const member = result.rows[0];

      if (!verifyCode(code, member.code_hash)) {
        return res.status(401).json({
          error: "Nieprawidłowy kod."
        });
      }

      req.role = "member";
      req.memberId = member.id;
      req.member = member;

      return next();
    }

    /* =========================
       OPIEKUN / ADMIN
    ========================= */

    if (String(code || "") !== String(CODES[role])) {
      return res.status(401).json({
        error: "Nieprawidłowy kod."
      });
    }

    req.role = role;
    next();
  } catch (error) {
    console.error("AUTH:", error);

    res.status(500).json({
      error: "Błąd autoryzacji."
    });
  }
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
      error: "Tylko administrator może wykonać tę operację."
    });
  }

  next();
}

/* =========================
   LOGIN
========================= */

app.post("/api/login", async (req, res) => {
  try {
    const {
      role,
      code,
      firstName,
      lastName
    } = req.body || {};

    if (!["member", "guardian", "admin"].includes(role)) {
      return res.status(400).json({
        error: "Nieprawidłowa rola."
      });
    }

    /* =========================
       CZŁONEK MDP
    ========================= */

    if (role === "member") {
      const cleanFirstName = String(firstName || "")
        .trim();

      const cleanLastName = String(lastName || "")
        .trim();

      if (!cleanFirstName || !cleanLastName || !code) {
        return res.status(400).json({
          error:
            "Podaj imię, nazwisko oraz kod dostępu."
        });
      }

      const result = await pool.query(
        `
        SELECT *
        FROM members
        WHERE LOWER(first_name) = LOWER($1)
          AND LOWER(last_name) = LOWER($2)
        LIMIT 1
        `,
        [
          cleanFirstName,
          cleanLastName
        ]
      );

      if (result.rows.length === 0) {
        return res.status(401).json({
          error:
            "Nie znaleziono członka o podanym imieniu i nazwisku."
        });
      }

      const member = result.rows[0];

      if (!verifyCode(code, member.code_hash)) {
        return res.status(401).json({
          error: "Nieprawidłowy kod dostępu."
        });
      }

      return res.json({
        ok: true,
        role: "member",
        member: {
          id: member.id,
          first_name: member.first_name,
          last_name: member.last_name,
          role: member.role,
          photo: member.photo || ""
        }
      });
    }

    /* =========================
       OPIEKUN / ADMIN
    ========================= */

    if (String(code || "") !== String(CODES[role])) {
      return res.status(401).json({
        error: "Nieprawidłowy kod."
      });
    }

    res.json({
      ok: true,
      role
    });
  } catch (error) {
    console.error("POST /api/login:", error);

    res.status(500).json({
      error: "Nie udało się zalogować."
    });
  }
});

/* =========================
   GET DATA
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
      SELECT
        id,
        first_name,
        last_name,
        name,
        role,
        photo,
        created_at
      FROM members
      ORDER BY first_name ASC, last_name ASC
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
   PROFILE - GET
========================= */

app.get(
  "/api/profile",
  auth,
  async (req, res) => {
    try {
      if (req.role !== "member") {
        return res.json({
          role: req.role
        });
      }

      const result = await pool.query(
        `
        SELECT
          id,
          first_name,
          last_name,
          role,
          photo,
          created_at
        FROM members
        WHERE id = $1
        `,
        [req.memberId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error: "Nie znaleziono profilu."
        });
      }

      res.json(result.rows[0]);
    } catch (error) {
      console.error("GET /api/profile:", error);

      res.status(500).json({
        error: "Nie udało się pobrać profilu."
      });
    }
  }
);

/* =========================
   PROFILE - UPDATE PHOTO
========================= */

app.put(
  "/api/profile",
  auth,
  async (req, res) => {
    try {
      if (req.role !== "member") {
        return res.status(403).json({
          error: "Ta funkcja dotyczy członka MDP."
        });
      }

      const {
        photo
      } = req.body || {};

      if (
        photo !== "" &&
        typeof photo !== "string"
      ) {
        return res.status(400).json({
          error: "Nieprawidłowe zdjęcie."
        });
      }

      if (photo && photo.length > 1500000) {
        return res.status(400).json({
          error: "Zdjęcie jest za duże."
        });
      }

      const result = await pool.query(
        `
        UPDATE members
        SET photo = $1
        WHERE id = $2
        RETURNING
          id,
          first_name,
          last_name,
          role,
          photo,
          created_at
        `,
        [
          photo || "",
          req.memberId
        ]
      );

      res.json({
        ok: true,
        member: result.rows[0]
      });
    } catch (error) {
      console.error(
        "PUT /api/profile:",
        error
      );

      res.status(500).json({
        error: "Nie udało się zapisać profilu."
      });
    }
  }
);

/* =========================
   PUSH - SEND
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

  try {
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

        console.log("Push wysłany.");
      } catch (error) {
        console.error(
          "Błąd push:",
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
      "Błąd pobierania subskrypcji:",
      error
    );
  }
}

/* =========================
   PUSH PUBLIC KEY
========================= */

app.get("/api/push/public-key", (req, res) => {
  if (!pushEnabled) {
    return res.status(503).json({
      error:
        "Powiadomienia push nie są skonfigurowane."
    });
  }

  res.json({
    publicKey: process.env.VAPID_PUBLIC_KEY
  });
});

/* =========================
   PUSH SUBSCRIBE
========================= */

app.post(
  "/api/push/subscribe",
  auth,
  async (req, res) => {
    try {
      if (!process.env.DATABASE_URL) {
        return res.status(503).json({
          error:
            "Baza danych nie jest podłączona."
        });
      }

      if (!pushEnabled) {
        return res.status(503).json({
          error: "Push nie jest skonfigurowany."
        });
      }

      const {
        subscription
      } = req.body || {};

      if (
        !subscription ||
        !subscription.endpoint ||
        !subscription.keys
      ) {
        return res.status(400).json({
          error:
            "Nieprawidłowa subskrypcja push."
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
      console.error(
        "POST /api/push/subscribe:",
        error
      );

      res.status(500).json({
        error:
          "Nie udało się zapisać subskrypcji."
      });
    }
  }
);

/* =========================
   PUSH UNSUBSCRIBE
========================= */

app.post(
  "/api/push/unsubscribe",
  auth,
  async (req, res) => {
    try {
      const {
        endpoint
      } = req.body || {};

      if (!endpoint) {
        return res.status(400).json({
          error: "Brak endpointu."
        });
      }

      if (process.env.DATABASE_URL) {
        await pool.query(
          `
          DELETE FROM push_subscriptions
          WHERE endpoint = $1
          `,
          [endpoint]
        );
      }

      res.json({
        ok: true
      });
    } catch (error) {
      console.error(
        "POST /api/push/unsubscribe:",
        error
      );

      res.status(500).json({
        error:
          "Nie udało się wyłączyć powiadomień."
      });
    }
  }
);

/* =========================
   PUSH TEST
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
      console.error(
        "POST /api/push/test:",
        error
      );

      res.status(500).json({
        error:
          "Nie udało się wysłać powiadomienia."
      });
    }
  }
);

/* =========================
   EVENTS - ADD
========================= */

app.post(
  "/api/events",
  auth,
  staff,
  async (req, res) => {
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
          error:
            "Uzupełnij wymagane pola."
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
      console.error(
        "POST /api/events:",
        error
      );

      res.status(500).json({
        error:
          "Nie udało się dodać zbiórki."
      });
    }
  }
);

/* =========================
   EVENTS - DELETE
========================= */

app.delete(
  "/api/events/:id",
  auth,
  staff,
  async (req, res) => {
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
      console.error(
        "DELETE /api/events:",
        error
      );

      res.status(500).json({
        error:
          "Nie udało się usunąć zbiórki."
      });
    }
  }
);

/* =========================
   NEWS - ADD
========================= */

app.post(
  "/api/news",
  auth,
  staff,
  async (req, res) => {
    try {
      const {
        title,
        body
      } = req.body || {};

      if (!title || !body) {
        return res.status(400).json({
          error:
            "Podaj tytuł i treść ogłoszenia."
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
      console.error(
        "POST /api/news:",
        error
      );

      res.status(500).json({
        error:
          "Nie udało się dodać ogłoszenia."
      });
    }
  }
);

/* =========================
   NEWS - DELETE
========================= */

app.delete(
  "/api/news/:id",
  auth,
  staff,
  async (req, res) => {
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
      console.error(
        "DELETE /api/news:",
        error
      );

      res.status(500).json({
        error:
          "Nie udało się usunąć ogłoszenia."
      });
    }
  }
);

/* =========================
   MEMBERS - ADD
========================= */

app.post(
  "/api/members",
  auth,
  staff,
  async (req, res) => {
    try {
      const {
        firstName,
        lastName,
        role,
        code,
        photo
      } = req.body || {};

      const cleanFirstName = String(
        firstName || ""
      ).trim();

      const cleanLastName = String(
        lastName || ""
      ).trim();

      const cleanRole = String(
        role || "Członek MDP"
      ).trim();

      const cleanCode = String(
        code || ""
      ).trim();

      if (
        !cleanFirstName ||
        !cleanLastName ||
        !cleanCode
      ) {
        return res.status(400).json({
          error:
            "Podaj imię, nazwisko oraz kod dostępu."
        });
      }

      if (cleanCode.length < 4) {
        return res.status(400).json({
          error:
            "Kod dostępu musi mieć co najmniej 4 znaki."
        });
      }

      if (
        photo &&
        typeof photo === "string" &&
        photo.length > 1500000
      ) {
        return res.status(400).json({
          error: "Zdjęcie jest za duże."
        });
      }

      const existing = await pool.query(
        `
        SELECT id
        FROM members
        WHERE LOWER(first_name) = LOWER($1)
          AND LOWER(last_name) = LOWER($2)
        LIMIT 1
        `,
        [
          cleanFirstName,
          cleanLastName
        ]
      );

      if (existing.rows.length > 0) {
        return res.status(409).json({
          error:
            "Członek o takim imieniu i nazwisku już istnieje."
        });
      }

      const name =
        `${cleanFirstName} ${cleanLastName}`;

      const codeHash = hashCode(cleanCode);

      const result = await pool.query(
        `
        INSERT INTO members
        (
          name,
          first_name,
          last_name,
          role,
          code_hash,
          photo
        )
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING
          id,
          first_name,
          last_name,
          name,
          role,
          photo,
          created_at
        `,
        [
          name,
          cleanFirstName,
          cleanLastName,
          cleanRole,
          codeHash,
          photo || ""
        ]
      );

      res.json({
        ok: true,
        member: result.rows[0]
      });
    } catch (error) {
      console.error(
        "POST /api/members:",
        error
      );

      res.status(500).json({
        error:
          "Nie udało się utworzyć konta członka."
      });
    }
  }
);

/* =========================
   MEMBERS - UPDATE
========================= */

app.put(
  "/api/members/:id",
  auth,
  staff,
  async (req, res) => {
    try {
      const id = Number(req.params.id);

      if (!Number.isInteger(id)) {
        return res.status(400).json({
          error: "Nieprawidłowe ID."
        });
      }

      const {
        firstName,
        lastName,
        role,
        code,
        photo
      } = req.body || {};

      const current = await pool.query(
        `
        SELECT *
        FROM members
        WHERE id = $1
        `,
        [id]
      );

      if (current.rows.length === 0) {
        return res.status(404).json({
          error: "Nie znaleziono członka."
        });
      }

      const member = current.rows[0];

      const newFirstName =
        String(
          firstName || member.first_name || ""
        ).trim();

      const newLastName =
        String(
          lastName || member.last_name || ""
        ).trim();

      const newRole =
        String(
          role || member.role || "Członek MDP"
        ).trim();

      const newPhoto =
        typeof photo === "string"
          ? photo
          : member.photo || "";

      if (!newFirstName || !newLastName) {
        return res.status(400).json({
          error:
            "Imię i nazwisko są wymagane."
        });
      }

      if (newPhoto.length > 1500000) {
        return res.status(400).json({
          error: "Zdjęcie jest za duże."
        });
      }

      let codeHash = member.code_hash;

      if (code) {
        if (String(code).trim().length < 4) {
          return res.status(400).json({
            error:
              "Kod dostępu musi mieć co najmniej 4 znaki."
          });
        }

        codeHash = hashCode(
          String(code).trim()
        );
      }

      const name =
        `${newFirstName} ${newLastName}`;

      const result = await pool.query(
        `
        UPDATE members
        SET
          name = $1,
          first_name = $2,
          last_name = $3,
          role = $4,
          code_hash = $5,
          photo = $6
        WHERE id = $7
        RETURNING
          id,
          first_name,
          last_name,
          name,
          role,
          photo,
          created_at
        `,
        [
          name,
          newFirstName,
          newLastName,
          newRole,
          codeHash,
          newPhoto,
          id
        ]
      );

      res.json({
        ok: true,
        member: result.rows[0]
      });
    } catch (error) {
      console.error(
        "PUT /api/members/:id:",
        error
      );

      res.status(500).json({
        error:
          "Nie udało się zmienić profilu."
      });
    }
  }
);

/* =========================
   MEMBERS - DELETE
========================= */

app.delete(
  "/api/members/:id",
  auth,
  staff,
  async (req, res) => {
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
      console.error(
        "DELETE /api/members:",
        error
      );

      res.status(500).json({
        error:
          "Nie udało się usunąć członka."
      });
    }
  }
);

/* =========================
   ATTENDANCE - SAVE
========================= */

app.post(
  "/api/attendance",
  auth,
  async (req, res) => {
    try {
      const {
        event_id,
        status,
        member_id,
        member_name
      } = req.body || {};

      if (
        !event_id ||
        !["yes", "maybe", "no"].includes(status)
      ) {
        return res.status(400).json({
          error:
            "Nieprawidłowe dane obecności."
        });
      }

      let finalMemberId = null;
      let finalMemberName = "";

      /* =========================
         CZŁONEK ZALOGOWANY
      ========================= */

      if (req.role === "member") {
        finalMemberId = req.memberId;

        finalMemberName =
          `${req.member.first_name} ${req.member.last_name}`;
      }

      /* =========================
         OPIEKUN / ADMIN
      ========================= */

      if (
        req.role === "guardian" ||
        req.role === "admin"
      ) {
        if (member_id) {
          const memberResult = await pool.query(
            `
            SELECT *
            FROM members
            WHERE id = $1
            `,
            [Number(member_id)]
          );

          if (memberResult.rows.length === 0) {
            return res.status(404).json({
              error:
                "Nie znaleziono członka."
            });
          }

          const member =
            memberResult.rows[0];

          finalMemberId = member.id;
          finalMemberName =
            `${member.first_name} ${member.last_name}`;
        } else if (member_name) {
          finalMemberName =
            String(member_name).trim();
        }
      }

      if (!finalMemberName) {
        return res.status(400).json({
          error:
            "Nie znaleziono członka."
        });
      }

      /* =========================
         SPRAWDŹ CZY JUŻ JEST
      ========================= */

      let existing;

      if (finalMemberId) {
        existing = await pool.query(
          `
          SELECT *
          FROM attendance
          WHERE event_id = $1
            AND member_name = $2
          LIMIT 1
          `,
          [
            Number(event_id),
            finalMemberName
          ]
        );
      } else {
        existing = await pool.query(
          `
          SELECT *
          FROM attendance
          WHERE event_id = $1
            AND member_name = $2
          LIMIT 1
          `,
          [
            Number(event_id),
            finalMemberName
          ]
        );
      }

      if (existing.rows.length > 0) {
        const result = await pool.query(
          `
          UPDATE attendance
          SET
            status = $1
          WHERE id = $2
          RETURNING *
          `,
          [
            status,
            existing.rows[0].id
          ]
        );

        return res.json({
          ok: true,
          attendance: result.rows[0]
        });
      }

      const result = await pool.query(
        `
        INSERT INTO attendance
        (
          event_id,
          member_name,
          status
        )
        VALUES ($1, $2, $3)
        RETURNING *
        `,
        [
          Number(event_id),
          finalMemberName,
          status
        ]
      );

      res.json({
        ok: true,
        attendance: result.rows[0]
      });
    } catch (error) {
      console.error(
        "POST /api/attendance:",
        error
      );

      res.status(500).json({
        error:
          "Nie udało się zapisać obecności."
      });
    }
  }
);

/* =========================
   ATTENDANCE - GET
========================= */

app.get(
  "/api/attendance/:eventId",
  auth,
  async (req, res) => {
    try {
      const eventId =
        Number(req.params.eventId);

      if (!Number.isInteger(eventId)) {
        return res.status(400).json({
          error:
            "Nieprawidłowe ID zbiórki."
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
      console.error(
        "GET /api/attendance:",
        error
      );

      res.status(500).json({
        error:
          "Nie udało się pobrać obecności."
      });
    }
  }
);

/* =========================
   MEMBER STATS
========================= */

app.get(
  "/api/member-stats/:memberId",
  auth,
  async (req, res) => {
    try {
      const memberId =
        Number(req.params.memberId);

      if (!Number.isInteger(memberId)) {
        return res.status(400).json({
          error: "Nieprawidłowe ID."
        });
      }

      if (
        req.role === "member" &&
        req.memberId !== memberId
      ) {
        return res.status(403).json({
          error: "Brak dostępu."
        });
      }

      const memberResult =
        await pool.query(
          `
          SELECT *
          FROM members
          WHERE id = $1
          `,
          [memberId]
        );

      if (memberResult.rows.length === 0) {
        return res.status(404).json({
          error:
            "Nie znaleziono członka."
        });
      }

      const member =
        memberResult.rows[0];

      const statsResult =
        await pool.query(
          `
          SELECT
            COUNT(*) FILTER (
              WHERE status = 'yes'
            )::int AS yes,

            COUNT(*) FILTER (
              WHERE status = 'maybe'
            )::int AS maybe,

            COUNT(*) FILTER (
              WHERE status = 'no'
            )::int AS no,

            COUNT(*)::int AS total

          FROM attendance
          WHERE member_name = $1
          `,
          [
            `${member.first_name} ${member.last_name}`
          ]
        );

      const stats =
        statsResult.rows[0];

      const total =
        Number(stats.total || 0);

      const yes =
        Number(stats.yes || 0);

      const percentage =
        total > 0
          ? Math.round((yes / total) * 100)
          : 0;

      res.json({
        member: {
          id: member.id,
          first_name: member.first_name,
          last_name: member.last_name,
          role: member.role,
          photo: member.photo || ""
        },
        stats: {
          yes,
          maybe: Number(stats.maybe || 0),
          no: Number(stats.no || 0),
          total,
          percentage
        }
      });
    } catch (error) {
      console.error(
        "GET /api/member-stats:",
        error
      );

      res.status(500).json({
        error:
          "Nie udało się pobrać statystyk."
      });
    }
  }
);

/* =========================
   GENERAL STATS
========================= */

app.get(
  "/api/stats",
  auth,
  async (req, res) => {
    try {
      const members =
        await pool.query(
          "SELECT COUNT(*)::int AS count FROM members"
        );

      const events =
        await pool.query(
          "SELECT COUNT(*)::int AS count FROM events"
        );

      const news =
        await pool.query(
          "SELECT COUNT(*)::int AS count FROM news"
        );

      const attendance =
        await pool.query(`
          SELECT
            COUNT(*)::int AS total,
            COUNT(*) FILTER (
              WHERE status = 'yes'
            )::int AS yes,
            COUNT(*) FILTER (
              WHERE status = 'maybe'
            )::int AS maybe,
            COUNT(*) FILTER (
              WHERE status = 'no'
            )::int AS no
          FROM attendance
        `);

      const row =
        attendance.rows[0];

      const total =
        Number(row.total || 0);

      const yes =
        Number(row.yes || 0);

      const percentage =
        total > 0
          ? Math.round((yes / total) * 100)
          : 0;

      res.json({
        members:
          Number(members.rows[0].count || 0),

        events:
          Number(events.rows[0].count || 0),

        news:
          Number(news.rows[0].count || 0),

        attendance: {
          total,
          yes,
          maybe: Number(row.maybe || 0),
          no: Number(row.no || 0),
          percentage
        }
      });
    } catch (error) {
      console.error(
        "GET /api/stats:",
        error
      );

      res.status(500).json({
        error:
          "Nie udało się pobrać statystyk."
      });
    }
  }
);

/* =========================
   HEALTH
========================= */

app.get(
  "/api/health",
  async (req, res) => {
    try {
      let database = false;

      if (process.env.DATABASE_URL) {
        await pool.query("SELECT 1");
        database = true;
      }

      res.json({
        ok: true,
        database,
        push: pushEnabled
      });
    } catch (error) {
      console.error(
        "Health check:",
        error
      );

      res.status(500).json({
        ok: false,
        database: false,
        push: pushEnabled
      });
    }
  }
);

/* =========================
   FRONTEND FALLBACK
========================= */

app.use(
  (req, res, next) => {
    if (req.method !== "GET") {
      return next();
    }

    if (req.path.startsWith("/api/")) {
      return res.status(404).json({
        error:
          "Nie znaleziono endpointu."
      });
    }

    res.sendFile(
      path.join(
        __dirname,
        "public",
        "index.html"
      )
    );
  }
);

/* =========================
   404
========================= */

app.use(
  (req, res) => {
    res.status(404).json({
      error: "Nie znaleziono."
    });
  }
);

/* =========================
   ERROR HANDLER
========================= */

app.use(
  (error, req, res, next) => {
    console.error(
      "SERVER ERROR:",
      error
    );

    if (res.headersSent) {
      return next(error);
    }

    res.status(500).json({
      error:
        "Wystąpił błąd serwera."
    });
  }
);

/* =========================
   START
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
      "Błąd uruchamiania serwera:",
      error
    );

    process.exit(1);
  }
}

startServer();
