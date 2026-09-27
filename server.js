const express = require("express");
const path = require("path");
const { Pool } = require("pg");
const webpush = require("web-push");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

/* =========================================================
   EXPRESS
========================================================= */

app.use(express.json({ limit: "3mb" }));
app.use(express.urlencoded({ extended: true, limit: "3mb" }));

app.use(
  express.static(
    path.join(__dirname, "public")
  )
);

/* =========================================================
   DATABASE
========================================================= */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,

  ssl: process.env.DATABASE_URL
    ? {
        rejectUnauthorized: false
      }
    : false
});

/* =========================================================
   LOGIN CODES
========================================================= */

const CODES = {
  guardian:
    String(
      process.env.GUARDIAN_CODE ||
      "9982018"
    ),

  admin:
    String(
      process.env.ADMIN_CODE ||
      "0000"
    )
};

/* =========================================================
   WEB PUSH
========================================================= */

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

  console.log(
    "Web Push: VAPID aktywny."
  );
} else {
  console.log(
    "Web Push: brak konfiguracji VAPID."
  );
}

/* =========================================================
   HELPERS
========================================================= */

function clean(value) {
  return String(
    value ?? ""
  ).trim();
}

function hashCode(code) {
  const salt =
    crypto
      .randomBytes(16)
      .toString("hex");

  const hash =
    crypto
      .scryptSync(
        String(code),
        salt,
        64
      )
      .toString("hex");

  return `${salt}:${hash}`;
}

function verifyCode(
  code,
  storedHash
) {
  try {
    if (
      !storedHash ||
      !storedHash.includes(":")
    ) {
      return false;
    }

    const parts =
      storedHash.split(":");

    const salt = parts[0];
    const originalHash = parts[1];

    const hash =
      crypto
        .scryptSync(
          String(code),
          salt,
          64
        )
        .toString("hex");

    const a =
      Buffer.from(
        hash,
        "hex"
      );

    const b =
      Buffer.from(
        originalHash,
        "hex"
      );

    if (
      a.length !==
      b.length
    ) {
      return false;
    }

    return crypto.timingSafeEqual(
      a,
      b
    );
  } catch {
    return false;
  }
}

/* =========================================================
   DATABASE INIT
========================================================= */

async function initDatabase() {
  if (!process.env.DATABASE_URL) {
    console.log(
      "Brak DATABASE_URL."
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
      event_id INTEGER NOT NULL
        REFERENCES events(id)
        ON DELETE CASCADE,
      member_name TEXT NOT NULL,
      status TEXT NOT NULL
        CHECK (
          status IN (
            'yes',
            'maybe',
            'no'
          )
        ),
      UNIQUE(
        event_id,
        member_name
      )
    );

    CREATE TABLE IF NOT EXISTS push_subscriptions (
      id SERIAL PRIMARY KEY,
      endpoint TEXT NOT NULL UNIQUE,
      subscription JSONB NOT NULL,
      role TEXT DEFAULT 'member',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  /* =======================================================
     MEMBER COLUMNS
  ======================================================= */

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

  /* =======================================================
     MIGRATE OLD MEMBERS
  ======================================================= */

  await pool.query(`
    UPDATE members
    SET
      first_name =
        COALESCE(
          NULLIF(
            split_part(
              name,
              ' ',
              1
            ),
            ''
          ),
          'Członek'
        ),

      last_name =
        COALESCE(
          NULLIF(
            regexp_replace(
              name,
              '^\\S+\\s*',
              ''
            ),
            ''
          ),
          ''
        )
    WHERE first_name IS NULL;
  `);

  console.log(
    "Baza danych gotowa."
  );
}

/* =========================================================
   AUTH
========================================================= */

async function auth(
  req,
  res,
  next
) {
  try {
    let role =
      clean(
        req.headers["x-role"]
      ).toLowerCase();

    const code =
      clean(
        req.headers["x-code"]
      );

    /*
      Obsługa różnych nazw roli,
      żeby frontend nie rozwalił logowania.
    */

    if (
      role === "opiekun"
    ) {
      role = "guardian";
    }

    if (
      role === "administrator"
    ) {
      role = "admin";
    }

    if (
      role === "czlonek" ||
      role === "członek"
    ) {
      role = "member";
    }

    if (
      ![
        "member",
        "guardian",
        "admin"
      ].includes(role)
    ) {
      return res.status(401).json({
        error:
          "Brak uprawnień."
      });
    }

    if (!code) {
      return res.status(401).json({
        error:
          "Brak kodu dostępu."
      });
    }

    /* =====================================================
       OPIEKUN / ADMIN
    ===================================================== */

    if (
      role === "guardian" ||
      role === "admin"
    ) {
      if (
        String(code) !==
        String(CODES[role])
      ) {
        return res.status(401).json({
          error:
            "Nieprawidłowy kod."
        });
      }

      req.role = role;

      return next();
    }

    /* =====================================================
       CZŁONEK
    ===================================================== */

    const memberId =
      Number(
        req.headers[
          "x-member-id"
        ]
      );

    if (
      !Number.isInteger(
        memberId
      ) ||
      memberId <= 0
    ) {
      return res.status(401).json({
        error:
          "Brak identyfikatora członka."
      });
    }

    const result =
      await pool.query(
        `
        SELECT *
        FROM members
        WHERE id = $1
        `,
        [memberId]
      );

    if (
      result.rows.length === 0
    ) {
      return res.status(401).json({
        error:
          "Nie znaleziono konta członka."
      });
    }

    const member =
      result.rows[0];

    if (
      !verifyCode(
        code,
        member.code_hash
      )
    ) {
      return res.status(401).json({
        error:
          "Nieprawidłowy kod."
      });
    }

    req.role = "member";
    req.memberId =
      member.id;
    req.member =
      member;

    next();

  } catch (error) {
    console.error(
      "AUTH ERROR:",
      error
    );

    res.status(500).json({
      error:
        "Błąd autoryzacji."
    });
  }
}

/* =========================================================
   STAFF
========================================================= */

function staff(
  req,
  res,
  next
) {
  if (
    req.role !== "guardian" &&
    req.role !== "admin"
  ) {
    return res.status(403).json({
      error:
        "Tylko opiekun lub administrator może wykonać tę operację."
    });
  }

  next();
}

/* =========================================================
   ADMIN ONLY
========================================================= */

function admin(
  req,
  res,
  next
) {
  if (
    req.role !== "admin"
  ) {
    return res.status(403).json({
      error:
        "Tylko administrator może wykonać tę operację."
    });
  }

  next();
}

/* =========================================================
   LOGIN
========================================================= */

app.post(
  "/api/login",
  async (
    req,
    res
  ) => {
    try {
      let role =
        clean(
          req.body?.role
        ).toLowerCase();

      const code =
        clean(
          req.body?.code
        );

      if (
        role === "opiekun"
      ) {
        role = "guardian";
      }

      if (
        role === "administrator"
      ) {
        role = "admin";
      }

      if (
        role === "czlonek" ||
        role === "członek"
      ) {
        role = "member";
      }

      if (
        ![
          "member",
          "guardian",
          "admin"
        ].includes(role)
      ) {
        return res.status(400).json({
          error:
            "Nieprawidłowa rola."
        });
      }

      if (!code) {
        return res.status(400).json({
          error:
            "Podaj kod dostępu."
        });
      }

      /* ===================================================
         OPIEKUN / ADMIN
      =================================================== */

      if (
        role === "guardian" ||
        role === "admin"
      ) {
        if (
          String(code) !==
          String(CODES[role])
        ) {
          return res.status(401).json({
            error:
              "Nieprawidłowy kod."
          });
        }

        return res.json({
          ok: true,
          role: role,
          memberId: null,

          firstName:
            role === "guardian"
              ? "Opiekun"
              : "Administrator",

          lastName: ""
        });
      }

      /* ===================================================
         CZŁONEK
      =================================================== */

      const firstName =
        clean(
          req.body?.firstName
        );

      const lastName =
        clean(
          req.body?.lastName
        );

      if (
        !firstName ||
        !lastName
      ) {
        return res.status(400).json({
          error:
            "Podaj imię i nazwisko."
        });
      }

      const result =
        await pool.query(
          `
          SELECT
            id,
            first_name,
            last_name,
            role,
            photo,
            code_hash
          FROM members

          WHERE
            LOWER(
              TRIM(first_name)
            )
            =
            LOWER(
              TRIM($1)
            )

          AND
            LOWER(
              TRIM(last_name)
            )
            =
            LOWER(
              TRIM($2)
            )

          LIMIT 1
          `,
          [
            firstName,
            lastName
          ]
        );

      if (
        result.rows.length === 0
      ) {
        return res.status(401).json({
          error:
            "Nie znaleziono członka o podanym imieniu i nazwisku."
        });
      }

      const member =
        result.rows[0];

      if (
        !verifyCode(
          code,
          member.code_hash
        )
      ) {
        return res.status(401).json({
          error:
            "Nieprawidłowy kod dostępu."
        });
      }

      return res.json({
        ok: true,

        role:
          "member",

        memberId:
          member.id,

        firstName:
          member.first_name,

        lastName:
          member.last_name,

        member: {
          id:
            member.id,

          first_name:
            member.first_name,

          last_name:
            member.last_name,

          role:
            member.role,

          photo:
            member.photo || ""
        }
      });

    } catch (error) {
      console.error(
        "LOGIN ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Nie udało się zalogować."
      });
    }
  }
);

/* =========================================================
   GET DATA
========================================================= */

app.get(
  "/api/data",
  auth,
  async (
    req,
    res
  ) => {
    try {
      const [
        events,
        news,
        members
      ] =
        await Promise.all([
          pool.query(`
            SELECT *
            FROM events
            ORDER BY
              event_date ASC,
              event_time ASC,
              id DESC
          `),

          pool.query(`
            SELECT *
            FROM news
            ORDER BY
              created_at DESC,
              id DESC
          `),

          pool.query(`
            SELECT
              id,
              first_name,
              last_name,
              name,
              role,
              photo,
              created_at
            FROM members
            ORDER BY
              first_name ASC,
              last_name ASC,
              id ASC
          `)
        ]);

      res.json({
        events:
          events.rows,

        news:
          news.rows,

        members:
          members.rows
      });

    } catch (error) {
      console.error(
        "GET /api/data:",
        error
      );

      res.status(500).json({
        error:
          "Nie udało się pobrać danych."
      });
    }
  }
);

/* =========================================================
   PROFILE GET
========================================================= */

app.get(
  "/api/profile",
  auth,
  async (
    req,
    res
  ) => {
    try {
      if (
        req.role !== "member"
      ) {
        return res.json({
          role:
            req.role,

          first_name:
            req.role ===
            "guardian"
              ? "Opiekun"
              : "Administrator",

          last_name:
            ""
        });
      }

      const result =
        await pool.query(
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
          [
            req.memberId
          ]
        );

      if (
        result.rows.length === 0
      ) {
        return res.status(404).json({
          error:
            "Nie znaleziono profilu."
        });
      }

      res.json(
        result.rows[0]
      );

    } catch (error) {
      console.error(
        "GET /api/profile:",
        error
      );

      res.status(500).json({
        error:
          "Nie udało się pobrać profilu."
      });
    }
  }
);

/* =========================================================
   PROFILE UPDATE
========================================================= */

app.put(
  "/api/profile",
  auth,
  async (
    req,
    res
  ) => {
    try {
      if (
        req.role !== "member"
      ) {
        return res.status(403).json({
          error:
            "Ta funkcja dotyczy członka MDP."
        });
      }

      const photo =
        req.body?.photo ?? "";

      if (
        typeof photo !==
        "string"
      ) {
        return res.status(400).json({
          error:
            "Nieprawidłowe zdjęcie."
        });
      }

      if (
        photo.length >
        1500000
      ) {
        return res.status(400).json({
          error:
            "Zdjęcie jest za duże."
        });
      }

      const result =
        await pool.query(
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
            photo,
            req.memberId
          ]
        );

      res.json({
        ok: true,
        member:
          result.rows[0]
      });

    } catch (error) {
      console.error(
        "PUT /api/profile:",
        error
      );

      res.status(500).json({
        error:
          "Nie udało się zapisać profilu."
      });
    }
  }
);

/* =========================================================
   PUSH SEND
========================================================= */

async function sendPushNotification(
  title,
  body
) {
  if (
    !pushEnabled
  ) {
    return;
  }

  if (
    !process.env.DATABASE_URL
  ) {
    return;
  }

  try {
    const result =
      await pool.query(`
        SELECT
          id,
          subscription

        FROM push_subscriptions
      `);

    for (
      const row of result.rows
    ) {
      try {
        await webpush.sendNotification(
          row.subscription,

          JSON.stringify({
            title,
            body,

            icon:
              "/icon-192-2.png",

            badge:
              "/icon-192-2.png"
          })
        );

      } catch (error) {
        console.error(
          "PUSH ERROR:",
          error.statusCode ||
            error.message
        );

        if (
          error.statusCode ===
            404 ||
          error.statusCode ===
            410
        ) {
          await pool.query(
            `
            DELETE FROM push_subscriptions
            WHERE id = $1
            `,
            [
              row.id
            ]
          );
        }
      }
    }

  } catch (error) {
    console.error(
      "PUSH DATABASE ERROR:",
      error
    );
  }
}

/* =========================================================
   PUSH PUBLIC KEY
========================================================= */

app.get(
  "/api/push/public-key",
  (
    req,
    res
  ) => {
    if (
      !pushEnabled
    ) {
      return res.status(503).json({
        error:
          "Powiadomienia push nie są skonfigurowane."
      });
    }

    res.json({
      publicKey:
        process.env.VAPID_PUBLIC_KEY
    });
  }
);

/* =========================================================
   PUSH SUBSCRIBE
========================================================= */

app.post(
  "/api/push/subscribe",
  auth,
  async (
    req,
    res
  ) => {
    try {
      if (
        !pushEnabled
      ) {
        return res.status(503).json({
          error:
            "Push nie jest skonfigurowany."
        });
      }

      const subscription =
        req.body?.subscription;

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
        INSERT INTO
          push_subscriptions
          (
            endpoint,
            subscription,
            role
          )

        VALUES
          (
            $1,
            $2,
            $3
          )

        ON CONFLICT (
          endpoint
        )

        DO UPDATE SET
          subscription =
            EXCLUDED.subscription,

          role =
            EXCLUDED.role
        `,
        [
          subscription.endpoint,

          JSON.stringify(
            subscription
          ),

          req.role
        ]
      );

      res.json({
        ok: true
      });

    } catch (error) {
      console.error(
        "PUSH SUBSCRIBE:",
        error
      );

      res.status(500).json({
        error:
          "Nie udało się zapisać subskrypcji."
      });
    }
  }
);

/* =========================================================
   PUSH UNSUBSCRIBE
========================================================= */

app.post(
  "/api/push/unsubscribe",
  auth,
  async (
    req,
    res
  ) => {
    try {
      const endpoint =
        clean(
          req.body?.endpoint
        );

      if (!endpoint) {
        return res.status(400).json({
          error:
            "Brak endpointu."
        });
      }

      await pool.query(
        `
        DELETE FROM
          push_subscriptions

        WHERE endpoint = $1
        `,
        [
          endpoint
        ]
      );

      res.json({
        ok: true
      });

    } catch (error) {
      console.error(
        "PUSH UNSUBSCRIBE:",
        error
      );

      res.status(500).json({
        error:
          "Nie udało się wyłączyć powiadomień."
      });
    }
  }
);

/* =========================================================
   PUSH TEST
========================================================= */

app.post(
  "/api/push/test",
  auth,
  staff,
  async (
    req,
    res
  ) => {
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
        "PUSH TEST:",
        error
      );

      res.status(500).json({
        error:
          "Nie udało się wysłać powiadomienia."
      });
    }
  }
);

/* =========================================================
   EVENTS ADD
========================================================= */

app.post(
  "/api/events",
  auth,
  staff,
  async (
    req,
    res
  ) => {
    try {
      /*
        Obsługujemy zarówno
        nazwy używane przez backend,
        jak i typowe nazwy z formularza.
      */

      const title =
        clean(
          req.body?.title ||
          req.body?.name
        );

      const event_date =
        clean(
          req.body?.event_date ||
          req.body?.date
        );

      const event_time =
        clean(
          req.body?.event_time ||
          req.body?.time
        );

      const place =
        clean(
          req.body?.place ||
          req.body?.location ||
          req.body?.address
        );

      const description =
        clean(
          req.body?.description ||
          req.body?.desc ||
          req.body?.text
        );

      console.log(
        "DODAWANIE ZBIÓRKI:",
        {
          role:
            req.role,

          title,

          event_date,

          event_time,

          place,

          description
        }
      );

      if (
        !title ||
        !event_date ||
        !event_time ||
        !place
      ) {
        return res.status(400).json({
          error:
            "Uzupełnij tytuł, datę, godzinę i miejsce."
        });
      }

      const result =
        await pool.query(
          `
          INSERT INTO events
          (
            title,
            event_date,
            event_time,
            place,
            description
          )

          VALUES
          (
            $1,
            $2,
            $3,
            $4,
            $5
          )

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

      const event =
        result.rows[0];

      /*
        Push nie może zablokować
        zapisania zbiórki.
      */

      try {
        await sendPushNotification(
          "📅 Nowa zbiórka MDP",

          `${event.title} — ${event.event_date} o ${event.event_time}`
        );
      } catch (
        pushError
      ) {
        console.error(
          "Błąd push:",
          pushError
        );
      }

      return res.status(201).json({
        ok: true,
        event
      });

    } catch (error) {
      console.error(
        "POST /api/events:",
        error
      );

      return res.status(500).json({
        error:
          "Nie udało się dodać zbiórki."
      });
    }
  }
);

/* =========================================================
   EVENTS DELETE
========================================================= */

app.delete(
  "/api/events/:id",
  auth,
  staff,
  async (
    req,
    res
  ) => {
    try {
      const id =
        Number(
          req.params.id
        );

      if (
        !Number.isInteger(id) ||
        id <= 0
      ) {
        return res.status(400).json({
          error:
            "Nieprawidłowe ID."
        });
      }

      const result =
        await pool.query(
          `
          DELETE FROM events
          WHERE id = $1
          RETURNING id
          `,
          [
            id
          ]
        );

      if (
        result.rows.length ===
        0
      ) {
        return res.status(404).json({
          error:
            "Nie znaleziono zbiórki."
        });
      }

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

/* =========================================================
   NEWS ADD
========================================================= */

app.post(
  "/api/news",
  auth,
  staff,
  async (
    req,
    res
  ) => {
    try {
      const title =
        clean(
          req.body?.title ||
          req.body?.name
        );

      const body =
        clean(
          req.body?.body ||
          req.body?.content ||
          req.body?.description ||
          req.body?.text
        );

      console.log(
        "DODAWANIE OGŁOSZENIA:",
        {
          role:
            req.role,

          title,

          body
        }
      );

      if (
        !title ||
        !body
      ) {
        return res.status(400).json({
          error:
            "Podaj tytuł i treść ogłoszenia."
        });
      }

      const result =
        await pool.query(
          `
          INSERT INTO news
          (
            title,
            body
          )

          VALUES
          (
            $1,
            $2
          )

          RETURNING *
          `,
          [
            title,
            body
          ]
        );

      const news =
        result.rows[0];

      try {
        await sendPushNotification(
          "📢 Nowe ogłoszenie MDP",
          news.title
        );
      } catch (
        pushError
      ) {
        console.error(
          "Błąd push:",
          pushError
        );
      }

      return res.status(201).json({
        ok: true,
        news
      });

    } catch (error) {
      console.error(
        "POST /api/news:",
        error
      );

      return res.status(500).json({
        error:
          "Nie udało się dodać ogłoszenia."
      });
    }
  }
);

/* =========================================================
   NEWS DELETE
========================================================= */

app.delete(
  "/api/news/:id",
  auth,
  staff,
  async (
    req,
    res
  ) => {
    try {
      const id =
        Number(
          req.params.id
        );

      if (
        !Number.isInteger(id) ||
        id <= 0
      ) {
        return res.status(400).json({
          error:
            "Nieprawidłowe ID."
        });
      }

      const result =
        await pool.query(
          `
          DELETE FROM news
          WHERE id = $1
          RETURNING id
          `,
          [
            id
          ]
        );

      if (
        result.rows.length ===
        0
      ) {
        return res.status(404).json({
          error:
            "Nie znaleziono ogłoszenia."
        });
      }

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

/* =========================================================
   MEMBERS ADD
========================================================= */

app.post(
  "/api/members",
  auth,
  staff,
  async (
    req,
    res
  ) => {
    try {
      const firstName =
        clean(
          req.body?.firstName
        );

      const lastName =
        clean(
          req.body?.lastName
        );

      const role =
        clean(
          req.body?.role
        ) ||
        "Członek MDP";

      const code =
        clean(
          req.body?.code
        );

      const photo =
        typeof req.body?.photo ===
        "string"
          ? req.body.photo
          : "";

      if (
        !firstName ||
        !lastName ||
        !code
      ) {
        return res.status(400).json({
          error:
            "Podaj imię, nazwisko oraz kod dostępu."
        });
      }

      if (
        code.length < 4
      ) {
        return res.status(400).json({
          error:
            "Kod dostępu musi mieć co najmniej 4 znaki."
        });
      }

      if (
        photo.length >
        1500000
      ) {
        return res.status(400).json({
          error:
            "Zdjęcie jest za duże."
        });
      }

      const existing =
        await pool.query(
          `
          SELECT id

          FROM members

          WHERE
            LOWER(
              TRIM(first_name)
            )
            =
            LOWER(
              TRIM($1)
            )

          AND
            LOWER(
              TRIM(last_name)
            )
            =
            LOWER(
              TRIM($2)
            )

          LIMIT 1
          `,
          [
            firstName,
            lastName
          ]
        );

      if (
        existing.rows.length
      ) {
        return res.status(409).json({
          error:
            "Członek o takim imieniu i nazwisku już istnieje."
        });
      }

      const name =
        `${firstName} ${lastName}`;

      const codeHash =
        hashCode(
          code
        );

      const result =
        await pool.query(
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

          VALUES
          (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6
          )

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
            firstName,
            lastName,
            role,
            codeHash,
            photo
          ]
        );

      res.status(201).json({
        ok: true,
        member:
          result.rows[0]
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

/* =========================================================
   MEMBERS UPDATE
========================================================= */

app.put(
  "/api/members/:id",
  auth,
  staff,
  async (
    req,
    res
  ) => {
    try {
      const id =
        Number(
          req.params.id
        );

      if (
        !Number.isInteger(id) ||
        id <= 0
      ) {
        return res.status(400).json({
          error:
            "Nieprawidłowe ID."
        });
      }

      const current =
        await pool.query(
          `
          SELECT *
          FROM members
          WHERE id = $1
          `,
          [
            id
          ]
        );

      if (
        current.rows.length ===
        0
      ) {
        return res.status(404).json({
          error:
            "Nie znaleziono członka."
        });
      }

      const member =
        current.rows[0];

      const firstName =
        clean(
          req.body?.firstName
        ) ||
        member.first_name ||
        "";

      const lastName =
        clean(
          req.body?.lastName
        ) ||
        member.last_name ||
        "";

      const role =
        clean(
          req.body?.role
        ) ||
        member.role ||
        "Członek MDP";

      const photo =
        typeof req.body?.photo ===
        "string"
          ? req.body.photo
          : member.photo ||
            "";

      if (
        !firstName ||
        !lastName
      ) {
        return res.status(400).json({
          error:
            "Imię i nazwisko są wymagane."
        });
      }

      if (
        photo.length >
        1500000
      ) {
        return res.status(400).json({
          error:
            "Zdjęcie jest za duże."
        });
      }

      let codeHash =
        member.code_hash;

      const newCode =
        clean(
          req.body?.code
        );

      if (newCode) {
        if (
          newCode.length < 4
        ) {
          return res.status(400).json({
            error:
              "Kod dostępu musi mieć co najmniej 4 znaki."
          });
        }

        codeHash =
          hashCode(
            newCode
          );
      }

      const name =
        `${firstName} ${lastName}`;

      const result =
        await pool.query(
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
            firstName,
            lastName,
            role,
            codeHash,
            photo,
            id
          ]
        );

      res.json({
        ok: true,
        member:
          result.rows[0]
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

/* =========================================================
   MEMBERS DELETE
========================================================= */

app.delete(
  "/api/members/:id",
  auth,
  staff,
  async (
    req,
    res
  ) => {
    try {
      const id =
        Number(
          req.params.id
        );

      if (
        !Number.isInteger(id) ||
        id <= 0
      ) {
        return res.status(400).json({
          error:
            "Nieprawidłowe ID."
        });
      }

      const result =
        await pool.query(
          `
          DELETE FROM members

          WHERE id = $1

          RETURNING id
          `,
          [
            id
          ]
        );

      if (
        result.rows.length ===
        0
      ) {
        return res.status(404).json({
          error:
            "Nie znaleziono członka."
        });
      }

      res.json({
        ok: true
      });

    } catch (error) {
      console.error(
        "DELETE /api/members/:id:",
        error
      );

      res.status(500).json({
        error:
          "Nie udało się usunąć członka."
      });
    }
  }
);

/* =========================================================
   ATTENDANCE SAVE
========================================================= */

app.post(
  "/api/attendance",
  auth,
  async (
    req,
    res
  ) => {
    try {
      const eventId =
        Number(
          req.body?.event_id
        );

      const status =
        clean(
          req.body?.status
        );

      let memberName =
        "";

      if (
        !Number.isInteger(
          eventId
        ) ||
        eventId <= 0
      ) {
        return res.status(400).json({
          error:
            "Nieprawidłowe ID zbiórki."
        });
      }

      if (
        ![
          "yes",
          "maybe",
          "no"
        ].includes(
          status
        )
      ) {
        return res.status(400).json({
          error:
            "Nieprawidłowy status."
        });
      }

      /* CZŁONEK */

      if (
        req.role ===
        "member"
      ) {
        memberName =
          `${req.member.first_name} ${req.member.last_name}`;
      }

      /* OPIEKUN / ADMIN */

      if (
        req.role ===
          "guardian" ||
        req.role ===
          "admin"
      ) {
        const memberId =
          Number(
            req.body?.member_id
          );

        if (
          Number.isInteger(
            memberId
          ) &&
          memberId > 0
        ) {
          const result =
            await pool.query(
              `
              SELECT
                first_name,
                last_name

              FROM members

              WHERE id = $1
              `,
              [
                memberId
              ]
            );

          if (
            result.rows.length ===
            0
          ) {
            return res.status(404).json({
              error:
                "Nie znaleziono członka."
            });
          }

          memberName =
            `${result.rows[0].first_name} ${result.rows[0].last_name}`;
        } else {
          memberName =
            clean(
              req.body?.member_name
            );
        }
      }

      if (!memberName) {
        return res.status(400).json({
          error:
            "Nie znaleziono członka."
        });
      }

      const existing =
        await pool.query(
          `
          SELECT id

          FROM attendance

          WHERE
            event_id = $1
            AND member_name = $2

          LIMIT 1
          `,
          [
            eventId,
            memberName
          ]
        );

      if (
        existing.rows.length
      ) {
        const result =
          await pool.query(
            `
            UPDATE attendance

            SET status = $1

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
          attendance:
            result.rows[0]
        });
      }

      const result =
        await pool.query(
          `
          INSERT INTO attendance
          (
            event_id,
            member_name,
            status
          )

          VALUES
          (
            $1,
            $2,
            $3
          )

          RETURNING *
          `,
          [
            eventId,
            memberName,
            status
          ]
        );

      res.status(201).json({
        ok: true,
        attendance:
          result.rows[0]
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

/* =========================================================
   ATTENDANCE GET
========================================================= */

app.get(
  "/api/attendance/:eventId",
  auth,
  async (
    req,
    res
  ) => {
    try {
      const eventId =
        Number(
          req.params.eventId
        );

      if (
        !Number.isInteger(
          eventId
        ) ||
        eventId <= 0
      ) {
        return res.status(400).json({
          error:
            "Nieprawidłowe ID zbiórki."
        });
      }

      const result =
        await pool.query(
          `
          SELECT *

          FROM attendance

          WHERE event_id = $1

          ORDER BY
            member_name ASC
          `,
          [
            eventId
          ]
        );

      res.json(
        result.rows
      );

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

/* =========================================================
   MEMBER STATS
========================================================= */

app.get(
  "/api/member-stats/:memberId",
  auth,
  async (
    req,
    res
  ) => {
    try {
      const memberId =
        Number(
          req.params.memberId
        );

      if (
        !Number.isInteger(
          memberId
        ) ||
        memberId <= 0
      ) {
        return res.status(400).json({
          error:
            "Nieprawidłowe ID."
        });
      }

      if (
        req.role ===
          "member" &&
        req.memberId !==
          memberId
      ) {
        return res.status(403).json({
          error:
            "Brak dostępu."
        });
      }

      const memberResult =
        await pool.query(
          `
          SELECT *
          FROM members
          WHERE id = $1
          `,
          [
            memberId
          ]
        );

      if (
        memberResult.rows.length ===
        0
      ) {
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

            COUNT(*)
              FILTER (
                WHERE status = 'yes'
              )::int AS yes,

            COUNT(*)
              FILTER (
                WHERE status = 'maybe'
              )::int AS maybe,

            COUNT(*)
              FILTER (
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

      const row =
        statsResult.rows[0];

      const total =
        Number(
          row.total || 0
        );

      const yes =
        Number(
          row.yes || 0
        );

      res.json({
        member: {
          id:
            member.id,

          first_name:
            member.first_name,

          last_name:
            member.last_name,

          role:
            member.role,

          photo:
            member.photo || ""
        },

        stats: {
          yes,

          maybe:
            Number(
              row.maybe || 0
            ),

          no:
            Number(
              row.no || 0
            ),

          total,

          percentage:
            total
              ? Math.round(
                  (yes / total) *
                    100
                )
              : 0
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

/* =========================================================
   GENERAL STATS
========================================================= */

app.get(
  "/api/stats",
  auth,
  async (
    req,
    res
  ) => {
    try {
      const [
        members,
        events,
        news,
        attendance
      ] =
        await Promise.all([
          pool.query(
            `
            SELECT
              COUNT(*)::int AS count
            FROM members
            `
          ),

          pool.query(
            `
            SELECT
              COUNT(*)::int AS count
            FROM events
            `
          ),

          pool.query(
            `
            SELECT
              COUNT(*)::int AS count
            FROM news
            `
          ),

          pool.query(`
            SELECT

              COUNT(*)::int
                AS total,

              COUNT(*)
                FILTER (
                  WHERE status = 'yes'
                )::int
                AS yes,

              COUNT(*)
                FILTER (
                  WHERE status = 'maybe'
                )::int
                AS maybe,

              COUNT(*)
                FILTER (
                  WHERE status = 'no'
                )::int
                AS no

            FROM attendance
          `)
        ]);

      const row =
        attendance.rows[0];

      const total =
        Number(
          row.total || 0
        );

      const yes =
        Number(
          row.yes || 0
        );

      res.json({
        members:
          Number(
            members.rows[0].count
          ),

        events:
          Number(
            events.rows[0].count
          ),

        news:
          Number(
            news.rows[0].count
          ),

        attendance: {
          total,

          yes,

          maybe:
            Number(
              row.maybe || 0
            ),

          no:
            Number(
              row.no || 0
            ),

          percentage:
            total
              ? Math.round(
                  (yes / total) *
                    100
                )
              : 0
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

/* =========================================================
   HEALTH
========================================================= */

app.get(
  "/api/health",
  async (
    req,
    res
  ) => {
    try {
      let database =
        false;

      if (
        process.env.DATABASE_URL
      ) {
        await pool.query(
          "SELECT 1"
        );

        database =
          true;
      }

      res.json({
        ok: true,

        database,

        push:
          pushEnabled
      });

    } catch (error) {
      console.error(
        "HEALTH:",
        error
      );

      res.status(500).json({
        ok: false,

        database:
          false,

        push:
          pushEnabled
      });
    }
  }
);

/* =========================================================
   FRONTEND FALLBACK
========================================================= */

app.use(
  (
    req,
    res,
    next
  ) => {
    if (
      req.method !==
      "GET"
    ) {
      return next();
    }

    if (
      req.path.startsWith(
        "/api/"
      )
    ) {
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

/* =========================================================
   404
========================================================= */

app.use(
  (
    req,
    res
  ) => {
    res.status(404).json({
      error:
        "Nie znaleziono."
    });
  }
);

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
  (
    error,
    req,
    res,
    next
  ) => {
    console.error(
      "SERVER ERROR:",
      error
    );

    if (
      res.headersSent
    ) {
      return next(
        error
      );
    }

    res.status(500).json({
      error:
        "Wystąpił błąd serwera."
    });
  }
);

/* =========================================================
   START
========================================================= */

async function startServer() {
  try {
    await initDatabase();

    app.listen(
      PORT,
      () => {
        console.log(
          `MDP Wiesiółka działa na porcie ${PORT}.`
        );

        console.log(
          "Opiekun:",
          Boolean(
            CODES.guardian
          )
        );

        console.log(
          "Admin:",
          Boolean(
            CODES.admin
          )
        );

        console.log(
          "Push:",
          pushEnabled
        );
      }
    );

  } catch (error) {
    console.error(
      "BŁĄD URUCHAMIANIA:",
      error
    );

    process.exit(1);
  }
}

startServer();
