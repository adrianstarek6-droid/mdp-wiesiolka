const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');
const webpush = require('web-push');

const app = express();
const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

const GUARDIAN_CODE = process.env.GUARDIAN_CODE || '9982018';
const ADMIN_CODE = process.env.ADMIN_CODE || '0000';

const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY || '';
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY || '';
const VAPID_EMAIL =
  process.env.VAPID_EMAIL || 'mailto:admin@example.com';

if (VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY) {
  webpush.setVapidDetails(
    VAPID_EMAIL,
    VAPID_PUBLIC_KEY,
    VAPID_PRIVATE_KEY
  );
}

app.use(express.json({ limit: '3mb' }));
app.use(express.urlencoded({ extended: true, limit: '3mb' }));

app.use(express.static(path.join(__dirname, 'public')));

const hashCode = code =>
  crypto
    .createHash('sha256')
    .update(String(code || ''))
    .digest('hex');

const normRole = role => {
  const r = String(role || '')
    .toLowerCase()
    .trim();

  if (['opiekun', 'guardian'].includes(r)) {
    return 'guardian';
  }

  if (['admin', 'administrator'].includes(r)) {
    return 'admin';
  }

  if (['member', 'czlonek', 'członek'].includes(r)) {
    return 'member';
  }

  return r;
};

const isStaff = req =>
  req.role === 'admin' || req.role === 'guardian';

async function auth(req, res, next) {
  const role = normRole(req.headers['x-role']);

  const code = String(
    req.headers['x-code'] ||
    req.headers['x-access-code'] ||
    ''
  );

  const memberId = String(
    req.headers['x-member-id'] ||
    req.headers['x-memberid'] ||
    ''
  );

  req.role = role;
  req.memberId = memberId;

  try {
    if (role === 'admin' && code === ADMIN_CODE) {
      req.authenticated = true;
      return next();
    }

    if (role === 'guardian' && code === GUARDIAN_CODE) {
      req.authenticated = true;
      return next();
    }

    if (role === 'member' && memberId && code) {
      const r = await pool.query(
        `
        SELECT
          id,
          first_name,
          last_name,
          role,
          photo,
          code_hash
        FROM members
        WHERE id=$1
        `,
        [memberId]
      );

      if (
        !r.rows[0] ||
        r.rows[0].code_hash !== hashCode(code)
      ) {
        return res.status(401).json({
          error: 'Nieprawidłowe dane logowania.'
        });
      }

      req.member = r.rows[0];
      req.authenticated = true;

      return next();
    }

    return res.status(401).json({
      error: 'Brak autoryzacji.'
    });
  } catch (e) {
    console.error(e);

    return res.status(500).json({
      error: 'Błąd autoryzacji.'
    });
  }
}

function staff(req, res, next) {
  return isStaff(req)
    ? next()
    : res.status(403).json({
        error: 'Brak uprawnień.'
      });
}


/* =========================================================
   BAZA DANYCH
========================================================= */

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS events (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      event_date TEXT,
      event_time TEXT,
      place TEXT,
      description TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS news (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      body TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS members (
      id SERIAL PRIMARY KEY,
      name TEXT,
      role TEXT DEFAULT 'member',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      first_name TEXT,
      last_name TEXT,
      code_hash TEXT,
      photo TEXT
    );

    CREATE TABLE IF NOT EXISTS attendance (
      id SERIAL PRIMARY KEY,
      event_id INTEGER NOT NULL
        REFERENCES events(id)
        ON DELETE CASCADE,
      member_name TEXT NOT NULL,
      status TEXT NOT NULL
        CHECK (status IN ('yes','maybe','no')),
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(event_id, member_name)
    );

    CREATE TABLE IF NOT EXISTS push_subscriptions (
      id SERIAL PRIMARY KEY,
      endpoint TEXT UNIQUE NOT NULL,
      subscription JSONB NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS urgent_messages (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      created_by_role TEXT
    );

    CREATE TABLE IF NOT EXISTS member_reports (
      id SERIAL PRIMARY KEY,
      member_id INTEGER
        REFERENCES members(id)
        ON DELETE CASCADE,
      member_name TEXT NOT NULL,
      report_type TEXT NOT NULL,
      body TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'new'
        CHECK (status IN ('new','in_progress','done')),
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS newspaper_groups (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      region TEXT NOT NULL,
      color TEXT NOT NULL DEFAULT '#2878ff',
      streets JSONB NOT NULL DEFAULT '[]'::jsonb,
      copies INTEGER NOT NULL DEFAULT 0,
      delivered INTEGER NOT NULL DEFAULT 0,
      started BOOLEAN NOT NULL DEFAULT FALSE,
      done BOOLEAN NOT NULL DEFAULT FALSE,
      member_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
      member_names JSONB NOT NULL DEFAULT '[]'::jsonb,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS newspaper_history (
      id SERIAL PRIMARY KEY,
      month_key TEXT NOT NULL,
      month_label TEXT NOT NULL,
      saved_at TIMESTAMPTZ DEFAULT NOW(),
      groups JSONB NOT NULL DEFAULT '[]'::jsonb
    );
  `);

  await pool.query(`
    ALTER TABLE members
    ADD COLUMN IF NOT EXISTS first_name TEXT
  `);

  await pool.query(`
    ALTER TABLE members
    ADD COLUMN IF NOT EXISTS last_name TEXT
  `);

  await pool.query(`
    ALTER TABLE members
    ADD COLUMN IF NOT EXISTS code_hash TEXT
  `);

  await pool.query(`
    ALTER TABLE members
    ADD COLUMN IF NOT EXISTS photo TEXT
  `);

  const c = await pool.query(`
    SELECT COUNT(*)::int AS count
    FROM newspaper_groups
  `);

  if (c.rows[0].count === 0) {
    await seedNewspaperGroups();
  }
}


/* =========================================================
   DOMYŚLNE GRUPY GAZET
========================================================= */

async function seedNewspaperGroups() {
  const groups = [
    [
      'Wiesiółka',
      'Henryka Pobożnego i to osiedle',
      '#2878ff',
      ['Henryka Pobożnego'],
      75
    ],
    [
      'Wysoka',
      '3 bloki — Sportowa, Parkowa, Robotnicza',
      '#36b86b',
      [
        'Sportowa',
        'Parkowa',
        'Robotnicza'
      ],
      85
    ],
    [
      'Wysoka — Kościuszki',
      'Kościuszki → do Dzwonka',
      '#ff9d2e',
      ['Kościuszki — do Dzwonka'],
      90
    ],
    [
      'Kopanina',
      'Kopanina',
      '#e23b45',
      [],
      45
    ],
    [
      'Gięto',
      'Gięto',
      '#a66cff',
      [],
      75
    ]
  ];

  for (const g of groups) {
    await pool.query(
      `
      INSERT INTO newspaper_groups
      (
        name,
        region,
        color,
        streets,
        copies
      )
      VALUES
      (
        $1,
        $2,
        $3,
        $4::jsonb,
        $5
      )
      `,
      [
        g[0],
        g[1],
        g[2],
        JSON.stringify(g[3]),
        g[4]
      ]
    );
  }
}

function groupJson(row, members = []) {
  return {
    id: row.id,
    name: row.name,
    region: row.region,
    color: row.color,

    streets: Array.isArray(row.streets)
      ? row.streets
      : [],

    copies: Number(row.copies || 0),

    delivered: Number(
      row.delivered || 0
    ),

    started: !!row.started,
    done: !!row.done,

    memberIds: Array.isArray(row.member_ids)
      ? row.member_ids.map(Number)
      : [],

    memberNames: Array.isArray(row.member_names)
      ? row.member_names
      : [],

    members
  };
}

async function getGroups() {
  const [g, m] = await Promise.all([
    pool.query(`
      SELECT *
      FROM newspaper_groups
      ORDER BY id
    `),

    pool.query(`
      SELECT
        id,
        first_name,
        last_name,
        name
      FROM members
      ORDER BY first_name,last_name,id
    `)
  ]);

  const members = m.rows;

  return g.rows.map(row => {
    let ids = Array.isArray(row.member_ids)
      ? row.member_ids.map(Number)
      : [];

    let names = Array.isArray(row.member_names)
      ? row.member_names.map(String)
      : [];

    if (!ids.length && names.length) {
      ids = members
        .filter(x =>
          names.includes(
            `${x.first_name || ''} ${x.last_name || ''}`.trim()
          ) ||
          names.includes(x.name || '')
        )
        .map(x => x.id);
    }

    const groupMembers = members.filter(x =>
      ids.includes(Number(x.id))
    );

    return groupJson(
      {
        ...row,
        member_ids: ids,
        member_names: names
      },
      groupMembers
    );
  });
}


/* =========================================================
   POWIADOMIENIA PUSH
========================================================= */

async function sendPushToAll(payload) {
  if (
    !VAPID_PUBLIC_KEY ||
    !VAPID_PRIVATE_KEY
  ) {
    return;
  }

  const r = await pool.query(`
    SELECT
      id,
      endpoint,
      subscription
    FROM push_subscriptions
  `);

  for (const s of r.rows) {
    try {
      await webpush.sendNotification(
        s.subscription,
        JSON.stringify(payload)
      );
    } catch (e) {
      if (
        e.statusCode === 404 ||
        e.statusCode === 410
      ) {
        await pool.query(
          `
          DELETE FROM push_subscriptions
          WHERE id=$1
          `,
          [s.id]
        );
      }
    }
  }
}


/* =========================================================
   LOGOWANIE
========================================================= */

app.post('/api/login', async (req, res) => {
  try {
    const role = normRole(req.body.role);

    const code = String(
      req.body.code ||
      req.body.password ||
      ''
    );

    if (
      role === 'admin' &&
      code === ADMIN_CODE
    ) {
      return res.json({
        role: 'admin'
      });
    }

    if (
      role === 'guardian' &&
      code === GUARDIAN_CODE
    ) {
      return res.json({
        role: 'guardian'
      });
    }

    if (role === 'member') {
      const r = await pool.query(
        `
        SELECT
          id,
          first_name,
          last_name,
          role,
          photo
        FROM members
        WHERE code_hash=$1
        ORDER BY id
        LIMIT 1
        `,
        [hashCode(code)]
      );

      const m = r.rows[0];

      if (!m) {
        return res.status(401).json({
          error: 'Nieprawidłowy kod członka.'
        });
      }

      return res.json({
        role: 'member',
        memberId: m.id,
        firstName: m.first_name || '',
        lastName: m.last_name || '',

        member: {
          id: m.id,
          first_name: m.first_name || '',
          last_name: m.last_name || '',
          role: m.role || 'member',
          photo: m.photo || ''
        }
      });
    }

    return res.status(401).json({
      error: 'Nieprawidłowe dane logowania.'
    });

  } catch (e) {
    console.error(e);

    res.status(500).json({
      error: 'Błąd logowania.'
    });
  }
});


/* =========================================================
   DANE
========================================================= */

app.get('/api/data', auth, async (req, res) => {
  try {
    const [
      events,
      news,
      members,
      urgent
    ] = await Promise.all([
      pool.query(`
        SELECT *
        FROM events
        ORDER BY
          event_date ASC NULLS LAST,
          event_time ASC NULLS LAST,
          id DESC
      `),

      pool.query(`
        SELECT *
        FROM news
        ORDER BY created_at DESC,id DESC
      `),

      pool.query(`
        SELECT
          id,
          first_name,
          last_name,
          role,
          photo,
          name,
          created_at
        FROM members
        ORDER BY first_name,last_name,id
      `),

      pool.query(`
        SELECT
          id,
          title,
          body,
          active,
          created_at
        FROM urgent_messages
        WHERE active=TRUE
        ORDER BY created_at DESC,id DESC
      `)
    ]);

    res.json({
      events: events.rows,
      news: news.rows,
      members: members.rows,
      urgent: urgent.rows
    });

  } catch (e) {
    console.error(e);

    res.status(500).json({
      error: 'Nie udało się pobrać danych.'
    });
  }
});


/* =========================================================
   STATYSTYKI
========================================================= */

app.get('/api/stats', auth, async (req, res) => {
  try {
    const [m, e, n] = await Promise.all([
      pool.query(`
        SELECT COUNT(*)::int c
        FROM members
      `),

      pool.query(`
        SELECT COUNT(*)::int c
        FROM events
      `),

      pool.query(`
        SELECT COUNT(*)::int c
        FROM news
      `)
    ]);

    res.json({
      members: m.rows[0].c,
      events: e.rows[0].c,
      news: n.rows[0].c
    });

  } catch (e) {
    res.status(500).json({
      error: 'Błąd statystyk.'
    });
  }
});


/* =========================================================
   ZBIÓRKI
========================================================= */

app.post(
  '/api/events',
  auth,
  staff,
  async (req, res) => {
    try {
      const b = req.body;

      const title = String(
        b.title ||
        b.name ||
        ''
      ).trim();

      if (!title) {
        return res.status(400).json({
          error: 'Podaj nazwę zbiórki.'
        });
      }

      const r = await pool.query(
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
        ($1,$2,$3,$4,$5)
        RETURNING *
        `,
        [
          title,
          b.event_date ||
            b.date ||
            null,

          b.event_time ||
            b.time ||
            null,

          b.place ||
            b.location ||
            b.address ||
            '',

          b.description ||
            b.desc ||
            b.text ||
            ''
        ]
      );

      try {
        await sendPushToAll({
          title: 'Nowa zbiórka MDP',
          body: title
        });
      } catch (e) {
        console.error(e);
      }

      res.json(r.rows[0]);

    } catch (e) {
      console.error(e);

      res.status(500).json({
        error: 'Nie udało się dodać zbiórki.'
      });
    }
  }
);

app.delete(
  '/api/events/:id',
  auth,
  staff,
  async (req, res) => {
    try {
      await pool.query(
        `
        DELETE FROM events
        WHERE id=$1
        `,
        [req.params.id]
      );

      res.json({
        ok: true
      });

    } catch (e) {
      res.status(500).json({
        error: 'Nie udało się usunąć zbiórki.'
      });
    }
  }
);


/* =========================================================
   OGŁOSZENIA
========================================================= */

app.post(
  '/api/news',
  auth,
  staff,
  async (req, res) => {
    try {
      const b = req.body;

      const title = String(
        b.title ||
        b.name ||
        ''
      ).trim();

      if (!title) {
        return res.status(400).json({
          error: 'Podaj tytuł ogłoszenia.'
        });
      }

      const r = await pool.query(
        `
        INSERT INTO news(title,body)
        VALUES($1,$2)
        RETURNING *
        `,
        [
          title,
          b.body ||
            b.content ||
            b.description ||
            b.text ||
            ''
        ]
      );

      try {
        await sendPushToAll({
          title: 'Nowe ogłoszenie MDP',
          body: title
        });
      } catch (e) {
        console.error(e);
      }

      res.json(r.rows[0]);

    } catch (e) {
      console.error(e);

      res.status(500).json({
        error: 'Nie udało się dodać ogłoszenia.'
      });
    }
  }
);

app.delete(
  '/api/news/:id',
  auth,
  staff,
  async (req, res) => {
    try {
      await pool.query(
        `
        DELETE FROM news
        WHERE id=$1
        `,
        [req.params.id]
      );

      res.json({
        ok: true
      });

    } catch (e) {
      res.status(500).json({
        error: 'Nie udało się usunąć ogłoszenia.'
      });
    }
  }
);


/* =========================================================
   PILNE KOMUNIKATY
========================================================= */

app.post(
  '/api/urgent-messages',
  auth,
  staff,
  async (req, res) => {
    try {
      const title = String(
        req.body.title || ''
      ).trim();

      const body = String(
        req.body.body ||
        req.body.content ||
        ''
      ).trim();

      if (!title || !body) {
        return res.status(400).json({
          error:
            'Podaj tytuł i treść komunikatu.'
        });
      }

      await pool.query(`
        UPDATE urgent_messages
        SET active=FALSE
        WHERE active=TRUE
      `);

      const r = await pool.query(
        `
        INSERT INTO urgent_messages
        (
          title,
          body,
          active,
          created_by_role
        )
        VALUES
        ($1,$2,TRUE,$3)
        RETURNING *
        `,
        [
          title,
          body,
          req.role
        ]
      );

      try {
        await sendPushToAll({
          title: '🚨 PILNY KOMUNIKAT MDP',
          body: title
        });
      } catch (e) {
        console.error(e);
      }

      res.json(r.rows[0]);

    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Nie udało się dodać pilnego komunikatu.'
      });
    }
  }
);

app.get(
  '/api/urgent-messages',
  auth,
  async (req, res) => {
    try {
      const r = await pool.query(
        req.role === 'admin' ||
        req.role === 'guardian'
          ? `
            SELECT *
            FROM urgent_messages
            ORDER BY created_at DESC,id DESC
          `
          : `
            SELECT *
            FROM urgent_messages
            WHERE active=TRUE
            ORDER BY created_at DESC,id DESC
          `
      );

      res.json(r.rows);

    } catch (e) {
      res.status(500).json({
        error:
          'Nie udało się pobrać komunikatów.'
      });
    }
  }
);

app.delete(
  '/api/urgent-messages/:id',
  auth,
  staff,
  async (req, res) => {
    try {
      await pool.query(
        `
        UPDATE urgent_messages
        SET active=FALSE
        WHERE id=$1
        `,
        [req.params.id]
      );

      res.json({
        ok: true
      });

    } catch (e) {
      res.status(500).json({
        error:
          'Nie udało się ukryć komunikatu.'
      });
    }
  }
);


/* =========================================================
   ZGŁOSZENIA OD CZŁONKÓW
========================================================= */

app.post(
  '/api/member-reports',
  auth,
  async (req, res) => {
    try {
      if (req.role !== 'member') {
        return res.status(403).json({
          error:
            'Tylko członek może wysłać zgłoszenie.'
        });
      }

      const type = String(
        req.body.type || 'Inne'
      ).trim();

      const body = String(
        req.body.body || ''
      ).trim();

      if (!body) {
        return res.status(400).json({
          error:
            'Napisz treść zgłoszenia.'
        });
      }

      const memberName =
        `${req.member.first_name || ''} ${req.member.last_name || ''}`
          .trim() ||
        'Członek MDP';

      const r = await pool.query(
        `
        INSERT INTO member_reports
        (
          member_id,
          member_name,
          report_type,
          body
        )
        VALUES
        ($1,$2,$3,$4)
        RETURNING *
        `,
        [
          req.member.id,
          memberName,
          type,
          body
        ]
      );

      try {
        await sendPushToAll({
          title:
            'Nowe zgłoszenie od członka',
          body:
            `${memberName}: ${type}`
        });
      } catch (e) {
        console.error(e);
      }

      res.json(r.rows[0]);

    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Nie udało się wysłać zgłoszenia.'
      });
    }
  }
);

app.get(
  '/api/member-reports',
  auth,
  staff,
  async (req, res) => {
    try {
      const r = await pool.query(`
        SELECT *
        FROM member_reports
        ORDER BY
          CASE status
            WHEN 'new' THEN 0
            WHEN 'in_progress' THEN 1
            ELSE 2
          END,
          created_at DESC,
          id DESC
      `);

      res.json(r.rows);

    } catch (e) {
      res.status(500).json({
        error:
          'Nie udało się pobrać zgłoszeń.'
      });
    }
  }
);

app.put(
  '/api/member-reports/:id',
  auth,
  staff,
  async (req, res) => {
    try {
      const status = String(
        req.body.status || ''
      ).trim();

      if (
        ![
          'new',
          'in_progress',
          'done'
        ].includes(status)
      ) {
        return res.status(400).json({
          error:
            'Nieprawidłowy status zgłoszenia.'
        });
      }

      const r = await pool.query(
        `
        UPDATE member_reports
        SET
          status=$1,
          updated_at=NOW()
        WHERE id=$2
        RETURNING *
        `,
        [
          status,
          req.params.id
        ]
      );

      if (!r.rows[0]) {
        return res.status(404).json({
          error:
            'Nie znaleziono zgłoszenia.'
        });
      }

      res.json(r.rows[0]);

    } catch (e) {
      res.status(500).json({
        error:
          'Nie udało się zmienić statusu zgłoszenia.'
      });
    }
  }
);


/* =========================================================
   CZŁONKOWIE
========================================================= */

app.post(
  '/api/members',
  auth,
  staff,
  async (req, res) => {
    try {
      const first = String(
        req.body.first_name ||
        req.body.firstName ||
        ''
      ).trim();

      const last = String(
        req.body.last_name ||
        req.body.lastName ||
        ''
      ).trim();

      const code = String(
        req.body.code || ''
      ).trim();

      if (!first || !last || !code) {
        return res.status(400).json({
          error:
            'Podaj imię, nazwisko i kod.'
        });
      }

      const r = await pool.query(
        `
        INSERT INTO members
        (
          first_name,
          last_name,
          name,
          role,
          code_hash
        )
        VALUES
        ($1,$2,$3,$4,$5)
        RETURNING
          id,
          first_name,
          last_name,
          role,
          photo
        `,
        [
          first,
          last,
          `${first} ${last}`,
          req.body.role || 'member',
          hashCode(code)
        ]
      );

      res.json(r.rows[0]);

    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Nie udało się dodać członka.'
      });
    }
  }
);

app.put(
  '/api/members/:id',
  auth,
  staff,
  async (req, res) => {
    try {
      const b = req.body;

      const r = await pool.query(
        `
        UPDATE members
        SET
          first_name=COALESCE($1,first_name),
          last_name=COALESCE($2,last_name),
          name=COALESCE($3,name),
          role=COALESCE($4,role),
          code_hash=COALESCE($5,code_hash),
          photo=COALESCE($6,photo)
        WHERE id=$7
        RETURNING
          id,
          first_name,
          last_name,
          role,
          photo
        `,
        [
          b.first_name ||
            b.firstName ||
            null,

          b.last_name ||
            b.lastName ||
            null,

          b.name ||
            null,

          b.role ||
            null,

          b.code
            ? hashCode(b.code)
            : null,

          b.photo ||
            null,

          req.params.id
        ]
      );

      if (!r.rows[0]) {
        return res.status(404).json({
          error:
            'Nie znaleziono członka.'
        });
      }

      res.json(r.rows[0]);

    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Nie udało się zmienić członka.'
      });
    }
  }
);

app.delete(
  '/api/members/:id',
  auth,
  staff,
  async (req, res) => {
    try {
      await pool.query(
        `
        DELETE FROM members
        WHERE id=$1
        `,
        [req.params.id]
      );

      res.json({
        ok: true
      });

    } catch (e) {
      res.status(500).json({
        error:
          'Nie udało się usunąć członka.'
      });
    }
  }
);


/* =========================================================
   PROFIL
========================================================= */

app.get(
  '/api/profile',
  auth,
  async (req, res) => {
    try {
      if (req.role !== 'member') {
        return res.json({
          role: req.role
        });
      }

      const r = await pool.query(
        `
        SELECT
          id,
          first_name,
          last_name,
          role,
          photo
        FROM members
        WHERE id=$1
        `,
        [req.member.id]
      );

      res.json(
        r.rows[0] || {}
      );

    } catch (e) {
      res.status(500).json({
        error:
          'Błąd profilu.'
      });
    }
  }
);

app.put(
  '/api/profile',
  auth,
  async (req, res) => {
    try {
      if (req.role !== 'member') {
        return res.status(403).json({
          error:
            'Brak uprawnień.'
        });
      }

      const r = await pool.query(
        `
        UPDATE members
        SET photo=$1
        WHERE id=$2
        RETURNING
          id,
          first_name,
          last_name,
          role,
          photo
        `,
        [
          req.body.photo || '',
          req.member.id
        ]
      );

      res.json(
        r.rows[0] || {}
      );

    } catch (e) {
      res.status(500).json({
        error:
          'Nie udało się zapisać profilu.'
      });
    }
  }
);


/* =========================================================
   OBECNOŚĆ
========================================================= */

async function saveAttendance(
  req,
  res,
  eventIdFromPath = null
) {
  try {
    const eventId = Number(
      eventIdFromPath ||
      req.body.event_id ||
      req.body.eventId
    );

    const status = String(
      req.body.status || ''
    ).toLowerCase();

    if (
      !Number.isInteger(eventId) ||
      eventId <= 0
    ) {
      return res.status(400).json({
        error:
          'Nieprawidłowe ID zbiórki.'
      });
    }

    if (
      ![
        'yes',
        'maybe',
        'no'
      ].includes(status)
    ) {
      return res.status(400).json({
        error:
          'Nieprawidłowy status.'
      });
    }

    const ev = await pool.query(
      `
      SELECT id
      FROM events
      WHERE id=$1
      `,
      [eventId]
    );

    if (!ev.rows[0]) {
      return res.status(404).json({
        error:
          'Nie znaleziono zbiórki.'
      });
    }

    let memberName = '';

    if (req.role === 'member') {
      memberName =
        `${req.member.first_name || ''} ${req.member.last_name || ''}`
          .trim();
    } else if (req.body.member_id) {
      const m = await pool.query(
        `
        SELECT
          first_name,
          last_name
        FROM members
        WHERE id=$1
        `,
        [req.body.member_id]
      );

      if (m.rows[0]) {
        memberName =
          `${m.rows[0].first_name || ''} ${m.rows[0].last_name || ''}`
            .trim();
      }
    } else {
      memberName = String(
        req.body.member_name || ''
      ).trim();
    }

    if (!memberName) {
      return res.status(400).json({
        error:
          'Nie znaleziono członka.'
      });
    }

    await pool.query(
      `
      INSERT INTO attendance
      (
        event_id,
        member_name,
        status
      )
      VALUES
      ($1,$2,$3)
      ON CONFLICT
      (
        event_id,
        member_name
      )
      DO UPDATE SET
        status=EXCLUDED.status
      `,
      [
        eventId,
        memberName,
        status
      ]
    );

    res.json({
      ok: true,
      event_id: eventId,
      member_name: memberName,
      status
    });

  } catch (e) {
    console.error(e);

    res.status(500).json({
      error:
        'Nie udało się zapisać obecności.'
    });
  }
}

app.post(
  '/api/attendance',
  auth,
  (req, res) =>
    saveAttendance(req, res)
);

app.post(
  '/api/attendance/:eventId',
  auth,
  (req, res) =>
    saveAttendance(
      req,
      res,
      req.params.eventId
    )
);

app.get(
  '/api/attendance/:eventId',
  auth,
  async (req, res) => {
    try {
      const r = await pool.query(
        `
        SELECT *
        FROM attendance
        WHERE event_id=$1
        ORDER BY member_name
        `,
        [req.params.eventId]
      );

      res.json(r.rows);

    } catch (e) {
      res.status(500).json({
        error:
          'Nie udało się pobrać obecności.'
      });
    }
  }
);

app.get(
  '/api/member-stats/:memberId',
  auth,
  async (req, res) => {
    try {
      if (
        req.role === 'member' &&
        String(req.member.id) !==
          String(req.params.memberId)
      ) {
        return res.status(403).json({
          error:
            'Brak dostępu.'
        });
      }

      const m = await pool.query(
        `
        SELECT
          id,
          first_name,
          last_name,
          role,
          photo
        FROM members
        WHERE id=$1
        `,
        [req.params.memberId]
      );

      if (!m.rows[0]) {
        return res.status(404).json({
          error:
            'Nie znaleziono członka.'
        });
      }

      const name =
        `${m.rows[0].first_name || ''} ${m.rows[0].last_name || ''}`
          .trim();

      const r = await pool.query(
        `
        SELECT
          status,
          COUNT(*)::int count
        FROM attendance
        WHERE member_name=$1
        GROUP BY status
        `,
        [name]
      );

      const s = {
        yes: 0,
        maybe: 0,
        no: 0
      };

      r.rows.forEach(x => {
        s[x.status] = x.count;
      });

      const confirmed =
        s.yes + s.no;

      const total =
        confirmed + s.maybe;

      res.json({
        member: m.rows[0],

        stats: {
          yes: s.yes,
          no: s.no,
          maybe: s.maybe,
          attended: s.yes,
          absent: s.no,
          confirmed,
          total,

          percentage:
            confirmed
              ? Math.round(
                  s.yes /
                    confirmed *
                    100
                )
              : 0
        }
      });

    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Nie udało się pobrać frekwencji.'
      });
    }
  }
);


/* =========================================================
   ECHO ŁAZ / GAZETY
========================================================= */

app.get(
  '/api/newspaper-groups',
  auth,
  async (req, res) => {
    try {
      res.json(
        await getGroups()
      );
    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Nie udało się pobrać grup gazet.'
      });
    }
  }
);

app.post(
  '/api/newspaper-groups',
  auth,
  staff,
  async (req, res) => {
    try {
      const b = req.body;

      const name = String(
        b.name || ''
      ).trim();

      const region = String(
        b.region || ''
      ).trim();

      if (!name || !region) {
        return res.status(400).json({
          error:
            'Podaj nazwę grupy i region.'
        });
      }

      const ids =
        Array.isArray(b.memberIds)
          ? b.memberIds
              .map(Number)
              .filter(Number.isFinite)
          : [];

      const m = ids.length
        ? await pool.query(
            `
            SELECT
              id,
              first_name,
              last_name,
              name
            FROM members
            WHERE id=ANY($1::int[])
            `,
            [ids]
          )
        : { rows: [] };

      const names = m.rows
        .map(x =>
          `${x.first_name || ''} ${x.last_name || ''}`.trim()
        )
        .filter(Boolean);

      const copies = Math.max(
        0,
        Number(b.copies || 0)
      );

      const r = await pool.query(
        `
        INSERT INTO newspaper_groups
        (
          name,
          region,
          color,
          streets,
          copies,
          member_ids,
          member_names
        )
        VALUES
        (
          $1,
          $2,
          $3,
          $4::jsonb,
          $5,
          $6::jsonb,
          $7::jsonb
        )
        RETURNING *
        `,
        [
          name,
          region,
          b.color || '#2878ff',
          JSON.stringify(
            Array.isArray(b.streets)
              ? b.streets
              : []
          ),
          copies,
          JSON.stringify(ids),
          JSON.stringify(names)
        ]
      );

      res.json(
        groupJson(
          r.rows[0],
          m.rows
        )
      );

    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Nie udało się zapisać grupy gazet.'
      });
    }
  }
);

app.put(
  '/api/newspaper-groups/:id',
  auth,
  async (req, res) => {
    try {
      const oldR = await pool.query(
        `
        SELECT *
        FROM newspaper_groups
        WHERE id=$1
        `,
        [req.params.id]
      );

      if (!oldR.rows[0]) {
        return res.status(404).json({
          error:
            'Nie znaleziono grupy.'
        });
      }

      const old = oldR.rows[0];

      const oldIds =
        Array.isArray(old.member_ids)
          ? old.member_ids.map(Number)
          : [];

      const oldNames =
        Array.isArray(old.member_names)
          ? old.member_names.map(String)
          : [];

      if (req.role === 'member') {
        if (
          !oldIds.includes(
            Number(req.member.id)
          )
        ) {
          return res.status(403).json({
            error:
              'Brak dostępu do tej grupy.'
          });
        }

        const delivered =
          Math.min(
            Number(old.copies),
            Math.max(
              0,
              Number(
                req.body.delivered ??
                  old.delivered
              )
            )
          );

        const started =
          req.body.started === undefined
            ? !!old.started
            : !!req.body.started;

        const done =
          req.body.done === undefined
            ? !!old.done
            : !!req.body.done;

        const r =
          await pool.query(
            `
            UPDATE newspaper_groups
            SET
              delivered=$1,
              started=$2,
              done=$3
            WHERE id=$4
            RETURNING *
            `,
            [
              delivered,
              started,
              done,
              req.params.id
            ]
          );

        return res.json(
          (
            await getGroups()
          ).find(
            x =>
              x.id ===
              Number(req.params.id)
          ) ||
            groupJson(
              r.rows[0]
            )
        );
      }

      if (!isStaff(req)) {
        return res.status(403).json({
          error:
            'Brak uprawnień.'
        });
      }

      const ids =
        Array.isArray(req.body.memberIds)
          ? req.body.memberIds
              .map(Number)
              .filter(Number.isFinite)
          : oldIds;

      const m = ids.length
        ? await pool.query(
            `
            SELECT
              id,
              first_name,
              last_name,
              name
            FROM members
            WHERE id=ANY($1::int[])
            `,
            [ids]
          )
        : { rows: [] };

      const names =
        Array.isArray(
          req.body.memberIds
        )
          ? m.rows
              .map(x =>
                `${x.first_name || ''} ${x.last_name || ''}`.trim()
              )
              .filter(Boolean)
          : oldNames;

      const copies =
        Math.max(
          0,
          Number(
            req.body.copies ??
              old.copies
          )
        );

      const delivered =
        Math.min(
          copies,
          Math.max(
            0,
            Number(
              req.body.delivered ??
                old.delivered
            )
          )
        );

      const r =
        await pool.query(
          `
          UPDATE newspaper_groups
          SET
            name=$1,
            region=$2,
            color=$3,
            streets=$4::jsonb,
            copies=$5,
            delivered=$6,
            started=$7,
            done=$8,
            member_ids=$9::jsonb,
            member_names=$10::jsonb
          WHERE id=$11
          RETURNING *
          `,
          [
            req.body.name ??
              old.name,

            req.body.region ??
              old.region,

            req.body.color ??
              old.color,

            JSON.stringify(
              Array.isArray(
                req.body.streets
              )
                ? req.body.streets
                : (
                    Array.isArray(
                      old.streets
                    )
                      ? old.streets
                      : []
                  )
            ),

            copies,
            delivered,

            !!(
              req.body.started ??
              old.started
            ),

            !!(
              req.body.done ??
              old.done
            ),

            JSON.stringify(ids),
            JSON.stringify(names),

            req.params.id
          ]
        );

      res.json(
        groupJson(
          r.rows[0],
          m.rows
        )
      );

    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Nie udało się zmienić grupy gazet.'
      });
    }
  }
);


/* =========================================================
   POSTĘP GAZET
========================================================= */

app.post(
  '/api/newspaper-groups/:id/start',
  auth,
  async (req, res) => {
    req.body.started = true;

    return updateGroupProgress(
      req,
      res,
      req.params.id
    );
  }
);

app.post(
  '/api/newspaper-groups/:id/progress',
  auth,
  async (req, res) =>
    updateGroupProgress(
      req,
      res,
      req.params.id
    )
);

app.post(
  '/api/newspaper-groups/:id/complete',
  auth,
  async (req, res) => {
    req.body.done = true;
    req.body.started = true;

    return updateGroupProgress(
      req,
      res,
      req.params.id
    );
  }
);

async function updateGroupProgress(
  req,
  res,
  id
) {
  try {
    const r = await pool.query(
      `
      SELECT *
      FROM newspaper_groups
      WHERE id=$1
      `,
      [id]
    );

    if (!r.rows[0]) {
      return res.status(404).json({
        error:
          'Nie znaleziono grupy.'
      });
    }

    const g = r.rows[0];

    const ids =
      Array.isArray(g.member_ids)
        ? g.member_ids.map(Number)
        : [];

    if (
      req.role === 'member' &&
      !ids.includes(
        Number(req.member.id)
      )
    ) {
      return res.status(403).json({
        error:
          'Brak dostępu do tej grupy.'
      });
    }

    if (
      !isStaff(req) &&
      req.role !== 'member'
    ) {
      return res.status(403).json({
        error:
          'Brak uprawnień.'
      });
    }

    const delivered =
      Math.min(
        Number(g.copies),
        Math.max(
          0,
          Number(
            req.body.delivered ??
              g.delivered
          )
        )
      );

    const started =
      req.body.started === undefined
        ? !!g.started
        : !!req.body.started;

    const done =
      req.body.done === undefined
        ? !!g.done
        : !!req.body.done;

    const u =
      await pool.query(
        `
        UPDATE newspaper_groups
        SET
          delivered=$1,
          started=$2,
          done=$3
        WHERE id=$4
        RETURNING *
        `,
        [
          delivered,
          started,
          done,
          id
        ]
      );

    res.json(
      (
        await getGroups()
      ).find(
        x =>
          x.id === Number(id)
      ) ||
        groupJson(
          u.rows[0]
        )
    );

  } catch (e) {
    console.error(e);

    res.status(500).json({
      error:
        'Nie udało się zapisać postępu.'
    });
  }
}


/* =========================================================
   USUWANIE GRUPY
========================================================= */

app.delete(
  '/api/newspaper-groups/:id',
  auth,
  staff,
  async (req, res) => {
    try {
      await pool.query(
        `
        DELETE FROM newspaper_groups
        WHERE id=$1
        `,
        [req.params.id]
      );

      res.json({
        ok: true
      });

    } catch (e) {
      res.status(500).json({
        error:
          'Nie udało się usunąć grupy gazet.'
      });
    }
  }
);


/* =========================================================
   RESET GRUP
========================================================= */

app.post(
  '/api/newspaper-groups/reset',
  auth,
  staff,
  async (req, res) => {
    try {
      await pool.query(`
        DELETE FROM newspaper_groups
      `);

      await seedNewspaperGroups();

      res.json(
        await getGroups()
      );

    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Nie udało się przywrócić planu gazet.'
      });
    }
  }
);


/* =========================================================
   HISTORIA GAZET
========================================================= */

app.get(
  '/api/newspaper-history',
  auth,
  staff,
  async (req, res) => {
    try {
      const r = await pool.query(`
        SELECT
          id,
          month_key,
          month_label,
          saved_at,
          groups
        FROM newspaper_history
        ORDER BY
          month_key DESC,
          id DESC
      `);

      res.json(r.rows);

    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Nie udało się pobrać historii gazet.'
      });
    }
  }
);


/* =========================================================
   NOWY MIESIĄC GAZET
========================================================= */

app.post(
  '/api/newspaper-groups/new-month',
  auth,
  staff,
  async (req, res) => {
    const client =
      await pool.connect();

    try {
      await client.query(
        'BEGIN'
      );

      const groupsResult =
        await client.query(`
          SELECT *
          FROM newspaper_groups
          ORDER BY id
          FOR UPDATE
        `);

      if (
        !groupsResult.rows.length
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res.status(400).json({
          error:
            'Brak grup gazet do zapisania.'
        });
      }

      const now = new Date();

      const year =
        now.getFullYear();

      const month =
        String(
          now.getMonth() + 1
        ).padStart(2, '0');

      const monthKey =
        `${year}-${month}`;

      const monthLabel =
        new Intl.DateTimeFormat(
          'pl-PL',
          {
            month: 'long',
            year: 'numeric'
          }
        ).format(now);

      const snapshot =
        groupsResult.rows.map(
          g => ({
            id: g.id,
            name: g.name,
            region: g.region,
            color: g.color,

            streets:
              Array.isArray(
                g.streets
              )
                ? g.streets
                : [],

            copies:
              Number(
                g.copies || 0
              ),

            delivered:
              Number(
                g.delivered || 0
              ),

            started:
              !!g.started,

            done:
              !!g.done,

            memberIds:
              Array.isArray(
                g.member_ids
              )
                ? g.member_ids.map(
                    Number
                  )
                : [],

            memberNames:
              Array.isArray(
                g.member_names
              )
                ? g.member_names
                : []
          })
        );

      const exists =
        await client.query(
          `
          SELECT id
          FROM newspaper_history
          WHERE month_key=$1
          LIMIT 1
          `,
          [monthKey]
        );

      if (!exists.rows.length) {
        await client.query(
          `
          INSERT INTO newspaper_history
          (
            month_key,
            month_label,
            groups
          )
          VALUES
          (
            $1,
            $2,
            $3::jsonb
          )
          `,
          [
            monthKey,
            monthLabel,
            JSON.stringify(snapshot)
          ]
        );
      }

      await client.query(`
        UPDATE newspaper_groups
        SET
          delivered=0,
          started=FALSE,
          done=FALSE
      `);

      await client.query(
        'COMMIT'
      );

      res.json({
        ok: true,
        archivedMonth:
          monthLabel,
        groups:
          await getGroups()
      });

    } catch (e) {
      await client
        .query('ROLLBACK')
        .catch(() => {});

      console.error(e);

      res.status(500).json({
        error:
          'Nie udało się rozpocząć nowego miesiąca.'
      });

    } finally {
      client.release();
    }
  }
);


/* =========================================================
   PUSH
========================================================= */

app.post(
  '/api/push/subscribe',
  auth,
  async (req, res) => {
    try {
      const s = req.body;

      if (!s?.endpoint) {
        return res.status(400).json({
          error:
            'Brak endpointu.'
        });
      }

      await pool.query(
        `
        INSERT INTO push_subscriptions
        (
          endpoint,
          subscription
        )
        VALUES
        (
          $1,
          $2::jsonb
        )
        ON CONFLICT(endpoint)
        DO UPDATE SET
          subscription=EXCLUDED.subscription
        `,
        [
          s.endpoint,
          JSON.stringify(s)
        ]
      );

      res.json({
        ok: true
      });

    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Nie udało się zapisać powiadomień.'
      });
    }
  }
);

app.get(
  '/api/push/public-key',
  auth,
  async (req, res) => {
    if (!VAPID_PUBLIC_KEY) {
      return res.status(503).json({
        error:
          'Powiadomienia push nie są skonfigurowane.'
      });
    }

    res.json({
      publicKey:
        VAPID_PUBLIC_KEY
    });
  }
);

app.post(
  '/api/push/unsubscribe',
  auth,
  async (req, res) => {
    try {
      if (req.body?.endpoint) {
        await pool.query(
          `
          DELETE FROM push_subscriptions
          WHERE endpoint=$1
          `,
          [req.body.endpoint]
        );
      }

      res.json({
        ok: true
      });

    } catch (e) {
      res.status(500).json({
        error:
          'Nie udało się usunąć subskrypcji.'
      });
    }
  }
);

app.post(
  '/api/push/test',
  auth,
  staff,
  async (req, res) => {
    try {
      await sendPushToAll({
        title: 'MDP Wiesiółka',
        body:
          req.body?.body ||
          'Testowe powiadomienie'
      });

      res.json({
        ok: true
      });

    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Nie udało się wysłać powiadomienia.'
      });
    }
  }
);


/* =========================================================
   HEALTH CHECK
========================================================= */

app.get(
  '/api/health',
  async (req, res) => {
    try {
      await pool.query(
        'SELECT 1'
      );

      res.json({
        ok: true
      });

    } catch (e) {
      console.error(e);

      res.status(500).json({
        ok: false
      });
    }
  }
);


/* =========================================================
   API 404
========================================================= */

app.use(
  '/api',
  (req, res) =>
    res.status(404).json({
      error:
        'Nie znaleziono endpointu.'
    })
);


/* =========================================================
   PWA / SPA FALLBACK
   Ważne: NIE używamy app.get('*')
   ========================================================= */

app.use(
  (req, res) =>
    res.sendFile(
      path.join(
        __dirname,
        'public',
        'index.html'
      )
    )
);


/* =========================================================
   START SERWERA
========================================================= */

initDb()
  .then(() => {
    app.listen(
      PORT,
      () => {
        console.log(
          `MDP Wiesiółka działa na porcie ${PORT}`
        );
      }
    );
  })
  .catch(err => {
    console.error(
      'Błąd inicjalizacji bazy:',
      err
    );

    process.exit(1);
  });
