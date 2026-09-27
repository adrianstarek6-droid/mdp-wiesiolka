
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');
const webpush = require('web-push');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '3mb' }));
app.use(express.urlencoded({ extended: true, limit: '3mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

const GUARDIAN_CODE = process.env.GUARDIAN_CODE || '9982018';
const ADMIN_CODE = process.env.ADMIN_CODE || '0000';

const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY || '';
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY || '';
const VAPID_EMAIL = process.env.VAPID_EMAIL || 'mailto:admin@example.com';

if (VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY) {
  webpush.setVapidDetails(
    VAPID_EMAIL,
    VAPID_PUBLIC_KEY,
    VAPID_PRIVATE_KEY
  );
}

function hashCode(code) {
  return crypto
    .createHash('sha256')
    .update(String(code || ''))
    .digest('hex');
}

function normRole(role) {
  const r = String(role || '').toLowerCase().trim();

  if (['opiekun', 'guardian'].includes(r)) return 'guardian';
  if (['admin', 'administrator'].includes(r)) return 'admin';
  if (['member', 'czlonek', 'członek'].includes(r)) return 'member';

  return r;
}

function auth(req, res, next) {
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

  if (role === 'admin' && code === ADMIN_CODE) {
    req.authenticated = true;
    req.member = null;
    return next();
  }

  if (role === 'guardian' && code === GUARDIAN_CODE) {
    req.authenticated = true;
    req.member = null;
    return next();
  }

  if (role === 'member' && memberId && code) {
    return pool.query(
      `SELECT id, first_name, last_name, role, photo, code_hash
       FROM members
       WHERE id=$1`,
      [memberId]
    )
      .then(r => {
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
        next();
      })
      .catch(err => {
        console.error(err);
        res.status(500).json({
          error: 'Błąd autoryzacji.'
        });
      });
  }

  return res.status(401).json({
    error: 'Brak autoryzacji.'
  });
}

function staff(req, res, next) {
  if (
    req.role === 'admin' ||
    req.role === 'guardian'
  ) {
    return next();
  }

  return res.status(403).json({
    error: 'Brak uprawnień.'
  });
}

async function sendPushToAll(payload) {
  if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) {
    return;
  }

  const result = await pool.query(
    'SELECT id, subscription FROM push_subscriptions'
  );

  for (const row of result.rows) {
    try {
      await webpush.sendNotification(
        row.subscription,
        JSON.stringify(payload)
      );
    } catch (e) {
      console.error(
        'Push error:',
        e.message
      );

      if (
        e.statusCode === 404 ||
        e.statusCode === 410
      ) {
        await pool.query(
          'DELETE FROM push_subscriptions WHERE id=$1',
          [row.id]
        );
      }
    }
  }
}

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
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS news (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      body TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS members (
      id SERIAL PRIMARY KEY,
      first_name TEXT,
      last_name TEXT,
      name TEXT,
      role TEXT DEFAULT 'member',
      code_hash TEXT NOT NULL,
      photo TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS attendance (
      id SERIAL PRIMARY KEY,
      event_id INTEGER NOT NULL,
      member_id INTEGER NOT NULL,
      status TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(event_id, member_id)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS push_subscriptions (
      id SERIAL PRIMARY KEY,
      subscription JSONB NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
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
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS newspaper_history (
      id SERIAL PRIMARY KEY,
      month_key TEXT NOT NULL,
      month_label TEXT NOT NULL,
      saved_at TIMESTAMPTZ DEFAULT NOW(),
      groups JSONB NOT NULL DEFAULT '[]'::jsonb
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS urgent_messages (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_by_role TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS member_reports (
      id SERIAL PRIMARY KEY,
      member_id INTEGER NOT NULL,
      member_name TEXT NOT NULL,
      report_type TEXT NOT NULL,
      body TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'new',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  const count = await pool.query(
    'SELECT COUNT(*)::int AS count FROM newspaper_groups'
  );

  if (count.rows[0].count === 0) {
    const defaults = [
      {
        name: 'Wiesiółka',
        region: 'Henryka Pobożnego i to osiedle',
        color: '#2878ff',
        streets: ['Henryka Pobożnego'],
        copies: 75,
        memberNames: [
          'Aleksandra Skrzypek',
          'Wiktoria Wilk'
        ]
      },
      {
        name: 'Wysoka',
        region: '3 bloki — Sportowa, Parkowa, Robotnicza',
        color: '#36b86b',
        streets: [
          'Sportowa',
          'Parkowa',
          'Robotnicza'
        ],
        copies: 85,
        memberNames: []
      },
      {
        name: 'Wysoka — Kościuszki',
        region: 'Kościuszki → do Dzwonka',
        color: '#ff9d2e',
        streets: [
          'Kościuszki — do Dzwonka'
        ],
        copies: 90,
        memberNames: [
          'Karol',
          'Mateusz Wilczyński',
          'Roksana Koszowska'
        ]
      },
      {
        name: 'Kopanina',
        region: 'Kopanina',
        color: '#e23b45',
        streets: [],
        copies: 45,
        memberNames: [
          'Jessica Labęda',
          'Maja Banaszak'
        ]
      },
      {
        name: 'Gięto',
        region: 'Gięto',
        color: '#a66cff',
        streets: [],
        copies: 75,
        memberNames: [
          'Iga Chmurzyńska',
          'Oliwia Popczyk'
        ]
      }
    ];

    for (const g of defaults) {
      await pool.query(
        `INSERT INTO newspaper_groups
        (name,region,color,streets,copies,member_ids,member_names)
        VALUES
        ($1,$2,$3,$4::jsonb,$5,'[]'::jsonb,$6::jsonb)`,
        [
          g.name,
          g.region,
          g.color,
          JSON.stringify(g.streets),
          g.copies,
          JSON.stringify(g.memberNames)
        ]
      );
    }
  }
}

function newspaperRow(row) {
  return {
    id: row.id,
    name: row.name,
    region: row.region,
    color: row.color,
    streets: row.streets || [],
    copies: Number(row.copies || 0),
    delivered: Number(row.delivered || 0),
    started: !!row.started,
    done: !!row.done,
    memberIds: row.member_ids || [],
    memberNames: row.member_names || []
  };
}

/* =========================
   LOGIN
========================= */

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
        `SELECT id, first_name, last_name, role, photo
         FROM members
         WHERE code_hash=$1
         ORDER BY id
         LIMIT 1`,
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

/* =========================
   DATA
========================= */

app.get('/api/data', auth, async (req, res) => {
  try {
    const [
      events,
      news,
      members,
      urgent
    ] = await Promise.all([
      pool.query(
        `SELECT *
         FROM events
         ORDER BY event_date ASC NULLS LAST,
                  event_time ASC NULLS LAST,
                  id DESC`
      ),

      pool.query(
        `SELECT *
         FROM news
         ORDER BY created_at DESC, id DESC`
      ),

      pool.query(
        `SELECT id, first_name, last_name,
                role, photo, name, created_at
         FROM members
         ORDER BY first_name, last_name, id`
      ),

      pool.query(
        `SELECT id,title,body,active,created_at
         FROM urgent_messages
         WHERE active=TRUE
         ORDER BY created_at DESC,id DESC`
      )
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

app.get('/api/stats', auth, async (req, res) => {
  try {
    const [
      m,
      e,
      n
    ] = await Promise.all([
      pool.query(
        'SELECT COUNT(*)::int c FROM members'
      ),
      pool.query(
        'SELECT COUNT(*)::int c FROM events'
      ),
      pool.query(
        'SELECT COUNT(*)::int c FROM news'
      )
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

/* =========================
   EVENTS
========================= */

app.post('/api/events', auth, staff, async (req, res) => {
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
      `INSERT INTO events
       (title,event_date,event_time,place,description)
       VALUES($1,$2,$3,$4,$5)
       RETURNING *`,
      [
        title,
        b.event_date || b.date || null,
        b.event_time || b.time || null,
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
});

app.delete(
  '/api/events/:id',
  auth,
  staff,
  async (req, res) => {
    try {
      await pool.query(
        'DELETE FROM events WHERE id=$1',
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

/* =========================
   NEWS
========================= */

app.post('/api/news', auth, staff, async (req, res) => {
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
      `INSERT INTO news(title,body)
       VALUES($1,$2)
       RETURNING *`,
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
});

app.delete(
  '/api/news/:id',
  auth,
  staff,
  async (req, res) => {
    try {
      await pool.query(
        'DELETE FROM news WHERE id=$1',
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

/* =========================
   MEMBERS
========================= */

app.post('/api/members', auth, staff, async (req, res) => {
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
      req.body.code ||
      ''
    ).trim();

    if (!first || !last || !code) {
      return res.status(400).json({
        error: 'Podaj imię, nazwisko i kod.'
      });
    }

    const r = await pool.query(
      `INSERT INTO members
       (first_name,last_name,name,role,code_hash)
       VALUES($1,$2,$3,$4,$5)
       RETURNING id,first_name,last_name,role,photo`,
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
      error: 'Nie udało się dodać członka.'
    });
  }
});

app.put(
  '/api/members/:id',
  auth,
  staff,
  async (req, res) => {
    try {
      const b = req.body;

      const r = await pool.query(
        `UPDATE members SET
          first_name=COALESCE($1,first_name),
          last_name=COALESCE($2,last_name),
          name=COALESCE($3,name),
          role=COALESCE($4,role),
          code_hash=COALESCE($5,code_hash),
          photo=COALESCE($6,photo)
         WHERE id=$7
         RETURNING id,first_name,last_name,role,photo`,
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

      res.json(
        r.rows[0] || {}
      );

    } catch (e) {
      res.status(500).json({
        error: 'Nie udało się zmienić członka.'
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
        'DELETE FROM members WHERE id=$1',
        [req.params.id]
      );

      res.json({
        ok: true
      });

    } catch (e) {
      res.status(500).json({
        error: 'Nie udało się usunąć członka.'
      });
    }
  }
);

/* =========================
   PROFILE
========================= */

app.get(
  '/api/profile',
  auth,
  async (req, res) => {
    if (req.role !== 'member') {
      return res.json({
        member: null
      });
    }

    res.json({
      member: req.member
    });
  }
);

app.put(
  '/api/profile',
  auth,
  async (req, res) => {
    try {
      if (req.role !== 'member') {
        return res.status(403).json({
          error: 'Brak uprawnień.'
        });
      }

      const photo = String(
        req.body.photo || ''
      );

      const r = await pool.query(
        `UPDATE members
         SET photo=$1
         WHERE id=$2
         RETURNING id,first_name,last_name,
                   role,photo`,
        [
          photo,
          req.member.id
        ]
      );

      res.json({
        member: r.rows[0]
      });

    } catch (e) {
      console.error(e);

      res.status(500).json({
        error: 'Nie udało się zapisać profilu.'
      });
    }
  }
);

/* =========================
   ATTENDANCE
========================= */

app.post(
  '/api/attendance',
  auth,
  async (req, res) => {
    try {
      if (req.role !== 'member') {
        return res.status(403).json({
          error: 'Tylko członek może ustawić obecność.'
        });
      }

      const eventId = Number(
        req.body.event_id ||
        req.body.eventId
      );

      const status = String(
        req.body.status || ''
      ).trim();

      if (
        !eventId ||
        !['yes', 'maybe', 'no'].includes(status)
      ) {
        return res.status(400).json({
          error: 'Nieprawidłowe dane obecności.'
        });
      }

      const r = await pool.query(
        `INSERT INTO attendance
         (event_id,member_id,status)
         VALUES($1,$2,$3)
         ON CONFLICT(event_id,member_id)
         DO UPDATE SET
           status=EXCLUDED.status,
           updated_at=NOW()
         RETURNING *`,
        [
          eventId,
          req.member.id,
          status
        ]
      );

      res.json(r.rows[0]);

    } catch (e) {
      console.error(e);

      res.status(500).json({
        error: 'Nie udało się zapisać obecności.'
      });
    }
  }
);

app.post(
  '/api/attendance/:eventId',
  auth,
  async (req, res) => {
    try {
      if (req.role !== 'member') {
        return res.status(403).json({
          error: 'Tylko członek może ustawić obecność.'
        });
      }

      const eventId = Number(
        req.params.eventId
      );

      const status = String(
        req.body.status || ''
      ).trim();

      if (
        !eventId ||
        !['yes', 'maybe', 'no'].includes(status)
      ) {
        return res.status(400).json({
          error: 'Nieprawidłowe dane obecności.'
        });
      }

      const r = await pool.query(
        `INSERT INTO attendance
         (event_id,member_id,status)
         VALUES($1,$2,$3)
         ON CONFLICT(event_id,member_id)
         DO UPDATE SET
           status=EXCLUDED.status,
           updated_at=NOW()
         RETURNING *`,
        [
          eventId,
          req.member.id,
          status
        ]
      );

      res.json(r.rows[0]);

    } catch (e) {
      console.error(e);

      res.status(500).json({
        error: 'Nie udało się zapisać obecności.'
      });
    }
  }
);

app.get(
  '/api/attendance/:eventId',
  auth,
  staff,
  async (req, res) => {
    try {
      const r = await pool.query(
        `SELECT
          a.id,
          a.event_id,
          a.member_id,
          a.status,
          a.created_at,
          a.updated_at,
          m.first_name,
          m.last_name
         FROM attendance a
         JOIN members m
           ON m.id=a.member_id
         WHERE a.event_id=$1
         ORDER BY m.first_name,m.last_name`,
        [req.params.eventId]
      );

      res.json(r.rows);

    } catch (e) {
      res.status(500).json({
        error: 'Nie udało się pobrać obecności.'
      });
    }
  }
);

app.get(
  '/api/member-stats/:memberId',
  auth,
  async (req, res) => {
    try {
      const memberId = Number(
        req.params.memberId
      );

      if (
        req.role === 'member' &&
        req.member.id !== memberId
      ) {
        return res.status(403).json({
          error: 'Brak uprawnień.'
        });
      }

      const r = await pool.query(
        `SELECT
          COUNT(*)::int AS total,
          COUNT(*) FILTER
            (WHERE status='yes')::int AS yes,
          COUNT(*) FILTER
            (WHERE status='no')::int AS no,
          COUNT(*) FILTER
            (WHERE status='maybe')::int AS maybe
         FROM attendance
         WHERE member_id=$1`,
        [memberId]
      );

      const row = r.rows[0];

      const total = Number(row.total || 0);
      const yes = Number(row.yes || 0);

      res.json({
        total,
        yes,
        no: Number(row.no || 0),
        maybe: Number(row.maybe || 0),
        percentage: total
          ? Math.round((yes / total) * 100)
          : 0
      });

    } catch (e) {
      res.status(500).json({
        error: 'Nie udało się pobrać statystyk.'
      });
    }
  }
);

/* =========================
   PILNE KOMUNIKATY
========================= */

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
        req.body.body || ''
      ).trim();

      if (!title || !body) {
        return res.status(400).json({
          error: 'Podaj tytuł i treść komunikatu.'
        });
      }

      // Tylko jeden aktywny pilny komunikat.
      await pool.query(
        `UPDATE urgent_messages
         SET active=FALSE
         WHERE active=TRUE`
      );

      const r = await pool.query(
        `INSERT INTO urgent_messages
         (title,body,active,created_by_role)
         VALUES($1,$2,TRUE,$3)
         RETURNING *`,
        [
          title,
          body,
          req.role
        ]
      );

      try {
        await sendPushToAll({
          title: `🚨 ${title}`,
          body
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
      const query =
        req.role === 'admin' ||
        req.role === 'guardian'
          ? `SELECT *
             FROM urgent_messages
             ORDER BY created_at DESC,id DESC`
          : `SELECT *
             FROM urgent_messages
             WHERE active=TRUE
             ORDER BY created_at DESC,id DESC`;

      const r = await pool.query(query);

      res.json(r.rows);

    } catch (e) {
      res.status(500).json({
        error:
          'Nie udało się pobrać pilnych komunikatów.'
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
        `UPDATE urgent_messages
         SET active=FALSE
         WHERE id=$1`,
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

/* =========================
   ZGŁOSZENIA OD CZŁONKÓW
========================= */

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
        req.body.type ||
        req.body.report_type ||
        'Inne'
      ).trim();

      const body = String(
        req.body.body ||
        req.body.message ||
        ''
      ).trim();

      if (!body) {
        return res.status(400).json({
          error:
            'Napisz treść zgłoszenia.'
        });
      }

      const memberName =
        `${req.member.first_name || ''} ${req.member.last_name || ''}`
          .trim();

      const r = await pool.query(
        `INSERT INTO member_reports
         (member_id,member_name,report_type,body)
         VALUES($1,$2,$3,$4)
         RETURNING *`,
        [
          req.member.id,
          memberName || 'Członek',
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
      const r = await pool.query(
        `SELECT *
         FROM member_reports
         ORDER BY
           CASE status
             WHEN 'new' THEN 0
             WHEN 'in_progress' THEN 1
             ELSE 2
           END,
           created_at DESC,
           id DESC`
      );

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
        `UPDATE member_reports
         SET status=$1,
             updated_at=NOW()
         WHERE id=$2
         RETURNING *`,
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
      console.error(e);

      res.status(500).json({
        error:
          'Nie udało się zmienić statusu zgłoszenia.'
      });
    }
  }
);

/* =========================
   GAZETY
========================= */

app.get(
  '/api/newspaper-groups',
  auth,
  async (req, res) => {
    try {
      const r = await pool.query(
        `SELECT *
         FROM newspaper_groups
         ORDER BY id ASC`
      );

      res.json(
        r.rows.map(newspaperRow)
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
      const name = String(
        req.body.name || ''
      ).trim();

      const region = String(
        req.body.region || ''
      ).trim();

      const color = String(
        req.body.color ||
        '#2878ff'
      );

      const streets =
        Array.isArray(req.body.streets)
          ? req.body.streets
          : [];

      const copies = Number(
        req.body.copies || 0
      );

      const memberIds =
        Array.isArray(req.body.memberIds)
          ? req.body.memberIds.map(Number)
          : [];

      if (!name || !region) {
        return res.status(400).json({
          error:
            'Podaj nazwę grupy i region.'
        });
      }

      let memberNames = [];

      if (memberIds.length) {
        const r = await pool.query(
          `SELECT id,first_name,last_name
           FROM members
           WHERE id=ANY($1::int[])`,
          [memberIds]
        );

        memberNames = r.rows.map(
          m =>
            `${m.first_name || ''} ${m.last_name || ''}`
              .trim()
        );
      }

      const r = await pool.query(
        `INSERT INTO newspaper_groups
         (name,region,color,streets,copies,
          delivered,started,done,
          member_ids,member_names)
         VALUES
         ($1,$2,$3,$4::jsonb,$5,
          0,FALSE,FALSE,
          $6::jsonb,$7::jsonb)
         RETURNING *`,
        [
          name,
          region,
          color,
          JSON.stringify(streets),
          copies,
          JSON.stringify(memberIds),
          JSON.stringify(memberNames)
        ]
      );

      res.json(
        newspaperRow(r.rows[0])
      );

    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Nie udało się dodać grupy gazet.'
      });
    }
  }
);

app.put(
  '/api/newspaper-groups/:id',
  auth,
  async (req, res) => {
    try {
      const id = Number(
        req.params.id
      );

      const existing = await pool.query(
        `SELECT *
         FROM newspaper_groups
         WHERE id=$1`,
        [id]
      );

      if (!existing.rows[0]) {
        return res.status(404).json({
          error:
            'Nie znaleziono grupy.'
        });
      }

      const group = existing.rows[0];

      if (req.role === 'member') {
        const allowed =
          (group.member_ids || [])
            .map(Number)
            .includes(
              Number(req.member.id)
            );

        if (!allowed) {
          return res.status(403).json({
            error:
              'Nie jesteś przypisany do tej grupy.'
          });
        }

        const delivered =
          Number(
            req.body.delivered ??
            group.delivered
          );

        const done =
          Boolean(
            req.body.done ??
            group.done
          );

        const r = await pool.query(
          `UPDATE newspaper_groups
           SET delivered=$1,
               done=$2
           WHERE id=$3
           RETURNING *`,
          [
            delivered,
            done,
            id
          ]
        );

        return res.json(
          newspaperRow(r.rows[0])
        );
      }

      if (
        req.role !== 'admin' &&
        req.role !== 'guardian'
      ) {
        return res.status(403).json({
          error:
            'Brak uprawnień.'
        });
      }

      const name =
        req.body.name ??
        group.name;

      const region =
        req.body.region ??
        group.region;

      const color =
        req.body.color ??
        group.color;

      const streets =
        Array.isArray(req.body.streets)
          ? req.body.streets
          : group.streets || [];

      const copies =
        Number(
          req.body.copies ??
          group.copies
        );

      const memberIds =
        Array.isArray(req.body.memberIds)
          ? req.body.memberIds.map(Number)
          : group.member_ids || [];

      let memberNames =
        group.member_names || [];

      if (Array.isArray(req.body.memberIds)) {
        const r = await pool.query(
          `SELECT id,first_name,last_name
           FROM members
           WHERE id=ANY($1::int[])`,
          [memberIds]
        );

        memberNames = r.rows.map(
          m =>
            `${m.first_name || ''} ${m.last_name || ''}`
              .trim()
        );
      }

      const r = await pool.query(
        `UPDATE newspaper_groups
         SET name=$1,
             region=$2,
             color=$3,
             streets=$4::jsonb,
             copies=$5,
             member_ids=$6::jsonb,
             member_names=$7::jsonb
         WHERE id=$8
         RETURNING *`,
        [
          name,
          region,
          color,
          JSON.stringify(streets),
          copies,
          JSON.stringify(memberIds),
          JSON.stringify(memberNames),
          id
        ]
      );

      res.json(
        newspaperRow(r.rows[0])
      );

    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Nie udało się zmienić grupy.'
      });
    }
  }
);

app.post(
  '/api/newspaper-groups/:id/start',
  auth,
  async (req, res) => {
    try {
      const id = Number(
        req.params.id
      );

      const r0 = await pool.query(
        `SELECT *
         FROM newspaper_groups
         WHERE id=$1`,
        [id]
      );

      const group = r0.rows[0];

      if (!group) {
        return res.status(404).json({
          error:
            'Nie znaleziono grupy.'
        });
      }

      if (req.role === 'member') {
        const allowed =
          (group.member_ids || [])
            .map(Number)
            .includes(
              Number(req.member.id)
            );

        if (!allowed) {
          return res.status(403).json({
            error:
              'Nie jesteś przypisany do tej grupy.'
          });
        }
      }

      const r = await pool.query(
        `UPDATE newspaper_groups
         SET started=TRUE
         WHERE id=$1
         RETURNING *`,
        [id]
      );

      res.json(
        newspaperRow(r.rows[0])
      );

    } catch (e) {
      res.status(500).json({
        error:
          'Nie udało się rozpocząć kolportażu.'
      });
    }
  }
);

app.post(
  '/api/newspaper-groups/:id/progress',
  auth,
  async (req, res) => {
    try {
      const id = Number(
        req.params.id
      );

      const amount = Math.max(
        0,
        Number(req.body.amount || 0)
      );

      const r0 = await pool.query(
        `SELECT *
         FROM newspaper_groups
         WHERE id=$1`,
        [id]
      );

      const group = r0.rows[0];

      if (!group) {
        return res.status(404).json({
          error:
            'Nie znaleziono grupy.'
        });
      }

      if (req.role === 'member') {
        const allowed =
          (group.member_ids || [])
            .map(Number)
            .includes(
              Number(req.member.id)
            );

        if (!allowed) {
          return res.status(403).json({
            error:
              'Nie jesteś przypisany do tej grupy.'
          });
        }
      }

      const delivered = Math.min(
        Number(group.copies || 0),
        Number(group.delivered || 0) +
          amount
      );

      const done =
        delivered >=
        Number(group.copies || 0);

      const r = await pool.query(
        `UPDATE newspaper_groups
         SET delivered=$1,
             done=$2
         WHERE id=$3
         RETURNING *`,
        [
          delivered,
          done,
          id
        ]
      );

      res.json(
        newspaperRow(r.rows[0])
      );

    } catch (e) {
      res.status(500).json({
        error:
          'Nie udało się zapisać postępu.'
      });
    }
  }
);

app.post(
  '/api/newspaper-groups/:id/complete',
  auth,
  async (req, res) => {
    try {
      const id = Number(
        req.params.id
      );

      const r0 = await pool.query(
        `SELECT *
         FROM newspaper_groups
         WHERE id=$1`,
        [id]
      );

      const group = r0.rows[0];

      if (!group) {
        return res.status(404).json({
          error:
            'Nie znaleziono grupy.'
        });
      }

      if (req.role === 'member') {
        const allowed =
          (group.member_ids || [])
            .map(Number)
            .includes(
              Number(req.member.id)
            );

        if (!allowed) {
          return res.status(403).json({
            error:
              'Nie jesteś przypisany do tej grupy.'
          });
        }
      }

      const r = await pool.query(
        `UPDATE newspaper_groups
         SET done=TRUE,
             started=TRUE,
             delivered=GREATEST(delivered,copies)
         WHERE id=$1
         RETURNING *`,
        [id]
      );

      res.json(
        newspaperRow(r.rows[0])
      );

    } catch (e) {
      res.status(500).json({
        error:
          'Nie udało się zakończyć kolportażu.'
      });
    }
  }
);

app.delete(
  '/api/newspaper-groups/:id',
  auth,
  staff,
  async (req, res) => {
    try {
      await pool.query(
        `DELETE FROM newspaper_groups
         WHERE id=$1`,
        [req.params.id]
      );

      res.json({
        ok: true
      });

    } catch (e) {
      res.status(500).json({
        error:
          'Nie udało się usunąć grupy.'
      });
    }
  }
);

app.post(
  '/api/newspaper-groups/reset',
  auth,
  staff,
  async (req, res) => {
    try {
      await pool.query(
        'DELETE FROM newspaper_groups'
      );

      const defaults = [
        {
          name: 'Wiesiółka',
          region: 'Henryka Pobożnego i to osiedle',
          color: '#2878ff',
          streets: ['Henryka Pobożnego'],
          copies: 75,
          memberNames: [
            'Aleksandra Skrzypek',
            'Wiktoria Wilk'
          ]
        },
        {
          name: 'Wysoka',
          region: '3 bloki — Sportowa, Parkowa, Robotnicza',
          color: '#36b86b',
          streets: [
            'Sportowa',
            'Parkowa',
            'Robotnicza'
          ],
          copies: 85,
          memberNames: []
        },
        {
          name: 'Wysoka — Kościuszki',
          region: 'Kościuszki → do Dzwonka',
          color: '#ff9d2e',
          streets: [
            'Kościuszki — do Dzwonka'
          ],
          copies: 90,
          memberNames: [
            'Karol',
            'Mateusz Wilczyński',
            'Roksana Koszowska'
          ]
        },
        {
          name: 'Kopanina',
          region: 'Kopanina',
          color: '#e23b45',
          streets: [],
          copies: 45,
          memberNames: [
            'Jessica Labęda',
            'Maja Banaszak'
          ]
        },
        {
          name: 'Gięto',
          region: 'Gięto',
          color: '#a66cff',
          streets: [],
          copies: 75,
          memberNames: [
            'Iga Chmurzyńska',
            'Oliwia Popczyk'
          ]
        }
      ];

      for (const g of defaults) {
        await pool.query(
          `INSERT INTO newspaper_groups
           (name,region,color,streets,copies,
            delivered,started,done,
            member_ids,member_names)
           VALUES
           ($1,$2,$3,$4::jsonb,$5,
            0,FALSE,FALSE,
            '[]'::jsonb,$6::jsonb)`,
          [
            g.name,
            g.region,
            g.color,
            JSON.stringify(g.streets),
            g.copies,
            JSON.stringify(g.memberNames)
          ]
        );
      }

      const r = await pool.query(
        `SELECT *
         FROM newspaper_groups
         ORDER BY id ASC`
      );

      res.json(
        r.rows.map(newspaperRow)
      );

    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Nie udało się wczytać planu gazet.'
      });
    }
  }
);

app.get(
  '/api/newspaper-history',
  auth,
  staff,
  async (req, res) => {
    try {
      const r = await pool.query(
        `SELECT *
         FROM newspaper_history
         ORDER BY saved_at DESC,id DESC`
      );

      res.json(r.rows);

    } catch (e) {
      res.status(500).json({
        error:
          'Nie udało się pobrać historii gazet.'
      });
    }
  }
);

app.post(
  '/api/newspaper-groups/new-month',
  auth,
  staff,
  async (req, res) => {
    try {
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
        now.toLocaleDateString(
          'pl-PL',
          {
            month: 'long',
            year: 'numeric'
          }
        );

      const existing =
        await pool.query(
          `SELECT id
           FROM newspaper_history
           WHERE month_key=$1
           LIMIT 1`,
          [monthKey]
        );

      const groups =
        await pool.query(
          `SELECT *
           FROM newspaper_groups
           ORDER BY id ASC`
        );

      if (
        existing.rows.length === 0
      ) {
        await pool.query(
          `INSERT INTO newspaper_history
           (month_key,month_label,groups)
           VALUES($1,$2,$3::jsonb)`,
          [
            monthKey,
            monthLabel,
            JSON.stringify(
              groups.rows.map(
                newspaperRow
              )
            )
          ]
        );
      }

      await pool.query(
        `UPDATE newspaper_groups
         SET delivered=0,
             started=FALSE,
             done=FALSE`
      );

      const r =
        await pool.query(
          `SELECT *
           FROM newspaper_groups
           ORDER BY id ASC`
        );

      res.json({
        groups:
          r.rows.map(
            newspaperRow
          ),
        monthKey,
        monthLabel
      });

    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Nie udało się rozpocząć nowego miesiąca.'
      });
    }
  }
);

/* =========================
   PUSH
========================= */

app.post(
  '/api/push/subscribe',
  auth,
  async (req, res) => {
    try {
      const subscription =
        req.body.subscription ||
        req.body;

      if (!subscription) {
        return res.status(400).json({
          error:
            'Brak subskrypcji.'
        });
      }

      const endpoint =
        subscription.endpoint;

      if (!endpoint) {
        return res.status(400).json({
          error:
            'Brak endpointu subskrypcji.'
        });
      }

      await pool.query(
        `DELETE FROM push_subscriptions
         WHERE subscription->>'endpoint'=$1`,
        [endpoint]
      );

      await pool.query(
        `INSERT INTO push_subscriptions
         (subscription)
         VALUES($1::jsonb)`,
        [
          JSON.stringify(
            subscription
          )
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

app.delete(
  '/api/push/subscribe',
  auth,
  async (req, res) => {
    try {
      const endpoint =
        req.body.endpoint ||
        req.body.subscription?.endpoint;

      if (endpoint) {
        await pool.query(
          `DELETE FROM push_subscriptions
           WHERE subscription->>'endpoint'=$1`,
          [endpoint]
        );
      }

      res.json({
        ok: true
      });

    } catch (e) {
      res.status(500).json({
        error:
          'Nie udało się wyłączyć powiadomień.'
      });
    }
  }
);

/* =========================
   HEALTH
========================= */

app.get(
  '/api/health',
  async (req, res) => {
    try {
      await pool.query(
        'SELECT 1'
      );

      res.json({
        ok: true,
        database: true
      });

    } catch (e) {
      res.status(500).json({
        ok: false,
        database: false
      });
    }
  }
);

/* =========================
   START
========================= */

initDb()
  .then(() => {
    app.listen(
      PORT,
      () => {
        console.log(
          `MDP Wiesiółka server działa na porcie ${PORT}`
        );
      }
    );
  })
  .catch(err => {
    console.error(
      'Błąd uruchamiania bazy:',
      err
    );

    process.exit(1);
  });

/* =========================
   SPA FALLBACK
========================= */

app.get(
  '*',
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        'public',
        'index.html'
      )
    );
  }
);
