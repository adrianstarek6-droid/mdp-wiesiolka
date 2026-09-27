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
const VAPID_EMAIL = process.env.VAPID_EMAIL || 'mailto:admin@example.com';

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
  crypto.createHash('sha256').update(String(code || '')).digest('hex');

function normRole(role) {
  const r = String(role || '').toLowerCase().trim();

  if (['opiekun', 'guardian'].includes(r)) return 'guardian';
  if (['admin', 'administrator'].includes(r)) return 'admin';
  if (['member', 'czlonek', 'członek'].includes(r)) return 'member';

  return r;
}

function isStaff(req) {
  return req.role === 'admin' || req.role === 'guardian';
}

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
      const result = await pool.query(
        `SELECT id, first_name, last_name, role, photo, code_hash
         FROM members
         WHERE id=$1`,
        [memberId]
      );

      const member = result.rows[0];

      if (!member || member.code_hash !== hashCode(code)) {
        return res.status(401).json({
          error: 'Nieprawidłowe dane logowania.'
        });
      }

      req.member = member;
      req.authenticated = true;

      return next();
    }

    return res.status(401).json({
      error: 'Brak autoryzacji.'
    });

  } catch (err) {
    console.error(err);

    return res.status(500).json({
      error: 'Błąd autoryzacji.'
    });
  }
}

function staff(req, res, next) {
  if (isStaff(req)) return next();

  return res.status(403).json({
    error: 'Brak uprawnień.'
  });
}


/* =========================================================
   BAZA DANYCH
========================================================= */

async function initDb() {

  await pool.query(`
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

  await pool.query(
    `ALTER TABLE members ADD COLUMN IF NOT EXISTS first_name TEXT`
  );

  await pool.query(
    `ALTER TABLE members ADD COLUMN IF NOT EXISTS last_name TEXT`
  );

  await pool.query(
    `ALTER TABLE members ADD COLUMN IF NOT EXISTS code_hash TEXT`
  );

  await pool.query(
    `ALTER TABLE members ADD COLUMN IF NOT EXISTS photo TEXT`
  );

  const count = await pool.query(
    `SELECT COUNT(*)::int AS count FROM newspaper_groups`
  );

  if (count.rows[0].count === 0) {
    await seedNewspaperGroups();
  }
}


/* =========================================================
   GAZETY — DOMYŚLNE GRUPY
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
      ['Sportowa', 'Parkowa', 'Robotnicza'],
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

  for (const group of groups) {

    await pool.query(
      `
      INSERT INTO newspaper_groups
      (name, region, color, streets, copies)
      VALUES ($1,$2,$3,$4::jsonb,$5)
      `,
      [
        group[0],
        group[1],
        group[2],
        JSON.stringify(group[3]),
        group[4]
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

    delivered: Number(row.delivered || 0),

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

  const [groupsResult, membersResult] =
    await Promise.all([

      pool.query(
        `SELECT *
         FROM newspaper_groups
         ORDER BY id`
      ),

      pool.query(
        `SELECT id, first_name, last_name, name
         FROM members
         ORDER BY first_name, last_name, id`
      )

    ]);

  const members = membersResult.rows;

  return groupsResult.rows.map(row => {

    let ids = Array.isArray(row.member_ids)
      ? row.member_ids.map(Number)
      : [];

    const names = Array.isArray(row.member_names)
      ? row.member_names.map(String)
      : [];

    if (!ids.length && names.length) {

      ids = members
        .filter(member => {

          const fullName =
            `${member.first_name || ''} ${member.last_name || ''}`.trim();

          return (
            names.includes(fullName) ||
            names.includes(member.name || '')
          );
        })
        .map(member => member.id);
    }

    const groupMembers =
      members.filter(member =>
        ids.includes(Number(member.id))
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
   PUSH
========================================================= */

async function sendPushToAll(payload) {

  if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) {
    return;
  }

  const result = await pool.query(
    `SELECT id, endpoint, subscription
     FROM push_subscriptions`
  );

  for (const sub of result.rows) {

    try {

      await webpush.sendNotification(
        sub.subscription,
        JSON.stringify(payload)
      );

    } catch (err) {

      if (
        err.statusCode === 404 ||
        err.statusCode === 410
      ) {

        await pool.query(
          `DELETE FROM push_subscriptions
           WHERE id=$1`,
          [sub.id]
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

    if (role === 'admin' && code === ADMIN_CODE) {

      return res.json({
        role: 'admin'
      });
    }

    if (role === 'guardian' && code === GUARDIAN_CODE) {

      return res.json({
        role: 'guardian'
      });
    }

    if (role === 'member') {

      const result = await pool.query(
        `
        SELECT id, first_name, last_name, role, photo
        FROM members
        WHERE code_hash=$1
        ORDER BY id
        LIMIT 1
        `,
        [hashCode(code)]
      );

      const member = result.rows[0];

      if (!member) {

        return res.status(401).json({
          error: 'Nieprawidłowy kod członka.'
        });
      }

      return res.json({
        role: 'member',
        memberId: member.id,

        firstName: member.first_name || '',
        lastName: member.last_name || '',

        member: {
          id: member.id,
          first_name: member.first_name || '',
          last_name: member.last_name || '',
          role: member.role || 'member',
          photo: member.photo || ''
        }
      });
    }

    return res.status(401).json({
      error: 'Nieprawidłowe dane logowania.'
    });

  } catch (err) {

    console.error(err);

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

      pool.query(
        `
        SELECT *
        FROM events
        ORDER BY
          event_date ASC NULLS LAST,
          event_time ASC NULLS LAST,
          id DESC
        `
      ),

      pool.query(
        `
        SELECT *
        FROM news
        ORDER BY created_at DESC, id DESC
        `
      ),

      pool.query(
        `
        SELECT
          id,
          first_name,
          last_name,
          role,
          photo,
          name,
          created_at
        FROM members
        ORDER BY first_name, last_name, id
        `
      ),

      pool.query(
        `
        SELECT
          id,
          title,
          body,
          active,
          created_at
        FROM urgent_messages
        WHERE active=TRUE
        ORDER BY created_at DESC, id DESC
        `
      )

    ]);

    res.json({
      events: events.rows,
      news: news.rows,
      members: members.rows,
      urgent: urgent.rows
    });

  } catch (err) {

    console.error(err);

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

    const [
      members,
      events,
      news,
      attendance
    ] = await Promise.all([

      pool.query(
        `SELECT COUNT(*)::int AS count FROM members`
      ),

      pool.query(
        `SELECT COUNT(*)::int AS count FROM events`
      ),

      pool.query(
        `SELECT COUNT(*)::int AS count FROM news`
      ),

      pool.query(
        `
        SELECT
          COUNT(*)::int AS total,
          COUNT(*) FILTER (WHERE status='yes')::int AS yes,
          COUNT(*) FILTER (WHERE status='maybe')::int AS maybe,
          COUNT(*) FILTER (WHERE status='no')::int AS no
        FROM attendance
        `
      )

    ]);

    res.json({
      members: members.rows[0].count,
      events: events.rows[0].count,
      news: news.rows[0].count,
      attendance: attendance.rows[0]
    });

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: 'Nie udało się pobrać statystyk.'
    });
  }
});


/* =========================================================
   ZBIÓRKI
========================================================= */

app.post('/api/events', auth, staff, async (req, res) => {

  try {

    const {
      title,
      event_date,
      event_time,
      place,
      description
    } = req.body;

    if (!title) {

      return res.status(400).json({
        error: 'Podaj nazwę zbiórki.'
      });
    }

    const result = await pool.query(
      `
      INSERT INTO events
      (title,event_date,event_time,place,description)
      VALUES ($1,$2,$3,$4,$5)
      RETURNING *
      `,
      [
        title,
        event_date || '',
        event_time || '',
        place || '',
        description || ''
      ]
    );

    res.json(result.rows[0]);

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: 'Nie udało się dodać zbiórki.'
    });
  }
});


app.delete('/api/events/:id', auth, staff, async (req, res) => {

  try {

    await pool.query(
      `DELETE FROM events WHERE id=$1`,
      [req.params.id]
    );

    res.json({
      ok: true
    });

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: 'Nie udało się usunąć zbiórki.'
    });
  }
});


/* =========================================================
   OGŁOSZENIA
========================================================= */

app.post('/api/news', auth, staff, async (req, res) => {

  try {

    const {
      title,
      body
    } = req.body;

    if (!title) {

      return res.status(400).json({
        error: 'Podaj tytuł ogłoszenia.'
      });
    }

    const result = await pool.query(
      `
      INSERT INTO news
      (title,body)
      VALUES ($1,$2)
      RETURNING *
      `,
      [
        title,
        body || ''
      ]
    );

    res.json(result.rows[0]);

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: 'Nie udało się dodać ogłoszenia.'
    });
  }
});


app.delete('/api/news/:id', auth, staff, async (req, res) => {

  try {

    await pool.query(
      `DELETE FROM news WHERE id=$1`,
      [req.params.id]
    );

    res.json({
      ok: true
    });

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: 'Nie udało się usunąć ogłoszenia.'
    });
  }
});


/* =========================================================
   CZŁONKOWIE
========================================================= */

app.post('/api/members', auth, staff, async (req, res) => {

  try {

    const firstName =
      String(req.body.first_name || req.body.firstName || '').trim();

    const lastName =
      String(req.body.last_name || req.body.lastName || '').trim();

    const code =
      String(req.body.code || '').trim();

    const photo =
      String(req.body.photo || '').trim();

    if (!firstName || !lastName || !code) {

      return res.status(400).json({
        error: 'Podaj imię, nazwisko i kod.'
      });
    }

    const result = await pool.query(
      `
      INSERT INTO members
      (name,role,first_name,last_name,code_hash,photo)
      VALUES ($1,'member',$2,$3,$4,$5)
      RETURNING id, name, role, first_name, last_name, photo, created_at
      `,
      [
        `${firstName} ${lastName}`,
        firstName,
        lastName,
        hashCode(code),
        photo
      ]
    );

    res.json(result.rows[0]);

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: 'Nie udało się dodać członka.'
    });
  }
});


app.put('/api/members/:id', auth, staff, async (req, res) => {

  try {

    const oldResult = await pool.query(
      `SELECT * FROM members WHERE id=$1`,
      [req.params.id]
    );

    if (!oldResult.rows[0]) {

      return res.status(404).json({
        error: 'Nie znaleziono członka.'
      });
    }

    const old = oldResult.rows[0];

    const firstName =
      String(
        req.body.first_name ??
        req.body.firstName ??
        old.first_name ??
        ''
      ).trim();

    const lastName =
      String(
        req.body.last_name ??
        req.body.lastName ??
        old.last_name ??
        ''
      ).trim();

    const photo =
      req.body.photo !== undefined
        ? String(req.body.photo || '')
        : (old.photo || '');

    const code =
      req.body.code !== undefined
        ? String(req.body.code || '').trim()
        : null;

    const newHash =
      code !== null && code !== ''
        ? hashCode(code)
        : old.code_hash;

    const name =
      `${firstName} ${lastName}`.trim();

    const result = await pool.query(
      `
      UPDATE members
      SET
        name=$1,
        first_name=$2,
        last_name=$3,
        code_hash=$4,
        photo=$5
      WHERE id=$6
      RETURNING id,name,role,first_name,last_name,photo,created_at
      `,
      [
        name,
        firstName,
        lastName,
        newHash,
        photo,
        req.params.id
      ]
    );

    res.json(result.rows[0]);

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: 'Nie udało się zmienić członka.'
    });
  }
});


app.delete('/api/members/:id', auth, staff, async (req, res) => {

  try {

    await pool.query(
      `DELETE FROM members WHERE id=$1`,
      [req.params.id]
    );

    res.json({
      ok: true
    });

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: 'Nie udało się usunąć członka.'
    });
  }
});


/* =========================================================
   PROFIL
========================================================= */

app.get('/api/profile', auth, async (req, res) => {

  if (req.role !== 'member') {

    return res.status(403).json({
      error: 'Ta funkcja dotyczy członka.'
    });
  }

  try {

    const result = await pool.query(
      `
      SELECT
        id,
        first_name,
        last_name,
        role,
        photo,
        name
      FROM members
      WHERE id=$1
      `,
      [req.memberId]
    );

    if (!result.rows[0]) {

      return res.status(404).json({
        error: 'Nie znaleziono profilu.'
      });
    }

    res.json(result.rows[0]);

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: 'Nie udało się pobrać profilu.'
    });
  }
});


app.put('/api/profile', auth, async (req, res) => {

  if (req.role !== 'member') {

    return res.status(403).json({
      error: 'Ta funkcja dotyczy członka.'
    });
  }

  try {

    const photo =
      String(req.body.photo || '');

    const result = await pool.query(
      `
      UPDATE members
      SET photo=$1
      WHERE id=$2
      RETURNING id,first_name,last_name,role,photo,name
      `,
      [
        photo,
        req.memberId
      ]
    );

    res.json(result.rows[0]);

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: 'Nie udało się zapisać profilu.'
    });
  }
});


/* =========================================================
   OBECNOŚĆ
========================================================= */

app.post('/api/attendance', auth, async (req, res) => {

  try {

    const eventId = Number(req.body.event_id);

    const status =
      String(req.body.status || '').trim();

    if (!eventId || !['yes','maybe','no'].includes(status)) {

      return res.status(400).json({
        error: 'Nieprawidłowa obecność.'
      });
    }

    let memberName =
      String(req.body.member_name || '').trim();

    if (req.role === 'member') {

      memberName =
        `${req.member.first_name || ''} ${req.member.last_name || ''}`.trim();
    }

    if (!memberName) {

      return res.status(400).json({
        error: 'Brak członka.'
      });
    }

    const result = await pool.query(
      `
      INSERT INTO attendance
      (event_id,member_name,status)
      VALUES ($1,$2,$3)
      ON CONFLICT(event_id,member_name)
      DO UPDATE SET
        status=EXCLUDED.status,
        created_at=NOW()
      RETURNING *
      `,
      [
        eventId,
        memberName,
        status
      ]
    );

    res.json(result.rows[0]);

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: 'Nie udało się zapisać obecności.'
    });
  }
});


app.post('/api/attendance/:eventId', auth, async (req, res) => {

  req.body.event_id = Number(req.params.eventId);

  return app._router.handle(req, res);
});


app.get('/api/attendance/:eventId', auth, staff, async (req, res) => {

  try {

    const result = await pool.query(
      `
      SELECT *
      FROM attendance
      WHERE event_id=$1
      ORDER BY created_at ASC, id ASC
      `,
      [req.params.eventId]
    );

    res.json(result.rows);

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: 'Nie udało się pobrać obecności.'
    });
  }
});


app.get('/api/member-stats/:memberId', auth, async (req, res) => {

  try {

    if (
      req.role === 'member' &&
      Number(req.memberId) !== Number(req.params.memberId)
    ) {

      return res.status(403).json({
        error: 'Brak uprawnień.'
      });
    }

    const result = await pool.query(
      `
      SELECT
        COUNT(*)::int AS total,
        COUNT(*) FILTER
          (WHERE status='yes')::int AS attended,
        COUNT(*) FILTER
          (WHERE status='no')::int AS absent,
        COUNT(*) FILTER
          (WHERE status='maybe')::int AS maybe
      FROM attendance a
      JOIN members m
        ON TRIM(
          CONCAT(
            COALESCE(m.first_name,''),
            ' ',
            COALESCE(m.last_name,'')
          )
        ) = a.member_name
      WHERE m.id=$1
      `,
      [req.params.memberId]
    );

    const row = result.rows[0];

    const total = Number(row.total || 0);
    const attended = Number(row.attended || 0);

    res.json({
      total,
      attended,
      absent: Number(row.absent || 0),
      maybe: Number(row.maybe || 0),
      percentage: total
        ? Math.round((attended / total) * 100)
        : 0
    });

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: 'Nie udało się pobrać statystyk członka.'
    });
  }
});


/* =========================================================
   PILNE KOMUNIKATY
========================================================= */

app.post('/api/urgent-messages', auth, staff, async (req, res) => {

  try {

    const title =
      String(req.body.title || '').trim();

    const body =
      String(req.body.body || '').trim();

    if (!title || !body) {

      return res.status(400).json({
        error: 'Podaj tytuł i treść komunikatu.'
      });
    }

    await pool.query(
      `UPDATE urgent_messages
       SET active=FALSE
       WHERE active=TRUE`
    );

    const result = await pool.query(
      `
      INSERT INTO urgent_messages
      (title,body,active,created_by_role)
      VALUES ($1,$2,TRUE,$3)
      RETURNING *
      `,
      [
        title,
        body,
        req.role
      ]
    );

    await sendPushToAll({
      title: `🚨 ${title}`,
      body
    });

    res.json(result.rows[0]);

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: 'Nie udało się dodać pilnego komunikatu.'
    });
  }
});


app.get('/api/urgent-messages', auth, async (req, res) => {

  try {

    let result;

    if (isStaff(req)) {

      result = await pool.query(
        `
        SELECT *
        FROM urgent_messages
        ORDER BY created_at DESC,id DESC
        `
      );

    } else {

      result = await pool.query(
        `
        SELECT *
        FROM urgent_messages
        WHERE active=TRUE
        ORDER BY created_at DESC,id DESC
        `
      );
    }

    res.json(result.rows);

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: 'Nie udało się pobrać komunikatów.'
    });
  }
});


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

    } catch (err) {

      console.error(err);

      res.status(500).json({
        error: 'Nie udało się usunąć komunikatu.'
      });
    }
  }
);


/* =========================================================
   ZGŁOSZENIA OD CZŁONKÓW
========================================================= */

app.post('/api/member-reports', auth, async (req, res) => {

  try {

    if (req.role !== 'member') {

      return res.status(403).json({
        error: 'Zgłoszenia są dostępne dla członków.'
      });
    }

    const type =
      String(req.body.type || 'Inne').trim();

    const body =
      String(req.body.body || '').trim();

    if (!body) {

      return res.status(400).json({
        error: 'Napisz treść zgłoszenia.'
      });
    }

    const memberName =
      `${req.member.first_name || ''} ${req.member.last_name || ''}`.trim();

    const result = await pool.query(
      `
      INSERT INTO member_reports
      (member_id,member_name,report_type,body,status)
      VALUES ($1,$2,$3,$4,'new')
      RETURNING *
      `,
      [
        req.member.id,
        memberName,
        type,
        body
      ]
    );

    await sendPushToAll({
      title: '📨 Nowe zgłoszenie',
      body: `${memberName}: ${type}`
    });

    res.json(result.rows[0]);

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: 'Nie udało się wysłać zgłoszenia.'
    });
  }
});


app.get('/api/member-reports', auth, staff, async (req, res) => {

  try {

    const result = await pool.query(
      `
      SELECT *
      FROM member_reports
      ORDER BY
        CASE status
          WHEN 'new' THEN 1
          WHEN 'in_progress' THEN 2
          ELSE 3
        END,
        created_at DESC,
        id DESC
      `
    );

    res.json(result.rows);

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: 'Nie udało się pobrać zgłoszeń.'
    });
  }
});


app.put(
  '/api/member-reports/:id',
  auth,
  staff,
  async (req, res) => {

    try {

      const status =
        String(req.body.status || '').trim();

      if (!['new','in_progress','done'].includes(status)) {

        return res.status(400).json({
          error: 'Nieprawidłowy status.'
        });
      }

      const result = await pool.query(
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

      if (!result.rows[0]) {

        return res.status(404).json({
          error: 'Nie znaleziono zgłoszenia.'
        });
      }

      res.json(result.rows[0]);

    } catch (err) {

      console.error(err);

      res.status(500).json({
        error: 'Nie udało się zmienić zgłoszenia.'
      });
    }
  }
);


/* =========================================================
   GAZETY
========================================================= */

app.get('/api/newspaper-groups', auth, async (req, res) => {

  try {

    res.json(await getGroups());

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: 'Nie udało się pobrać grup gazet.'
    });
  }
});


app.post('/api/newspaper-groups', auth, staff, async (req, res) => {

  try {

    const b = req.body;

    const name =
      String(b.name || '').trim();

    const region =
      String(b.region || '').trim();

    if (!name || !region) {

      return res.status(400).json({
        error: 'Podaj nazwę grupy i region.'
      });
    }

    const ids =
      Array.isArray(b.memberIds)
        ? b.memberIds
            .map(Number)
            .filter(Number.isFinite)
        : [];

    const memberResult = ids.length
      ? await pool.query(
          `
          SELECT id,first_name,last_name,name
          FROM members
          WHERE id=ANY($1::int[])
          `,
          [ids]
        )
      : { rows: [] };

    const names =
      memberResult.rows
        .map(member =>
          `${member.first_name || ''} ${member.last_name || ''}`.trim()
        )
        .filter(Boolean);

    const copies =
      Math.max(0, Number(b.copies || 0));

    const result = await pool.query(
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
      ($1,$2,$3,$4::jsonb,$5,$6::jsonb,$7::jsonb)
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
        result.rows[0],
        memberResult.rows
      )
    );

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: 'Nie udało się zapisać grupy gazet.'
    });
  }
});


app.put('/api/newspaper-groups/:id', auth, async (req, res) => {

  try {

    const oldResult = await pool.query(
      `
      SELECT *
      FROM newspaper_groups
      WHERE id=$1
      `,
      [req.params.id]
    );

    if (!oldResult.rows[0]) {

      return res.status(404).json({
        error: 'Nie znaleziono grupy.'
      });
    }

    const old = oldResult.rows[0];

    const oldIds =
      Array.isArray(old.member_ids)
        ? old.member_ids.map(Number)
        : [];

    const oldNames =
      Array.isArray(old.member_names)
        ? old.member_names.map(String)
        : [];

    if (req.role === 'member') {

      if (!oldIds.includes(Number(req.member.id))) {

        return res.status(403).json({
          error: 'Brak dostępu do tej grupy.'
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

      await pool.query(
        `
        UPDATE newspaper_groups
        SET
          delivered=$1,
          started=$2,
          done=$3
        WHERE id=$4
        `,
        [
          delivered,
          started,
          done,
          req.params.id
        ]
      );

      const groups = await getGroups();

      return res.json(
        groups.find(
          group =>
            group.id === Number(req.params.id)
        )
      );
    }

    if (!isStaff(req)) {

      return res.status(403).json({
        error: 'Brak uprawnień.'
      });
    }

    const ids =
      Array.isArray(req.body.memberIds)
        ? req.body.memberIds
            .map(Number)
            .filter(Number.isFinite)
        : oldIds;

    const memberResult = ids.length
      ? await pool.query(
          `
          SELECT id,first_name,last_name,name
          FROM members
          WHERE id=ANY($1::int[])
          `,
          [ids]
        )
      : { rows: [] };

    const names =
      Array.isArray(req.body.memberIds)
        ? memberResult.rows
            .map(member =>
              `${member.first_name || ''} ${member.last_name || ''}`.trim()
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

    const result = await pool.query(
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
        req.body.name ?? old.name,
        req.body.region ?? old.region,
        req.body.color ?? old.color,

        JSON.stringify(
          Array.isArray(req.body.streets)
            ? req.body.streets
            : (
                Array.isArray(old.streets)
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
        result.rows[0],
        memberResult.rows
      )
    );

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: 'Nie udało się zmienić grupy gazet.'
    });
  }
});


async function updateGroupProgress(req, res, id) {

  try {

    const result = await pool.query(
      `
      SELECT *
      FROM newspaper_groups
      WHERE id=$1
      `,
      [id]
    );

    if (!result.rows[0]) {

      return res.status(404).json({
        error: 'Nie znaleziono grupy.'
      });
    }

    const group = result.rows[0];

    const ids =
      Array.isArray(group.member_ids)
        ? group.member_ids.map(Number)
        : [];

    if (
      req.role === 'member' &&
      !ids.includes(Number(req.member.id))
    ) {

      return res.status(403).json({
        error: 'Brak dostępu do tej grupy.'
      });
    }

    if (
      !isStaff(req) &&
      req.role !== 'member'
    ) {

      return res.status(403).json({
        error: 'Brak uprawnień.'
      });
    }

    const delivered =
      Math.min(
        Number(group.copies),
        Math.max(
          0,
          Number(
            req.body.delivered ??
            group.delivered
          )
        )
      );

    const started =
      req.body.started === undefined
        ? !!group.started
        : !!req.body.started;

    const done =
      req.body.done === undefined
        ? !!group.done
        : !!req.body.done;

    await pool.query(
      `
      UPDATE newspaper_groups
      SET
        delivered=$1,
        started=$2,
        done=$3
      WHERE id=$4
      `,
      [
        delivered,
        started,
        done,
        id
      ]
    );

    const groups = await getGroups();

    res.json(
      groups.find(
        item =>
          item.id === Number(id)
      )
    );

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: 'Nie udało się zapisać postępu.'
    });
  }
}


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
  async (req, res) => {

    return updateGroupProgress(
      req,
      res,
      req.params.id
    );
  }
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

    } catch (err) {

      console.error(err);

      res.status(500).json({
        error: 'Nie udało się usunąć grupy gazet.'
      });
    }
  }
);


/* =========================================================
   RESET GRUP GAZET
========================================================= */

app.post(
  '/api/newspaper-groups/reset',
  auth,
  staff,
  async (req, res) => {

    try {

      await pool.query(
        `DELETE FROM newspaper_groups`
      );

      await seedNewspaperGroups();

      res.json(
        await getGroups()
      );

    } catch (err) {

      console.error(err);

      res.status(500).json({
        error: 'Nie udało się przywrócić planu gazet.'
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

      const result = await pool.query(
        `
        SELECT
          id,
          month_key,
          month_label,
          saved_at,
          groups
        FROM newspaper_history
        ORDER BY month_key DESC,id DESC
        `
      );

      res.json(result.rows);

    } catch (err) {

      console.error(err);

      res.status(500).json({
        error: 'Nie udało się pobrać historii gazet.'
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

    const client = await pool.connect();

    try {

      await client.query('BEGIN');

      const groupsResult = await client.query(
        `
        SELECT *
        FROM newspaper_groups
        ORDER BY id
        FOR UPDATE
        `
      );

      if (!groupsResult.rows.length) {

        await client.query('ROLLBACK');

        return res.status(400).json({
          error: 'Brak grup gazet do zapisania.'
        });
      }

      const now = new Date();

      const year =
        now.getFullYear();

      const month =
        String(now.getMonth() + 1)
          .padStart(2, '0');

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
        groupsResult.rows.map(group => ({

          id: group.id,

          name: group.name,

          region: group.region,

          color: group.color,

          streets:
            Array.isArray(group.streets)
              ? group.streets
              : [],

          copies:
            Number(group.copies || 0),

          delivered:
            Number(group.delivered || 0),

          started:
            !!group.started,

          done:
            !!group.done,

          memberIds:
            Array.isArray(group.member_ids)
              ? group.member_ids.map(Number)
              : [],

          memberNames:
            Array.isArray(group.member_names)
              ? group.member_names
              : []
        }));

      const exists = await client.query(
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
          (month_key,month_label,groups)
          VALUES ($1,$2,$3::jsonb)
          `,
          [
            monthKey,
            monthLabel,
            JSON.stringify(snapshot)
          ]
        );
      }

      await client.query(
        `
        UPDATE newspaper_groups
        SET
          delivered=0,
          started=FALSE,
          done=FALSE
        `
      );

      await client.query('COMMIT');

      res.json({
        ok: true,
        archivedMonth: monthLabel,
        groups: await getGroups()
      });

    } catch (err) {

      await client
        .query('ROLLBACK')
        .catch(() => {});

      console.error(err);

      res.status(500).json({
        error: 'Nie udało się rozpocząć nowego miesiąca.'
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

      const subscription = req.body;

      if (!subscription?.endpoint) {

        return res.status(400).json({
          error: 'Brak endpointu.'
        });
      }

      await pool.query(
        `
        INSERT INTO push_subscriptions
        (endpoint,subscription)
        VALUES ($1,$2::jsonb)
        ON CONFLICT(endpoint)
        DO UPDATE SET
          subscription=EXCLUDED.subscription
        `,
        [
          subscription.endpoint,
          JSON.stringify(subscription)
        ]
      );

      res.json({
        ok: true
      });

    } catch (err) {

      console.error(err);

      res.status(500).json({
        error: 'Nie udało się zapisać powiadomień.'
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
        error: 'Powiadomienia push nie są skonfigurowane.'
      });
    }

    res.json({
      publicKey: VAPID_PUBLIC_KEY
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

    } catch (err) {

      console.error(err);

      res.status(500).json({
        error: 'Nie udało się usunąć subskrypcji.'
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

    } catch (err) {

      console.error(err);

      res.status(500).json({
        error: 'Nie udało się wysłać powiadomienia.'
      });
    }
  }
);


/* =========================================================
   HEALTH
========================================================= */

app.get('/api/health', async (req, res) => {

  try {

    await pool.query('SELECT 1');

    res.json({
      ok: true
    });

  } catch (err) {

    console.error(err);

    res.status(500).json({
      ok: false
    });
  }
});


/* =========================================================
   NIEZNANE API
========================================================= */

app.use('/api', (req, res) => {

  res.status(404).json({
    error: 'Nie znaleziono endpointu.'
  });
});


/* =========================================================
   PWA / STRONA
   WAŻNE: NIE MA app.get('*')
   bo Express 5 wyrzuca przez to PathError.
========================================================= */

app.use((req, res) => {

  res.sendFile(
    path.join(
      __dirname,
      'public',
      'index.html'
    )
  );
});


/* =========================================================
   START
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
