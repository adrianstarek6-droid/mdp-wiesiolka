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


// ======================================================
// HELPERY
// ======================================================

const hashCode = code =>
  crypto
    .createHash('sha256')
    .update(String(code || ''))
    .digest('hex');

const normRole = role => {
  const r = String(role || '').toLowerCase().trim();

  if (['opiekun', 'guardian'].includes(r)) return 'guardian';
  if (['admin', 'administrator'].includes(r)) return 'admin';
  if (['member', 'czlonek', 'członek'].includes(r)) return 'member';

  return r;
};

const isStaff = req =>
  req.role === 'admin' || req.role === 'guardian';

function safeArray(value) {
  if (Array.isArray(value)) return value;

  if (typeof value === 'string') {
    try {
      const parsed = JSON.parse(value);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }

  return [];
}

function normalizeIds(value) {
  return [
    ...new Set(
      safeArray(value)
        .map(Number)
        .filter(Number.isInteger)
        .filter(x => x > 0)
    )
  ];
}

function normalizeNames(value) {
  return [
    ...new Set(
      safeArray(value)
        .map(x => String(x || '').trim())
        .filter(Boolean)
    )
  ];
}

function monthInfo(date = new Date()) {
  const year = date.getFullYear();

  const month = String(
    date.getMonth() + 1
  ).padStart(2, '0');

  const monthKey = `${year}-${month}`;

  const monthLabel =
    new Intl.DateTimeFormat('pl-PL', {
      month: 'long',
      year: 'numeric'
    }).format(date);

  return {
    year,
    month,
    monthKey,
    monthLabel
  };
}

function groupSnapshot(row) {
  return {
    id: Number(row.id),
    name: row.name || '',
    region: row.region || '',
    color: row.color || '#2878ff',

    streets: safeArray(row.streets),

    copies: Number(row.copies || 0),
    delivered: Number(row.delivered || 0),

    started: !!row.started,
    done: !!row.done,

    memberIds: normalizeIds(row.member_ids),
    memberNames: normalizeNames(row.member_names)
  };
}

function groupJson(row, members = []) {
  return {
    id: Number(row.id),
    name: row.name || '',
    region: row.region || '',
    color: row.color || '#2878ff',

    streets: safeArray(row.streets),

    copies: Number(row.copies || 0),
    delivered: Number(row.delivered || 0),

    started: !!row.started,
    done: !!row.done,

    memberIds: normalizeIds(row.member_ids),
    memberNames: normalizeNames(row.member_names),

    members
  };
}


// ======================================================
// AUTH
// ======================================================

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


// ======================================================
// BAZA DANYCH
// ======================================================

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS events (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      event_date TEXT,
      event_time TEXT,
      place TEXT,
      description TEXT,
      outfit TEXT,
      completed BOOLEAN NOT NULL DEFAULT FALSE,
      completed_at TIMESTAMPTZ,
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
      event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
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
      member_id INTEGER REFERENCES members(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS event_reminders (
      id SERIAL PRIMARY KEY,
      event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
      member_id INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
      last_sent_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(event_id, member_id)
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
      member_id INTEGER REFERENCES members(id) ON DELETE CASCADE,
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
    'ALTER TABLE events ADD COLUMN IF NOT EXISTS outfit TEXT'
  );

  await pool.query(
    'ALTER TABLE events ADD COLUMN IF NOT EXISTS completed BOOLEAN NOT NULL DEFAULT FALSE'
  );

  await pool.query(
    'ALTER TABLE events ADD COLUMN IF NOT EXISTS completed_at TIMESTAMPTZ'
  );

  await pool.query(
    'ALTER TABLE members ADD COLUMN IF NOT EXISTS first_name TEXT'
  );

  await pool.query(
    'ALTER TABLE members ADD COLUMN IF NOT EXISTS last_name TEXT'
  );

  await pool.query(
    'ALTER TABLE members ADD COLUMN IF NOT EXISTS code_hash TEXT'
  );

  await pool.query(
    'ALTER TABLE members ADD COLUMN IF NOT EXISTS photo TEXT'
  );

  await pool.query(
    'ALTER TABLE members ADD COLUMN IF NOT EXISTS address TEXT'
  );

  await pool.query(
    'ALTER TABLE members ADD COLUMN IF NOT EXISTS phone TEXT'
  );

  await pool.query(
    'ALTER TABLE members ADD COLUMN IF NOT EXISTS guardian_phone TEXT'
  );

  await pool.query(`
    CREATE TABLE IF NOT EXISTS member_uniforms (
      member_id INTEGER PRIMARY KEY REFERENCES members(id) ON DELETE CASCADE,
      items JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(
    'ALTER TABLE push_subscriptions ADD COLUMN IF NOT EXISTS member_id INTEGER REFERENCES members(id) ON DELETE CASCADE'
  );

  await pool.query(`
    CREATE TABLE IF NOT EXISTS event_reminders (
      id SERIAL PRIMARY KEY,
      event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
      member_id INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
      last_sent_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(event_id, member_id)
    )
  `);

  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS
    newspaper_history_month_key_unique
    ON newspaper_history(month_key)
  `);

  const c = await pool.query(
    'SELECT COUNT(*)::int AS count FROM newspaper_groups'
  );

  if (c.rows[0].count === 0) {
    await seedNewspaperGroups();
  }
}

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

  for (const g of groups) {
    await pool.query(
      `
      INSERT INTO newspaper_groups
      (name,region,color,streets,copies)
      VALUES($1,$2,$3,$4::jsonb,$5)
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


// ======================================================
// GAZETY — POBIERANIE GRUP
// ======================================================

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
    let ids = normalizeIds(row.member_ids);
    let names = normalizeNames(row.member_names);

    if (!ids.length && names.length) {
      ids = members
        .filter(x => {
          const fullName =
            `${x.first_name || ''} ${x.last_name || ''}`
              .trim();

          return (
            names.includes(fullName) ||
            names.includes(x.name || '')
          );
        })
        .map(x => Number(x.id));
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


// ======================================================
// PUSH
// ======================================================

async function sendPushToAll(payload) {
  if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) {
    return;
  }

  const r = await pool.query(
    'SELECT id,endpoint,subscription FROM push_subscriptions'
  );

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
          'DELETE FROM push_subscriptions WHERE id=$1',
          [s.id]
        );
      }
    }
  }
}

async function sendPushToMember(memberId, payload) {
  if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) {
    return;
  }

  const r = await pool.query(
    `
    SELECT id, endpoint, subscription
    FROM push_subscriptions
    WHERE member_id=$1
    `,
    [memberId]
  );

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
          'DELETE FROM push_subscriptions WHERE id=$1',
          [s.id]
        );
      } else {
        console.error(
          'Błąd push dla członka',
          memberId,
          e
        );
      }
    }
  }
}

function parseEventStart(event) {
  if (!event?.event_date) return null;

  const date = String(event.event_date).trim();
  const time = String(
    event.event_time || '00:00'
  ).trim();

  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(date);

  if (!match) return null;

  const parts = time.match(
    /^(\d{1,2}):(\d{2})$/
  );

  const hour = parts
    ? Number(parts[1])
    : 0;

  const minute = parts
    ? Number(parts[2])
    : 0;

  const d = new Date(
    Number(match[1]),
    Number(match[2]) - 1,
    Number(match[3]),
    hour,
    minute,
    0,
    0
  );

  return Number.isNaN(d.getTime())
    ? null
    : d;
}

async function sendNewEventPush(event) {
  if (!event?.id) return;

  const r = await pool.query(`
    SELECT id
    FROM members
    WHERE role='member'
    ORDER BY id
  `);

  const outfit = String(
    event.outfit || ''
  ).trim();

  const bodyParts = [
    event.title || 'Nowa zbiórka'
  ];

  if (event.event_date) {
    bodyParts.push(`📅 ${event.event_date}`);
  }

  if (event.event_time) {
    bodyParts.push(`🕐 ${event.event_time}`);
  }

  if (outfit) {
    bodyParts.push(`👕 ${outfit}`);
  }

  for (const member of r.rows) {
    try {
      await sendPushToMember(
        member.id,
        {
          title: '📅 Nowa zbiórka MDP',
          body: bodyParts.join(' • '),
          eventId: Number(event.id),
          type: 'event-attendance',
          url: '/'
        }
      );
    } catch (e) {
      console.error(
        'Błąd wysyłania nowej zbiórki:',
        e
      );
    }
  }
}

async function processEventAttendanceReminders() {
  if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) {
    return;
  }

  try {
    const eventsResult = await pool.query(`
      SELECT *
      FROM events
      WHERE event_date IS NOT NULL
        AND event_date <> ''
      ORDER BY id
    `);

    const now = new Date();

    for (const event of eventsResult.rows) {
      const startsAt = parseEventStart(event);

      if (!startsAt || now >= startsAt) {
        continue;
      }

      const membersResult = await pool.query(`
        SELECT
          m.id,
          m.first_name,
          m.last_name
        FROM members m
        WHERE m.role='member'
        ORDER BY m.id
      `);

      for (const member of membersResult.rows) {
        const memberName =
          `${member.first_name || ''} ${member.last_name || ''}`
            .trim();

        if (!memberName) continue;

        const attendanceResult = await pool.query(
          `
          SELECT status
          FROM attendance
          WHERE event_id=$1
            AND member_name=$2
          LIMIT 1
          `,
          [
            event.id,
            memberName
          ]
        );

        const status =
          attendanceResult.rows[0]?.status || null;

        // "yes" i "no" są odpowiedziami końcowymi.
        // "maybe" nadal dostaje przypomnienia.
        if (
          status === 'yes' ||
          status === 'no'
        ) {
          continue;
        }

        const reminderResult = await pool.query(
          `
          SELECT last_sent_at
          FROM event_reminders
          WHERE event_id=$1
            AND member_id=$2
          LIMIT 1
          `,
          [
            event.id,
            member.id
          ]
        );

        const lastSent =
          reminderResult.rows[0]?.last_sent_at
            ? new Date(
                reminderResult.rows[0].last_sent_at
              )
            : null;

        // Pierwsze przypomnienie dopiero 30 minut
        // po utworzeniu zbiórki. Kolejne co 30 minut.
        const baseTime = lastSent
          ? lastSent.getTime()
          : new Date(event.created_at).getTime();

        if (
          !Number.isFinite(baseTime) ||
          now.getTime() - baseTime <
            30 * 60 * 1000
        ) {
          continue;
        }

        const outfit = String(
          event.outfit || ''
        ).trim();

        const body = outfit
          ? `Nie zapomnij odpowiedzieć na zbiórkę „${event.title}”. 👕 Ubiór: ${outfit}`
          : `Nie zapomnij odpowiedzieć na zbiórkę „${event.title}”.`;

        try {
          await sendPushToMember(
            member.id,
            {
              title: '⏰ Przypomnienie o zbiórce',
              body,
              eventId: Number(event.id),
              type: 'event-attendance-reminder',
              url: '/'
            }
          );

          await pool.query(
            `
            INSERT INTO event_reminders
            (event_id,member_id,last_sent_at)
            VALUES($1,$2,NOW())
            ON CONFLICT(event_id,member_id)
            DO UPDATE SET
              last_sent_at=NOW()
            `,
            [
              event.id,
              member.id
            ]
          );
        } catch (e) {
          console.error(
            'Błąd przypomnienia o zbiórce:',
            e
          );
        }
      }
    }
  } catch (e) {
    console.error(
      'Błąd automatycznych przypomnień:',
      e
    );
  }
}


// ======================================================
// LOGIN
// ======================================================

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


// ======================================================
// DATA
// ======================================================

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
          ${['guardian','admin'].includes(req.role) ? ', address, phone, guardian_phone' : ''}
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


function staffOnly(req, res) {
  if (!req.authenticated || !['guardian', 'admin'].includes(req.role)) {
    res.status(403).json({ error: 'Dostęp tylko dla opiekuna lub administratora.' });
    return false;
  }
  return true;
}

app.get('/api/member-records', auth, async (req, res) => {
  if (!staffOnly(req, res)) return;
  try {
    const r = await pool.query(`
      SELECT id, first_name, last_name, role, photo, name,
             address, phone, guardian_phone, created_at
      FROM members
      WHERE role = 'member' OR role IS NULL
      ORDER BY first_name, last_name, id
    `);
    res.json({ members: r.rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Nie udało się pobrać danych członków.' });
  }
});

app.put('/api/member-records/:id', auth, async (req, res) => {
  if (!staffOnly(req, res)) return;
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({ error: 'Nieprawidłowy identyfikator członka.' });
    }
    const address = String(req.body?.address ?? '').trim();
    const phone = String(req.body?.phone ?? '').trim();
    const guardianPhone = String(req.body?.guardian_phone ?? '').trim();
    const r = await pool.query(`
      UPDATE members
      SET address=$1, phone=$2, guardian_phone=$3
      WHERE id=$4
      RETURNING id, first_name, last_name, role, photo, name, address, phone, guardian_phone, created_at
    `, [address, phone, guardianPhone, id]);
    if (!r.rows.length) return res.status(404).json({ error: 'Członek nie istnieje.' });
    res.json(r.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Nie udało się zapisać danych członka.' });
  }
});

app.get('/api/member-uniforms', auth, async (req, res) => {
  if (!staffOnly(req, res)) return;
  try {
    const r = await pool.query(`
      SELECT m.id, m.first_name, m.last_name, m.name,
             COALESCE(mu.items, '{}'::jsonb) AS items
      FROM members m
      LEFT JOIN member_uniforms mu ON mu.member_id=m.id
      WHERE m.role='member' OR m.role IS NULL
      ORDER BY m.first_name, m.last_name, m.id
    `);
    res.json({ members: r.rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Nie udało się pobrać umundurowania.' });
  }
});

app.put('/api/member-uniforms/:id', auth, async (req, res) => {
  if (!staffOnly(req, res)) return;
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({ error: 'Nieprawidłowy identyfikator członka.' });
    }
    const member = await pool.query('SELECT id FROM members WHERE id=$1', [id]);
    if (!member.rows.length) return res.status(404).json({ error: 'Członek nie istnieje.' });
    const allowed = ['koszula','krawat','czapka_czerwona','czapka_czarna','czapka_zimowa','czarna_koszulka','czerwona_koszulka','bluza_koszaru','spodnie_koszaru','bandama','kamizelka'];
    const incoming = req.body?.items && typeof req.body.items === 'object' ? req.body.items : {};
    const items = {};
    for (const key of allowed) items[key] = incoming[key] === true;
    const r = await pool.query(`
      INSERT INTO member_uniforms(member_id, items, updated_at)
      VALUES($1,$2::jsonb,NOW())
      ON CONFLICT(member_id) DO UPDATE SET items=EXCLUDED.items, updated_at=NOW()
      RETURNING member_id, items
    `, [id, JSON.stringify(items)]);
    res.json({ memberId: Number(r.rows[0].member_id), items: r.rows[0].items || {} });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Nie udało się zapisać umundurowania.' });
  }
});

app.delete('/api/member-uniforms/:id', auth, async (req, res) => {
  if (!staffOnly(req, res)) return;
  try {
    const id = Number(req.params.id);
    await pool.query('DELETE FROM member_uniforms WHERE member_id=$1', [id]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Nie udało się usunąć członka z ewidencji.' });
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


// ======================================================
// EVENTS
// ======================================================

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

    const outfit = String(
      b.outfit ||
      b.clothing ||
      ''
    ).trim();

    const r = await pool.query(
      `
      INSERT INTO events
      (title,event_date,event_time,place,description,outfit)
      VALUES($1,$2,$3,$4,$5,$6)
      RETURNING *
      `,
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
          '',
        outfit
      ]
    );

    try {
      await sendNewEventPush(r.rows[0]);
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

app.put(
  '/api/events/:id',
  auth,
  staff,
  async (req, res) => {
    try {
      const b = req.body;

      const r = await pool.query(
        `
        UPDATE events
        SET
          title=COALESCE($1,title),
          event_date=COALESCE($2,event_date),
          event_time=COALESCE($3,event_time),
          place=COALESCE($4,place),
          description=COALESCE($5,description),
          outfit=COALESCE($6,outfit)
        WHERE id=$7
        RETURNING *
        `,
        [
          b.title !== undefined
            ? String(b.title).trim()
            : null,

          b.event_date !== undefined
            ? b.event_date
            : null,

          b.event_time !== undefined
            ? b.event_time
            : null,

          b.place !== undefined
            ? b.place
            : null,

          b.description !== undefined
            ? b.description
            : null,

          b.outfit !== undefined
            ? String(b.outfit).trim()
            : null,

          req.params.id
        ]
      );

      if (!r.rows[0]) {
        return res.status(404).json({
          error:
            'Nie znaleziono zbiórki.'
        });
      }

      res.json(r.rows[0]);

    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Nie udało się zmienić zbiórki.'
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


// ======================================================
// NEWS
// ======================================================

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
        error:
          'Nie udało się usunąć ogłoszenia.'
      });
    }
  }
);


// ======================================================
// PILNE
// ======================================================

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
          error: 'Podaj tytuł i treść komunikatu.'
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
        (title,body,active,created_by_role)
        VALUES($1,$2,TRUE,$3)
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
      const result = await pool.query(
        `
        DELETE FROM urgent_messages
        WHERE id=$1
        RETURNING id
        `,
        [req.params.id]
      );

      if (!result.rows[0]) {
        return res.status(404).json({
          error:
            'Nie znaleziono pilnego komunikatu.'
        });
      }

      res.json({
        ok: true,
        deleted: true
      });

    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Nie udało się usunąć pilnego komunikatu.'
      });
    }
  }
);


// ======================================================
// ZGŁOSZENIA
// ======================================================

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
          error: 'Napisz treść zgłoszenia.'
        });
      }

      const memberName =
        `${req.member.first_name || ''} ${req.member.last_name || ''}`
          .trim() ||
        'Członek MDP';

      const r = await pool.query(
        `
        INSERT INTO member_reports
        (member_id,member_name,report_type,body)
        VALUES($1,$2,$3,$4)
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
          title: 'Nowe zgłoszenie od członka',
          body: `${memberName}: ${type}`
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


// ======================================================
// MEMBERS
// ======================================================

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
        (first_name,last_name,name,role,code_hash)
        VALUES($1,$2,$3,$4,$5)
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
        'DELETE FROM members WHERE id=$1',
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


// ======================================================
// PROFILE
// ======================================================

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

      res.json(r.rows[0] || {});

    } catch (e) {
      res.status(500).json({
        error: 'Błąd profilu.'
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
          error: 'Brak uprawnień.'
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

      res.json(r.rows[0] || {});

    } catch (e) {
      res.status(500).json({
        error:
          'Nie udało się zapisać profilu.'
      });
    }
  }
);


// ======================================================
// ATTENDANCE
// ======================================================

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
      'SELECT id,completed FROM events WHERE id=$1',
      [eventId]
    );

    if (!ev.rows[0]) {
      return res.status(404).json({
        error:
          'Nie znaleziono zbiórki.'
      });
    }

    // Członek nie może zmieniać odpowiedzi po zakończeniu zbiórki,
    // ale opiekun/admin musi móc poprawić faktyczną obecność w historii.
    if (ev.rows[0].completed && req.role === 'member') {
      return res.status(400).json({
        error:
          'Ta zbiórka została już zakończona.'
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
        SELECT first_name,last_name
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
      (event_id,member_name,status)
      VALUES($1,$2,$3)
      ON CONFLICT(event_id,member_name)
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
      const eventId = Number(req.params.eventId);

      if (!Number.isInteger(eventId) || eventId <= 0) {
        return res.status(400).json({
          error: 'Nieprawidłowe ID zbiórki.'
        });
      }

      const eventCheck = await pool.query(
        'SELECT id FROM events WHERE id=$1',
        [eventId]
      );

      if (!eventCheck.rows[0]) {
        return res.status(404).json({
          error: 'Nie znaleziono zbiórki.'
        });
      }

      // Zwracamy KAŻDEGO aktualnego członka MDP.
      // Jeśli nie odpowiedział, status będzie NULL i frontend pokaże brak odpowiedzi.
      // Dodatkowo obsługujemy starszych członków, którzy mogą mieć tylko pole `name`.
      const r = await pool.query(
        `
        SELECT
          m.id AS member_id,
          m.first_name,
          m.last_name,
          m.photo,
          COALESCE(
            NULLIF(TRIM(CONCAT(COALESCE(m.first_name,''),' ',COALESCE(m.last_name,''))), ''),
            TRIM(COALESCE(m.name,''))
          ) AS member_name,
          a.status,
          a.created_at
        FROM members m
        LEFT JOIN attendance a
          ON a.event_id=$1
         AND a.member_name=COALESCE(
           NULLIF(TRIM(CONCAT(COALESCE(m.first_name,''),' ',COALESCE(m.last_name,''))), ''),
           TRIM(COALESCE(m.name,''))
         )
        WHERE COALESCE(m.role,'member')='member'
        ORDER BY LOWER(
          COALESCE(
            NULLIF(TRIM(CONCAT(COALESCE(m.first_name,''),' ',COALESCE(m.last_name,''))), ''),
            TRIM(COALESCE(m.name,''))
          )
        ), m.id
        `,
        [eventId]
      );

      res.json(r.rows);

    } catch (e) {
      console.error('Błąd pobierania listy obecności:', e);
      res.status(500).json({
        error: 'Nie udało się pobrać obecności.'
      });
    }
  }
);

// Zakończenie zbiórki: zapisuje końcowy stan obecności wszystkich aktualnych członków.
app.post(
  '/api/events/:id/complete',
  auth,
  staff,
  async (req, res) => {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      const event = await client.query(
        'SELECT * FROM events WHERE id=$1 FOR UPDATE',
        [req.params.id]
      );

      if (!event.rows[0]) {
        await client.query('ROLLBACK');
        return res.status(404).json({error:'Nie znaleziono zbiórki.'});
      }

      if (event.rows[0].completed) {
        await client.query('COMMIT');
        return res.json(event.rows[0]);
      }

      const members = await client.query(`
        SELECT id, first_name, last_name
        FROM members
        WHERE COALESCE(role,'member')='member'
        ORDER BY id
      `);

      for (const member of members.rows) {
        const name = `${member.first_name || ''} ${member.last_name || ''}`.trim();
        if (!name) continue;

        // Jeśli członek nie odpowiedział, zostawiamy go jako "maybe" —
        // nie zawyżamy ani obecności, ani nieobecności.
        await client.query(`
          INSERT INTO attendance(event_id,member_name,status)
          VALUES($1,$2,'maybe')
          ON CONFLICT(event_id,member_name) DO NOTHING
        `,[req.params.id,name]);
      }

      const updated = await client.query(`
        UPDATE events
        SET completed=TRUE, completed_at=NOW()
        WHERE id=$1
        RETURNING *
      `,[req.params.id]);

      await client.query('COMMIT');
      res.json(updated.rows[0]);

    } catch (e) {
      await client.query('ROLLBACK').catch(()=>{});
      console.error('Błąd kończenia zbiórki:',e);
      res.status(500).json({error:'Nie udało się zakończyć zbiórki.'});
    } finally {
      client.release();
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

          percentage: confirmed
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


// ======================================================
// FREKWENCJA ROCZNA — WSZYSCY CZŁONKOWIE
// ======================================================

app.get(
  '/api/annual-attendance',
  auth,
  staff,
  async (req, res) => {
    try {
      const year = Number(
        req.query.year || new Date().getFullYear()
      );

      if (
        !Number.isInteger(year) ||
        year < 2000 ||
        year > 2100
      ) {
        return res.status(400).json({
          error: 'Nieprawidłowy rok.'
        });
      }

      const r = await pool.query(
        `
        SELECT
          m.id,
          m.first_name,
          m.last_name,
          m.role,
          m.photo,

          COALESCE(
            SUM(
              CASE
                WHEN LEFT(COALESCE(e.event_date,''),4)=$1::text
                 AND a.status='yes'
                THEN 1
                ELSE 0
              END
            ),
            0
          )::int AS yes,

          COALESCE(
            SUM(
              CASE
                WHEN LEFT(COALESCE(e.event_date,''),4)=$1::text
                 AND a.status='no'
                THEN 1
                ELSE 0
              END
            ),
            0
          )::int AS no,

          COALESCE(
            SUM(
              CASE
                WHEN LEFT(COALESCE(e.event_date,''),4)=$1::text
                 AND a.status='maybe'
                THEN 1
                ELSE 0
              END
            ),
            0
          )::int AS maybe

        FROM members m

        LEFT JOIN attendance a
          ON a.member_name =
             TRIM(
               CONCAT(
                 COALESCE(m.first_name,''),
                 ' ',
                 COALESCE(m.last_name,'')
               )
             )

        LEFT JOIN events e
          ON e.id=a.event_id

        GROUP BY
          m.id,
          m.first_name,
          m.last_name,
          m.role,
          m.photo

        ORDER BY
          m.first_name,
          m.last_name,
          m.id
        `,
        [String(year)]
      );

      const members = r.rows.map(x => {
        const yes = Number(x.yes || 0);
        const no = Number(x.no || 0);
        const maybe = Number(x.maybe || 0);

        const confirmed = yes + no;
        const total = confirmed + maybe;

        return {
          id: Number(x.id),
          first_name: x.first_name || '',
          last_name: x.last_name || '',
          role: x.role || 'member',
          photo: x.photo || '',

          yes,
          no,
          maybe,

          attended: yes,
          absent: no,

          confirmed,
          total,

          percentage: confirmed
            ? Math.round(yes / confirmed * 100)
            : 0
        };
      });

      res.json({
        year,
        members
      });

    } catch (e) {
      console.error(
        'Błąd frekwencji rocznej:',
        e
      );

      res.status(500).json({
        error:
          'Nie udało się pobrać frekwencji rocznej.'
      });
    }
  }
);


// ======================================================
// GAZETY
// ======================================================

app.get(
  '/api/newspaper-groups',
  auth,
  async (req, res) => {
    try {
      res.json(await getGroups());

    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Nie udało się pobrać grup gazet.'
      });
    }
  }
);


// ======================================================
// DODAWANIE GRUPY
// ======================================================

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

      const ids = normalizeIds(
        b.memberIds
      );

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
          `${x.first_name || ''} ${x.last_name || ''}`
            .trim()
        )
        .filter(Boolean);

      const copies = Math.max(
        0,
        Number(b.copies || 0)
      );

      const streets = safeArray(
        b.streets
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
          delivered,
          started,
          done,
          member_ids,
          member_names
        )
        VALUES(
          $1,
          $2,
          $3,
          $4::jsonb,
          $5,
          0,
          FALSE,
          FALSE,
          $6::jsonb,
          $7::jsonb
        )
        RETURNING *
        `,
        [
          name,
          region,
          b.color || '#2878ff',
          JSON.stringify(streets),
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


// ======================================================
// EDYCJA GRUPY
// ======================================================

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
        normalizeIds(old.member_ids);

      const oldNames =
        normalizeNames(old.member_names);

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

        const copies =
          Math.max(
            0,
            Number(old.copies || 0)
          );

        const delivered =
          Math.min(
            copies,
            Math.max(
              0,
              Number(
                req.body.delivered ??
                old.delivered ??
                0
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

        const r = await pool.query(
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

        const groups =
          await getGroups();

        return res.json(
          groups.find(
            x =>
              x.id ===
              Number(req.params.id)
          ) ||
          groupJson(r.rows[0])
        );
      }

      if (!isStaff(req)) {
        return res.status(403).json({
          error:
            'Brak uprawnień.'
        });
      }

      const ids =
        req.body.memberIds !== undefined
          ? normalizeIds(req.body.memberIds)
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
        req.body.memberIds !== undefined
          ? m.rows
              .map(x =>
                `${x.first_name || ''} ${x.last_name || ''}`
                  .trim()
              )
              .filter(Boolean)
          : oldNames;

      const copies =
        req.body.copies !== undefined
          ? Math.max(
              0,
              Number(req.body.copies)
            )
          : Number(old.copies || 0);

      const delivered =
        Math.min(
          copies,
          Math.max(
            0,
            Number(
              req.body.delivered ??
              old.delivered ??
              0
            )
          )
        );

      const streets =
        req.body.streets !== undefined
          ? safeArray(req.body.streets)
          : safeArray(old.streets);

      const name =
        req.body.name !== undefined
          ? String(req.body.name).trim()
          : old.name;

      const region =
        req.body.region !== undefined
          ? String(req.body.region).trim()
          : old.region;

      const color =
        req.body.color !== undefined
          ? String(req.body.color)
          : old.color;

      const started =
        req.body.started !== undefined
          ? !!req.body.started
          : !!old.started;

      const done =
        req.body.done !== undefined
          ? !!req.body.done
          : !!old.done;

      const r = await pool.query(
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
          name,
          region,
          color,
          JSON.stringify(streets),
          copies,
          delivered,
          started,
          done,
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


// ======================================================
// POSTĘP GAZET
// ======================================================

app.post(
  '/api/newspaper-groups/:id/start',
  auth,
  async (req, res) => {
    req.body = req.body || {};
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
    req.body = req.body || {};
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
      normalizeIds(g.member_ids);

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

    const copies =
      Math.max(
        0,
        Number(g.copies || 0)
      );

    const delivered =
      Math.min(
        copies,
        Math.max(
          0,
          Number(
            req.body.delivered ??
            g.delivered ??
            0
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

    const u = await pool.query(
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

    const groups =
      await getGroups();

    res.json(
      groups.find(
        x =>
          x.id === Number(id)
      ) ||
      groupJson(u.rows[0])
    );

  } catch (e) {
    console.error(e);

    res.status(500).json({
      error:
        'Nie udało się zapisać postępu.'
    });
  }
}


// ======================================================
// USUWANIE GRUPY
// ======================================================

app.delete(
  '/api/newspaper-groups/:id',
  auth,
  staff,
  async (req, res) => {
    try {
      const r = await pool.query(
        `
        DELETE FROM newspaper_groups
        WHERE id=$1
        RETURNING id
        `,
        [req.params.id]
      );

      if (!r.rows[0]) {
        return res.status(404).json({
          error:
            'Nie znaleziono grupy.'
        });
      }

      res.json({
        ok: true,
        deleted: true
      });

    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Nie udało się usunąć grupy gazet.'
      });
    }
  }
);


// ======================================================
// RESET PLANU GAZET
// ======================================================

app.post(
  '/api/newspaper-groups/reset',
  auth,
  staff,
  async (req, res) => {
    const client = await pool.connect();

    try {
      await client.query('BEGIN');

      await client.query(`
        UPDATE newspaper_groups
        SET
          delivered = 0,
          started = FALSE,
          done = FALSE
      `);

      const result = await client.query(`
        SELECT *
        FROM newspaper_groups
        ORDER BY id
      `);

      await client.query('COMMIT');

      res.json({
        ok: true,
        reset: true,
        groups: result.rows.map(groupSnapshot)
      });

    } catch (e) {
      await client
        .query('ROLLBACK')
        .catch(() => {});

      console.error(
        'Błąd resetu gazet:',
        e
      );

      res.status(500).json({
        error:
          'Nie udało się zresetować miesiąca.'
      });

    } finally {
      client.release();
    }
  }
);


// ======================================================
// HISTORIA GAZET
// ======================================================

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
        ORDER BY month_key DESC,id DESC
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


// ======================================================
// PODSUMOWANIE MIESIĄCA
// ======================================================

app.get(
  '/api/newspaper-month-summary',
  auth,
  staff,
  async (req, res) => {
    try {
      const groups = await getGroups();

      const totalCopies = groups.reduce(
        (sum, g) =>
          sum + Number(g.copies || 0),
        0
      );

      const totalDelivered = groups.reduce(
        (sum, g) =>
          sum + Number(g.delivered || 0),
        0
      );

      const completedGroups =
        groups.filter(
          g => g.done
        ).length;

      const startedGroups =
        groups.filter(
          g => g.started
        ).length;

      const remaining =
        Math.max(
          0,
          totalCopies -
            totalDelivered
        );

      const percentage =
        totalCopies
          ? Math.round(
              totalDelivered /
                totalCopies *
                100
            )
          : 0;

      const info = monthInfo();

      res.json({
        month: info.monthLabel,
        monthKey: info.monthKey,

        totalGroups:
          groups.length,

        startedGroups,

        completedGroups,

        totalCopies,

        totalDelivered,

        remaining,

        percentage,

        groups
      });

    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Nie udało się pobrać podsumowania miesiąca.'
      });
    }
  }
);


// ======================================================
// FUNKCJA ZAPISUJĄCA AKTUALNY MIESIĄC
// ======================================================

async function archiveCurrentMonth(client) {
  const groupsResult =
    await client.query(`
      SELECT *
      FROM newspaper_groups
      ORDER BY id
      FOR UPDATE
    `);

  if (!groupsResult.rows.length) {
    throw new Error(
      'Brak grup gazet do zapisania.'
    );
  }

  const info = monthInfo();

  const snapshot =
    groupsResult.rows.map(
      groupSnapshot
    );

  const existing =
    await client.query(
      `
      SELECT id
      FROM newspaper_history
      WHERE month_key=$1
      LIMIT 1
      `,
      [info.monthKey]
    );

  let historyId;

  if (existing.rows.length) {
    historyId =
      existing.rows[0].id;

    await client.query(
      `
      UPDATE newspaper_history
      SET
        month_label=$1,
        groups=$2::jsonb,
        saved_at=NOW()
      WHERE id=$3
      `,
      [
        info.monthLabel,
        JSON.stringify(snapshot),
        historyId
      ]
    );

  } else {
    const saved =
      await client.query(
        `
        INSERT INTO newspaper_history
        (
          month_key,
          month_label,
          groups
        )
        VALUES($1,$2,$3::jsonb)
        RETURNING id
        `,
        [
          info.monthKey,
          info.monthLabel,
          JSON.stringify(snapshot)
        ]
      );

    historyId =
      saved.rows[0].id;
  }

  return {
    historyId,
    monthKey: info.monthKey,
    monthLabel: info.monthLabel,
    groups: snapshot
  };
}


// ======================================================
// ZAPIS MIESIĄCA
// ======================================================

app.post(
  '/api/newspaper-groups/save-month',
  auth,
  staff,
  async (req, res) => {
    const client =
      await pool.connect();

    try {
      await client.query('BEGIN');

      const archived =
        await archiveCurrentMonth(
          client
        );

      await client.query(
        'COMMIT'
      );

      res.json({
        ok: true,
        saved: true,
        historyId:
          archived.historyId,
        monthKey:
          archived.monthKey,
        monthLabel:
          archived.monthLabel,
        groups:
          archived.groups
      });

    } catch (e) {
      await client
        .query('ROLLBACK')
        .catch(() => {});

      console.error(e);

      res.status(500).json({
        error:
          e.message ===
          'Brak grup gazet do zapisania.'
            ? e.message
            : 'Nie udało się zapisać miesiąca.'
      });

    } finally {
      client.release();
    }
  }
);


// ======================================================
// ZAPISZ + ZRESETUJ MIESIĄC
// ======================================================

app.post(
  '/api/newspaper-groups/save-and-reset-month',
  auth,
  staff,
  async (req, res) => {
    const client =
      await pool.connect();

    try {
      await client.query(
        'BEGIN'
      );

      const archived =
        await archiveCurrentMonth(
          client
        );

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
        saved: true,
        reset: true,

        archivedMonth:
          archived.monthLabel,

        monthKey:
          archived.monthKey,

        historyId:
          archived.historyId,

        previousGroups:
          archived.groups,

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
          e.message ===
          'Brak grup gazet do zapisania.'
            ? e.message
            : 'Nie udało się zapisać i zresetować miesiąca.'
      });

    } finally {
      client.release();
    }
  }
);


// ======================================================
// KOMPATYBILNOŚĆ — NOWY MIESIĄC
// ======================================================

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

      const archived =
        await archiveCurrentMonth(
          client
        );

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

        saved: true,
        reset: true,

        archivedMonth:
          archived.monthLabel,

        monthKey:
          archived.monthKey,

        historyId:
          archived.historyId,

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


// ======================================================
// AKTUALNY MIESIĄC
// ======================================================

app.get(
  '/api/newspaper-current-month',
  auth,
  async (req, res) => {
    try {
      const info = monthInfo();

      res.json({
        monthKey:
          info.monthKey,

        monthLabel:
          info.monthLabel
      });

    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Nie udało się pobrać informacji o miesiącu.'
      });
    }
  }
);


// ======================================================
// PUSH
// ======================================================

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

      const memberId =
        req.role === 'member'
          ? Number(req.member.id)
          : (
              s.memberId !== undefined
                ? Number(s.memberId)
                : null
            );

      await pool.query(
        `
        INSERT INTO push_subscriptions
        (endpoint,subscription,member_id)
        VALUES($1,$2::jsonb,$3)
        ON CONFLICT(endpoint)
        DO UPDATE SET
          subscription=EXCLUDED.subscription,
          member_id=COALESCE(
            EXCLUDED.member_id,
            push_subscriptions.member_id
          )
        `,
        [
          s.endpoint,
          JSON.stringify(s),
          Number.isInteger(memberId) &&
          memberId > 0
            ? memberId
            : null
        ]
      );

      res.json({
        ok: true,
        memberId:
          Number.isInteger(memberId) &&
          memberId > 0
            ? memberId
            : null
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


// ======================================================
// CRON — AUTOMATYCZNE PRZYPOMNIENIA O ZBIÓRKACH
// ======================================================

app.post(
  '/api/cron/attendance-reminders',
  async (req, res) => {
    try {
      const secret = String(
        process.env.CRON_SECRET || ''
      );

      const provided = String(
        req.headers['x-cron-secret'] ||
        req.body?.secret ||
        req.query?.secret ||
        ''
      );

      if (!secret || provided !== secret) {
        return res.status(401).json({
          error: 'Brak prawidłowego klucza CRON.'
        });
      }

      await processEventAttendanceReminders();

      res.json({
        ok: true,
        ranAt: new Date().toISOString()
      });

    } catch (e) {
      console.error(
        'Błąd CRON przypomnień:',
        e
      );

      res.status(500).json({
        error:
          'Nie udało się uruchomić przypomnień.'
      });
    }
  }
);


// ======================================================
// HEALTH
// ======================================================

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


// ======================================================
// API 404
// ======================================================

app.use(
  '/api',
  (req, res) =>
    res.status(404).json({
      error:
        'Nie znaleziono endpointu.'
    })
);


// ======================================================
// SPA
// ======================================================

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


// ======================================================
// START
// ======================================================

initDb()
  .then(() => {
    app.listen(
      PORT,
      () =>
        console.log(
          `MDP Wiesiółka działa na porcie ${PORT}`
        )
    );

    // Sprawdzamy przypomnienia co minutę.
    // Samo przypomnienie może zostać wysłane
    // maksymalnie raz na 30 minut na osobę i zbiórkę.
    setInterval(
      processEventAttendanceReminders,
      60 * 1000
    );

    // Pierwsze sprawdzenie chwilę po uruchomieniu.
    setTimeout(
      processEventAttendanceReminders,
      10 * 1000
    );
  })
  .catch(err => {
    console.error(
      'Błąd inicjalizacji bazy:',
      err
    );

    process.exit(1);
  });
