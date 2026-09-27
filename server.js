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

// =====================================================
// KODY LOGOWANIA
// =====================================================

const GUARDIAN_CODE = process.env.GUARDIAN_CODE || '9982018';
const ADMIN_CODE = process.env.ADMIN_CODE || '0000';

// =====================================================
// PUSH
// =====================================================

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

// =====================================================
// EXPRESS
// =====================================================

app.use(express.json({ limit: '3mb' }));

app.use(
  express.urlencoded({
    extended: true,
    limit: '3mb'
  })
);

app.use(
  express.static(
    path.join(__dirname, 'public')
  )
);

// =====================================================
// POMOCNICZE
// =====================================================

function hashCode(code) {
  return crypto
    .createHash('sha256')
    .update(String(code || ''))
    .digest('hex');
}

function normRole(role) {
  const r = String(role || '')
    .toLowerCase()
    .trim();

  if (
    r === 'opiekun' ||
    r === 'guardian'
  ) {
    return 'guardian';
  }

  if (
    r === 'admin' ||
    r === 'administrator'
  ) {
    return 'admin';
  }

  if (
    r === 'member' ||
    r === 'czlonek' ||
    r === 'członek'
  ) {
    return 'member';
  }

  return r;
}

function isStaff(req) {
  return (
    req.role === 'admin' ||
    req.role === 'guardian'
  );
}

// =====================================================
// AUTORYZACJA
// =====================================================

async function auth(req, res, next) {
  const role = normRole(
    req.headers['x-role']
  );

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
    // ADMIN
    if (
      role === 'admin' &&
      code === ADMIN_CODE
    ) {
      req.authenticated = true;
      return next();
    }

    // OPIEKUN
    if (
      role === 'guardian' &&
      code === GUARDIAN_CODE
    ) {
      req.authenticated = true;
      return next();
    }

    // CZŁONEK
    if (
      role === 'member' &&
      memberId &&
      code
    ) {
      const result = await pool.query(
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

      const member = result.rows[0];

      if (
        !member ||
        member.code_hash !== hashCode(code)
      ) {
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

  } catch (error) {
    console.error(error);

    return res.status(500).json({
      error: 'Błąd autoryzacji.'
    });
  }
}

function staff(req, res, next) {
  if (isStaff(req)) {
    return next();
  }

  return res.status(403).json({
    error: 'Brak uprawnień.'
  });
}

// =====================================================
// BAZA DANYCH
// =====================================================

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

    CREATE TABLE IF NOT EXISTS newspaper_groups (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      region TEXT NOT NULL,

      color TEXT NOT NULL
        DEFAULT '#2878ff',

      streets JSONB NOT NULL
        DEFAULT '[]'::jsonb,

      copies INTEGER NOT NULL
        DEFAULT 0,

      delivered INTEGER NOT NULL
        DEFAULT 0,

      started BOOLEAN NOT NULL
        DEFAULT FALSE,

      done BOOLEAN NOT NULL
        DEFAULT FALSE,

      member_ids JSONB NOT NULL
        DEFAULT '[]'::jsonb,

      member_names JSONB NOT NULL
        DEFAULT '[]'::jsonb,

      created_at TIMESTAMPTZ
        DEFAULT NOW()
    );
  `);

  // Dodatkowe kolumny dla starszej bazy

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

  // Jeżeli nie ma jeszcze grup gazet,
  // tworzymy domyślny plan.

  const result = await pool.query(
    `
    SELECT COUNT(*)::int AS count
    FROM newspaper_groups
    `
  );

  if (
    result.rows[0].count === 0
  ) {
    await seedNewspaperGroups();
  }
}

// =====================================================
// DOMYŚLNE GRUPY GAZET
// =====================================================

async function seedNewspaperGroups() {

  const groups = [

    [
      'Wiesiółka',
      'Wiesiółka',
      '#2878ff',
      [],
      75
    ],

    [
      'Wysoka',
      'Wysoka',
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
      'Wysoka',
      '#ff9d2e',
      [
        'Kościuszki — do Dzwonka'
      ],
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
        group[0],
        group[1],
        group[2],
        JSON.stringify(group[3]),
        group[4]
      ]
    );

  }
}

// =====================================================
// GRUPY GAZET - FORMAT
// =====================================================

function groupJson(
  row,
  members = []
) {

  return {

    id: row.id,

    name: row.name,

    region: row.region,

    color: row.color,

    streets:
      Array.isArray(row.streets)
        ? row.streets
        : [],

    copies:
      Number(row.copies || 0),

    delivered:
      Number(row.delivered || 0),

    started:
      Boolean(row.started),

    done:
      Boolean(row.done),

    memberIds:
      Array.isArray(row.member_ids)
        ? row.member_ids.map(Number)
        : [],

    memberNames:
      Array.isArray(row.member_names)
        ? row.member_names
        : [],

    members

  };
}

// =====================================================
// POBIERANIE GRUP GAZET
// =====================================================

async function getGroups() {

  const groupsResult =
    await pool.query(
      `
      SELECT *
      FROM newspaper_groups
      ORDER BY id
      `
    );

  const membersResult =
    await pool.query(
      `
      SELECT
        id,
        first_name,
        last_name,
        name
      FROM members
      ORDER BY
        first_name,
        last_name,
        id
      `
    );

  const members =
    membersResult.rows;

  return groupsResult.rows.map(
    row => {

      let ids =
        Array.isArray(row.member_ids)
          ? row.member_ids.map(Number)
          : [];

      const names =
        Array.isArray(row.member_names)
          ? row.member_names.map(String)
          : [];

      // Obsługa starszych grup,
      // które miały zapisane tylko nazwiska.

      if (
        ids.length === 0 &&
        names.length > 0
      ) {

        ids = members
          .filter(member => {

            const fullName =
              `${member.first_name || ''} ${member.last_name || ''}`
                .trim();

            return (
              names.includes(fullName) ||
              names.includes(
                member.name || ''
              )
            );

          })
          .map(member => member.id);
      }

      const groupMembers =
        members.filter(member =>
          ids.includes(
            Number(member.id)
          )
        );

      return groupJson(
        {
          ...row,
          member_ids: ids,
          member_names: names
        },
        groupMembers
      );

    }
  );
}

// =====================================================
// POWIADOMIENIA PUSH
// =====================================================

async function sendPushToAll(payload) {

  if (
    !VAPID_PUBLIC_KEY ||
    !VAPID_PRIVATE_KEY
  ) {
    return;
  }

  const result =
    await pool.query(
      `
      SELECT
        id,
        endpoint,
        subscription
      FROM push_subscriptions
      `
    );

  for (
    const subscription
    of result.rows
  ) {

    try {

      await webpush.sendNotification(
        subscription.subscription,
        JSON.stringify(payload)
      );

    } catch (error) {

      if (
        error.statusCode === 404 ||
        error.statusCode === 410
      ) {

        await pool.query(
          `
          DELETE FROM push_subscriptions
          WHERE id=$1
          `,
          [subscription.id]
        );

      }

    }

  }
}

// =====================================================
// LOGOWANIE
// =====================================================

app.post(
  '/api/login',
  async (req, res) => {

    try {

      const role =
        normRole(req.body.role);

      const code =
        String(
          req.body.code ||
          req.body.password ||
          ''
        );

      // ADMIN

      if (
        role === 'admin' &&
        code === ADMIN_CODE
      ) {

        return res.json({
          role: 'admin'
        });

      }

      // OPIEKUN

      if (
        role === 'guardian' &&
        code === GUARDIAN_CODE
      ) {

        return res.json({
          role: 'guardian'
        });

      }

      // CZŁONEK

      if (role === 'member') {

        const result =
          await pool.query(
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

        const member =
          result.rows[0];

        if (!member) {

          return res.status(401).json({
            error:
              'Nieprawidłowy kod członka.'
          });

        }

        return res.json({

          role: 'member',

          memberId: member.id,

          firstName:
            member.first_name || '',

          lastName:
            member.last_name || '',

          member: {
            id: member.id,
            first_name:
              member.first_name || '',
            last_name:
              member.last_name || '',
            role:
              member.role || 'member',
            photo:
              member.photo || ''
          }

        });

      }

      return res.status(401).json({
        error:
          'Nieprawidłowe dane logowania.'
      });

    } catch (error) {

      console.error(error);

      return res.status(500).json({
        error: 'Błąd logowania.'
      });

    }

  }
);

// =====================================================
// GŁÓWNE DANE
// =====================================================

app.get(
  '/api/data',
  auth,
  async (req, res) => {

    try {

      const [
        events,
        news,
        members
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
          ORDER BY
            created_at DESC,
            id DESC
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
          ORDER BY
            first_name,
            last_name,
            id
          `
        )

      ]);

      res.json({
        events: events.rows,
        news: news.rows,
        members: members.rows
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          'Nie udało się pobrać danych.'
      });

    }

  }
);

// =====================================================
// STATYSTYKI
// =====================================================

app.get(
  '/api/stats',
  auth,
  async (req, res) => {

    try {

      const [
        members,
        events,
        news
      ] = await Promise.all([

        pool.query(
          'SELECT COUNT(*)::int AS c FROM members'
        ),

        pool.query(
          'SELECT COUNT(*)::int AS c FROM events'
        ),

        pool.query(
          'SELECT COUNT(*)::int AS c FROM news'
        )

      ]);

      res.json({

        members:
          members.rows[0].c,

        events:
          events.rows[0].c,

        news:
          news.rows[0].c

      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error: 'Błąd statystyk.'
      });

    }

  }
);

// =====================================================
// ZBIÓRKI
// =====================================================

app.post(
  '/api/events',
  auth,
  staff,
  async (req, res) => {

    try {

      const body =
        req.body;

      const title =
        String(
          body.title ||
          body.name ||
          ''
        ).trim();

      if (!title) {

        return res.status(400).json({
          error:
            'Podaj nazwę zbiórki.'
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

            body.event_date ||
              body.date ||
              null,

            body.event_time ||
              body.time ||
              null,

            body.place ||
              body.location ||
              body.address ||
              '',

            body.description ||
              body.desc ||
              body.text ||
              ''
          ]
        );

      try {

        await sendPushToAll({
          title:
            'Nowa zbiórka MDP',
          body: title
        });

      } catch (error) {
        console.error(error);
      }

      res.json(
        result.rows[0]
      );

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          'Nie udało się dodać zbiórki.'
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

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          'Nie udało się usunąć zbiórki.'
      });

    }

  }
);

// =====================================================
// OGŁOSZENIA
// =====================================================

app.post(
  '/api/news',
  auth,
  staff,
  async (req, res) => {

    try {

      const body =
        req.body;

      const title =
        String(
          body.title ||
          body.name ||
          ''
        ).trim();

      if (!title) {

        return res.status(400).json({
          error:
            'Podaj tytuł ogłoszenia.'
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
            body.body ||
              body.content ||
              body.description ||
              body.text ||
              ''
          ]
        );

      try {

        await sendPushToAll({
          title:
            'Nowe ogłoszenie MDP',
          body: title
        });

      } catch (error) {
        console.error(error);
      }

      res.json(
        result.rows[0]
      );

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          'Nie udało się dodać ogłoszenia.'
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

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          'Nie udało się usunąć ogłoszenia.'
      });

    }

  }
);

// =====================================================
// CZŁONKOWIE
// =====================================================

app.post(
  '/api/members',
  auth,
  staff,
  async (req, res) => {

    try {

      const first =
        String(
          req.body.first_name ||
          req.body.firstName ||
          ''
        ).trim();

      const last =
        String(
          req.body.last_name ||
          req.body.lastName ||
          ''
        ).trim();

      const code =
        String(
          req.body.code ||
          ''
        ).trim();

      if (
        !first ||
        !last ||
        !code
      ) {

        return res.status(400).json({
          error:
            'Podaj imię, nazwisko i kod.'
        });

      }

      const result =
        await pool.query(
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
          (
            $1,
            $2,
            $3,
            $4,
            $5
          )
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
            req.body.role ||
              'member',
            hashCode(code)
          ]
        );

      res.json(
        result.rows[0]
      );

    } catch (error) {

      console.error(error);

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

      const body =
        req.body;

      const first =
        body.first_name ||
        body.firstName ||
        null;

      const last =
        body.last_name ||
        body.lastName ||
        null;

      const name =
        body.name ||
        (
          first && last
            ? `${first} ${last}`
            : null
        );

      const role =
        body.role ||
        null;

      const codeHash =
        body.code
          ? hashCode(body.code)
          : null;

      const photo =
        body.photo !== undefined
          ? body.photo
          : null;

      const result =
        await pool.query(
          `
          UPDATE members
          SET
            first_name =
              COALESCE($1, first_name),

            last_name =
              COALESCE($2, last_name),

            name =
              COALESCE($3, name),

            role =
              COALESCE($4, role),

            code_hash =
              COALESCE($5, code_hash),

            photo =
              COALESCE($6, photo)

          WHERE id=$7

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
            name,
            role,
            codeHash,
            photo,
            req.params.id
          ]
        );

      if (!result.rows[0]) {

        return res.status(404).json({
          error:
            'Nie znaleziono członka.'
        });

      }

      res.json(
        result.rows[0]
      );

    } catch (error) {

      console.error(error);

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

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          'Nie udało się usunąć członka.'
      });

    }

  }
);

// =====================================================
// PROFIL
// =====================================================

app.get(
  '/api/profile',
  auth,
  async (req, res) => {

    try {

      if (
        req.role !== 'member'
      ) {

        return res.json({
          role: req.role
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
            photo
          FROM members
          WHERE id=$1
          `,
          [req.member.id]
        );

      res.json(
        result.rows[0] || {}
      );

    } catch (error) {

      console.error(error);

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

      if (
        req.role !== 'member'
      ) {

        return res.status(403).json({
          error:
            'Brak uprawnień.'
        });

      }

      const result =
        await pool.query(
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
        result.rows[0] || {}
      );

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          'Nie udało się zapisać profilu.'
      });

    }

  }
);

// =====================================================
// FREKWENCJA
// =====================================================

async function saveAttendance(
  req,
  res,
  eventIdFromPath = null
) {

  try {

    const eventId =
      Number(
        eventIdFromPath ||
        req.body.event_id ||
        req.body.eventId
      );

    const status =
      String(
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

    const event =
      await pool.query(
        `
        SELECT id
        FROM events
        WHERE id=$1
        `,
        [eventId]
      );

    if (!event.rows[0]) {

      return res.status(404).json({
        error:
          'Nie znaleziono zbiórki.'
      });

    }

    let memberName = '';

    // Członek odpowiada za siebie.

    if (
      req.role === 'member'
    ) {

      memberName =
        `${req.member.first_name || ''} ${req.member.last_name || ''}`
          .trim();

    }

    // Opiekun/admin może wybrać członka.

    else if (
      req.body.member_id
    ) {

      const member =
        await pool.query(
          `
          SELECT
            first_name,
            last_name
          FROM members
          WHERE id=$1
          `,
          [req.body.member_id]
        );

      if (member.rows[0]) {

        memberName =
          `${member.rows[0].first_name || ''} ${member.rows[0].last_name || ''}`
            .trim();

      }

    }

    else {

      memberName =
        String(
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
      (
        $1,
        $2,
        $3
      )

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

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error:
        'Nie udało się zapisać obecności.'
    });

  }

}

app.post(
  '/api/attendance',
  auth,
  saveAttendance
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

      const result =
        await pool.query(
          `
          SELECT *
          FROM attendance
          WHERE event_id=$1
          ORDER BY member_name
          `,
          [req.params.eventId]
        );

      res.json(
        result.rows
      );

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          'Nie udało się pobrać obecności.'
      });

    }

  }
);

// =====================================================
// STATYSTYKI CZŁONKA
// =====================================================

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

      const memberResult =
        await pool.query(
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

      const member =
        memberResult.rows[0];

      if (!member) {

        return res.status(404).json({
          error:
            'Nie znaleziono członka.'
        });

      }

      const name =
        `${member.first_name || ''} ${member.last_name || ''}`
          .trim();

      const attendance =
        await pool.query(
          `
          SELECT
            status,
            COUNT(*)::int AS count
          FROM attendance
          WHERE member_name=$1
          GROUP BY status
          `,
          [name]
        );

      const stats = {
        yes: 0,
        maybe: 0,
        no: 0
      };

      attendance.rows.forEach(
        row => {
          stats[row.status] =
            row.count;
        }
      );

      const confirmed =
        stats.yes + stats.no;

      const total =
        confirmed + stats.maybe;

      const percentage =
        confirmed > 0
          ? Math.round(
              stats.yes /
              confirmed *
              100
            )
          : 0;

      res.json({

        member,

        stats: {

          yes: stats.yes,

          no: stats.no,

          maybe: stats.maybe,

          attended: stats.yes,

          absent: stats.no,

          confirmed,

          total,

          percentage

        }

      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          'Nie udało się pobrać frekwencji.'
      });

    }

  }
);

// =====================================================
// GAZETY / ECHO ŁAZ
// =====================================================

// Pobieranie grup

app.get(
  '/api/newspaper-groups',
  auth,
  async (req, res) => {

    try {

      res.json(
        await getGroups()
      );

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          'Nie udało się pobrać grup gazet.'
      });

    }

  }
);

// Dodawanie grupy

app.post(
  '/api/newspaper-groups',
  auth,
  staff,
  async (req, res) => {

    try {

      const body =
        req.body;

      const name =
        String(
          body.name || ''
        ).trim();

      const region =
        String(
          body.region || ''
        ).trim();

      if (
        !name ||
        !region
      ) {

        return res.status(400).json({
          error:
            'Podaj nazwę grupy i region.'
        });

      }

      const ids =
        Array.isArray(
          body.memberIds
        )
          ? body.memberIds
              .map(Number)
              .filter(Number.isFinite)
          : [];

      let members = [];

      if (ids.length > 0) {

        const result =
          await pool.query(
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
          );

        members =
          result.rows;

      }

      const names =
        members
          .map(member =>
            `${member.first_name || ''} ${member.last_name || ''}`
              .trim()
          )
          .filter(Boolean);

      const copies =
        Math.max(
          0,
          Number(body.copies || 0)
        );

      const streets =
        Array.isArray(body.streets)
          ? body.streets
          : [];

      const result =
        await pool.query(
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

            body.color ||
              '#2878ff',

            JSON.stringify(
              streets
            ),

            copies,

            JSON.stringify(
              ids
            ),

            JSON.stringify(
              names
            )
          ]
        );

      res.json(
        groupJson(
          result.rows[0],
          members
        )
      );

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          'Nie udało się zapisać grupy gazet.'
      });

    }

  }
);

// Edycja grupy

app.put(
  '/api/newspaper-groups/:id',
  auth,
  async (req, res) => {

    try {

      const groupResult =
        await pool.query(
          `
          SELECT *
          FROM newspaper_groups
          WHERE id=$1
          `,
          [req.params.id]
        );

      const old =
        groupResult.rows[0];

      if (!old) {

        return res.status(404).json({
          error:
            'Nie znaleziono grupy.'
        });

      }

      const oldIds =
        Array.isArray(
          old.member_ids
        )
          ? old.member_ids.map(Number)
          : [];

      const oldNames =
        Array.isArray(
          old.member_names
        )
          ? old.member_names.map(String)
          : [];

      // Członek może zmieniać
      // tylko swój postęp.

      if (
        req.role === 'member'
      ) {

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
            ? Boolean(old.started)
            : Boolean(req.body.started);

        const done =
          req.body.done === undefined
            ? Boolean(old.done)
            : Boolean(req.body.done);

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

        const groups =
          await getGroups();

        const updated =
          groups.find(
            group =>
              group.id ===
              Number(req.params.id)
          );

        return res.json(
          updated
        );

      }

      if (!isStaff(req)) {

        return res.status(403).json({
          error:
            'Brak uprawnień.'
        });

      }

      const ids =
        Array.isArray(
          req.body.memberIds
        )
          ? req.body.memberIds
              .map(Number)
              .filter(Number.isFinite)
          : oldIds;

      let members = [];

      if (ids.length > 0) {

        const result =
          await pool.query(
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
          );

        members =
          result.rows;

      }

      const names =
        Array.isArray(
          req.body.memberIds
        )
          ? members
              .map(member =>
                `${member.first_name || ''} ${member.last_name || ''}`
                  .trim()
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

      const streets =
        Array.isArray(
          req.body.streets
        )
          ? req.body.streets
          : (
              Array.isArray(old.streets)
                ? old.streets
                : []
            );

      const result =
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
              streets
            ),

            copies,

            delivered,

            Boolean(
              req.body.started ??
              old.started
            ),

            Boolean(
              req.body.done ??
              old.done
            ),

            JSON.stringify(
              ids
            ),

            JSON.stringify(
              names
            ),

            req.params.id

          ]
        );

      res.json(
        groupJson(
          result.rows[0],
          members
        )
      );

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          'Nie udało się zmienić grupy gazet.'
      });

    }

  }
);

// =====================================================
// POSTĘP GAZET
// =====================================================

async function updateGroupProgress(
  req,
  res,
  id
) {

  try {

    const result =
      await pool.query(
        `
        SELECT *
        FROM newspaper_groups
        WHERE id=$1
        `,
        [id]
      );

    const group =
      result.rows[0];

    if (!group) {

      return res.status(404).json({
        error:
          'Nie znaleziono grupy.'
      });

    }

    const ids =
      Array.isArray(
        group.member_ids
      )
        ? group.member_ids.map(Number)
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
        ? Boolean(group.started)
        : Boolean(req.body.started);

    const done =
      req.body.done === undefined
        ? Boolean(group.done)
        : Boolean(req.body.done);

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

    const groups =
      await getGroups();

    const updated =
      groups.find(
        item =>
          item.id === Number(id)
      );

    res.json(
      updated
    );

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error:
        'Nie udało się zapisać postępu.'
    });

  }

}

// START

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

// POSTĘP

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

// GOTOWE

app.post(
  '/api/newspaper-groups/:id/complete',
  auth,
  async (req, res) => {

    req.body.started = true;
    req.body.done = true;

    return updateGroupProgress(
      req,
      res,
      req.params.id
    );

  }
);

// =====================================================
// USUWANIE GRUPY
// =====================================================

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

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          'Nie udało się usunąć grupy gazet.'
      });

    }

  }
);

// =====================================================
// RESET GRUP GAZET
// =====================================================

app.post(
  '/api/newspaper-groups/reset',
  auth,
  staff,
  async (req, res) => {

    try {

      await pool.query(
        `
        DELETE FROM newspaper_groups
        `
      );

      await seedNewspaperGroups();

      res.json(
        await getGroups()
      );

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          'Nie udało się przywrócić planu gazet.'
      });

    }

  }
);

// =====================================================
// PUSH - SUBSKRYPCJA
// =====================================================

app.post(
  '/api/push/subscribe',
  auth,
  async (req, res) => {

    try {

      const subscription =
        req.body;

      if (
        !subscription ||
        !subscription.endpoint
      ) {

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
          subscription=
            EXCLUDED.subscription
        `,
        [
          subscription.endpoint,
          JSON.stringify(
            subscription
          )
        ]
      );

      res.json({
        ok: true
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          'Nie udało się zapisać powiadomień.'
      });

    }

  }
);

// =====================================================
// PUSH - KLUCZ PUBLICZNY
// =====================================================

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

// =====================================================
// PUSH - USUNIĘCIE
// =====================================================

app.post(
  '/api/push/unsubscribe',
  auth,
  async (req, res) => {

    try {

      if (
        req.body &&
        req.body.endpoint
      ) {

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

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          'Nie udało się usunąć subskrypcji.'
      });

    }

  }
);

// =====================================================
// PUSH - TEST
// =====================================================

app.post(
  '/api/push/test',
  auth,
  staff,
  async (req, res) => {

    try {

      await sendPushToAll({

        title:
          'MDP Wiesiółka',

        body:
          req.body.body ||
          'Testowe powiadomienie'

      });

      res.json({
        ok: true
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          'Nie udało się wysłać powiadomienia.'
      });

    }

  }
);

// =====================================================
// HEALTH CHECK
// =====================================================

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

    } catch (error) {

      console.error(error);

      res.status(500).json({
        ok: false
      });

    }

  }
);

// =====================================================
// NIEZNANE API
// =====================================================

app.use(
  '/api',
  (req, res) => {

    res.status(404).json({
      error:
        'Nie znaleziono endpointu.'
    });

  }
);

// =====================================================
// STRONA
// =====================================================

app.use(
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

// =====================================================
// START SERWERA
// =====================================================

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
  .catch(error => {

    console.error(
      'Błąd inicjalizacji bazy:',
      error
    );

    process.exit(1);

  });
