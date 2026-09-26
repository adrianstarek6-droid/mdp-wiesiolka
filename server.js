const express = require("express");
const fs = require("fs");
const path = require("path");
const webpush = require("web-push");

const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const DB = path.join(__dirname, "data.json");

let db = fs.existsSync(DB)
  ? JSON.parse(fs.readFileSync(DB))
  : {
      events: [],
      announcements: [],
      subscriptions: [],
      members: []
    };

/*
  Jeśli masz już stary data.json bez "members",
  dodajemy pustą tablicę automatycznie.
*/
if (!Array.isArray(db.members)) {
  db.members = [];
}

if (!Array.isArray(db.events)) {
  db.events = [];
}

if (!Array.isArray(db.announcements)) {
  db.announcements = [];
}

if (!Array.isArray(db.subscriptions)) {
  db.subscriptions = [];
}

const save = () => {
  fs.writeFileSync(DB, JSON.stringify(db, null, 2));
};


/* =========================
   POWIADOMIENIA PUSH
========================= */

const pub =
  process.env.VAPID_PUBLIC_KEY ||
  "BIWpm8hQkp5baHHWghKCnKWDrV66BXkYROf4tshTITqR-BOrfiByXvKgJXNeHsEwYdc6XgwVen2S4QsnsNDmwOk";

const priv =
  process.env.VAPID_PRIVATE_KEY ||
  "66hgvyhsi299p9yAkK0Q62Uojja6jdIb4BYoNEAyEy4";

if (pub && priv) {
  webpush.setVapidDetails(
    "mailto:admin@mdpwiesiolka.pl",
    pub,
    priv
  );
}

async function pushAll(payload) {
  if (!pub || !priv) return;

  for (const s of [...db.subscriptions]) {
    try {
      await webpush.sendNotification(
        s,
        JSON.stringify(payload)
      );
    } catch (e) {
      if ([404, 410].includes(e.statusCode)) {
        db.subscriptions =
          db.subscriptions.filter(
            x => x.endpoint !== s.endpoint
          );
      }
    }
  }

  save();
}


/* =========================
   GŁÓWNE DANE
========================= */

app.get("/api/data", (req, res) => {
  res.json({
    events: db.events,
    announcements: db.announcements,
    members: db.members
  });
});


/* =========================
   CZŁONKOWIE MDP
========================= */

/*
  Pobieranie wszystkich członków
*/
app.get("/api/members", (req, res) => {
  res.json(db.members);
});


/*
  Dodawanie nowego członka

  Wysyłane:
  {
    "name": "Jan Kowalski"
  }

  Jeśli osoba już istnieje,
  nie zostanie dodana drugi raz.
*/
app.post("/api/members", (req, res) => {
  const name = String(req.body.name || "").trim();

  if (!name) {
    return res.status(400).json({
      error: "Imię i nazwisko jest wymagane."
    });
  }

  /*
    Sprawdzamy bez względu na wielkość liter,
    np. Jan Kowalski = jan kowalski
  */
  const exists = db.members.some(
    m => m.toLowerCase() === name.toLowerCase()
  );

  if (exists) {
    return res.json({
      ok: true,
      added: false,
      message: "Członek już istnieje.",
      members: db.members
    });
  }

  db.members.push(name);

  /*
    Sortowanie alfabetyczne
  */
  db.members.sort((a, b) =>
    a.localeCompare(b, "pl")
  );

  save();

  res.json({
    ok: true,
    added: true,
    member: name,
    members: db.members
  });
});


/*
  Usuwanie członka

  Przykład:
  DELETE /api/members/Jan%20Kowalski
*/
app.delete("/api/members/:name", (req, res) => {
  const name = decodeURIComponent(req.params.name).trim();

  const before = db.members.length;

  db.members = db.members.filter(
    m => m.toLowerCase() !== name.toLowerCase()
  );

  if (db.members.length === before) {
    return res.status(404).json({
      error: "Nie znaleziono takiego członka."
    });
  }

  save();

  res.json({
    ok: true,
    members: db.members
  });
});


/* =========================
   ZBIÓRKI
========================= */

app.post("/api/events", (req, res) => {
  let e = {
    id: Date.now(),
    title: req.body.title,
    date: req.body.date,
    place:
      req.body.place ||
      "Remiza OSP Wiesiółka",
    desc: req.body.desc || "",
    responses: {}
  };

  db.events.push(e);

  save();

  pushAll({
    title: "📅 Nowa zbiórka — MDP WIESIÓŁKA",
    body:
      `${e.title} • ` +
      `${new Date(e.date).toLocaleString("pl-PL")}`
  });

  res.json(e);
});


/*
  Usuwanie zbiórki
*/
app.delete("/api/events/:id", (req, res) => {
  db.events = db.events.filter(
    e => e.id != req.params.id
  );

  save();

  res.json({
    ok: true
  });
});


/*
  Odpowiedź członka na zbiórkę

  status:
  yes = obecność
  no = nieobecność
  maybe = może
*/
app.post("/api/events/:id/response", (req, res) => {
  let e = db.events.find(
    e => e.id == req.params.id
  );

  if (!e) {
    return res.status(404).end();
  }

  e.responses = e.responses || {};

  const name = String(req.body.name || "").trim();
  const status = req.body.status;

  if (!name) {
    return res.status(400).json({
      error: "Brak imienia i nazwiska."
    });
  }

  if (!["yes", "no", "maybe"].includes(status)) {
    return res.status(400).json({
      error: "Nieprawidłowy status."
    });
  }

  e.responses[name] = status;

  save();

  res.json(e);
});


/* =========================
   OGŁOSZENIA
========================= */

app.post("/api/announcements", (req, res) => {
  let a = {
    id: Date.now(),
    title: req.body.title,
    text: req.body.text,
    createdAt: new Date().toISOString()
  };

  db.announcements.unshift(a);

  save();

  pushAll({
    title: "📢 MDP WIESIÓŁKA",
    body: a.title
  });

  res.json(a);
});


/*
  Usuwanie ogłoszenia
*/
app.delete("/api/announcements/:id", (req, res) => {
  db.announcements =
    db.announcements.filter(
      a => a.id != req.params.id
    );

  save();

  res.json({
    ok: true
  });
});


/* =========================
   POWIADOMIENIA PUSH
========================= */

app.post("/api/push/subscribe", (req, res) => {
  if (
    !db.subscriptions.some(
      s => s.endpoint === req.body.endpoint
    )
  ) {
    db.subscriptions.push(req.body);
  }

  save();

  res.json({
    ok: true
  });
});


app.get("/api/push/public-key", (req, res) => {
  res.json({
    key: pub || ""
  });
});


/* =========================
   AUTOMATYCZNE PRZYPOMNIENIA
========================= */

setInterval(async () => {
  const now = Date.now();

  for (const e of db.events) {
    const diff =
      new Date(e.date).getTime() - now;

    /*
      Przypomnienie, jeśli zbiórka
      jest za mniej niż godzinę.
    */
    if (
      diff > 0 &&
      diff < 61 * 60 * 1000 &&
      !e.reminderSent
    ) {
      e.reminderSent = true;

      await pushAll({
        title: "🔥 Zbiórka za mniej niż godzinę",
        body: e.title,
        url: "/"
      });

      save();
    }
  }
}, 60 * 1000);


/* =========================
   URUCHOMIENIE SERWERA
========================= */

app.listen(
  process.env.PORT || 3000,
  () =>
    console.log(
      "MDP WIESIÓŁKA działa na porcie " +
      (process.env.PORT || 3000)
    )
);
