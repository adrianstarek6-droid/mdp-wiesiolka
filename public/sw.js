const CACHE_NAME = "mdp-wiesiolka-v2";

const FILES_TO_CACHE = [
  "/",
  "/index.html",
  "/manifest.json"
];

self.addEventListener("install", event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(FILES_TO_CACHE))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys
          .filter(key => key !== CACHE_NAME)
          .map(key => caches.delete(key))
      )
    ).then(() => self.clients.claim())
  );
});

/* =========================
   PUSH POWIADOMIENIA
========================= */

self.addEventListener("push", event => {
  let data = {
    title: "MDP Wiesiółka 🚒",
    body: "Masz nowe powiadomienie.",
    icon: "/icon-192-2.png",
    badge: "/icon-192-2.png"
  };

  try {
    if (event.data) {
      data = {
        ...data,
        ...event.data.json()
      };
    }
  } catch (error) {
    console.log("Błąd odczytu powiadomienia:", error);
  }

  event.waitUntil(
    self.registration.showNotification(
      data.title,
      {
        body: data.body,
        icon: data.icon,
        badge: data.badge,
        vibrate: [200, 100, 200],
        data: {
          url: "/"
        }
      }
    )
  );
});

self.addEventListener("notificationclick", event => {
  event.notification.close();

  event.waitUntil(
    clients.matchAll({
      type: "window",
      includeUncontrolled: true
    }).then(clientList => {
      for (const client of clientList) {
        if ("focus" in client) {
          return client.focus();
        }
      }

      if (clients.openWindow) {
        return clients.openWindow("/");
      }
    })
  );
});

/* =========================
   CACHE
========================= */

self.addEventListener("fetch", event => {
  if (event.request.method !== "GET") {
    return;
  }

  event.respondWith(
    fetch(event.request)
      .catch(() => caches.match(event.request))
  );
});
