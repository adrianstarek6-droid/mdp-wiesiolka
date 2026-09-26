# MDP WIESIÓŁKA — gotowa wersja online

Aplikacja zawiera: synchronizowane zbiórki, odpowiedzi obecności, informacje, usuwanie treści przez administratora, kalendarz oraz Web Push.

## Jedyna rzecz, której nie da się wykonać z samego pliku
Publiczna aplikacja musi zostać uruchomiona na serwerze z HTTPS. Bez dostępu do konta hostingowego domeny nie mogę samodzielnie opublikować jej w internecie z tego czatu. Po wdrożeniu nie trzeba zmieniać kodu.

## Uruchomienie serwera
`npm install` → `npm start` (albo Docker).

Powiadomienia wymagają HTTPS oraz zgody użytkownika na powiadomienia. Klucze VAPID są już wpisane w konfiguracji.

Kody demonstracyjne: członek 1234, administrator 0000. Przed publicznym użyciem należy zastąpić je prawdziwym uwierzytelnianiem.


## Poprawka logowania
W wersji naprawionej zmieniono identyfikatory ekranów `login`/`app`, ponieważ przeglądarka tworzyła z nich zmienne globalne i kolidowały z funkcją `login()`.
