# Render irratti website deploy gochuu

Project kun PHP, Apache fi MySQL fayyadama. Render irratti namoonni online akka fayyadaman gochuuf GitHub private repository, Render Web Service fi MySQL database alaa barbaachisu.

## 1. Faayiloota dhuunfaa hin olkaa'in

`.gitignore` fi `.dockerignore` keessatti faayiloota `uploads/` (fakkeenyaaf suuraa barattootaa) fi log files olkaa'uun dhorkameera. Faayiloota dhuunfaa GitHub irratti hin dabaliin. Logo, avatar fi suuraaleen upload godhaman Render disk dhaabbataa malee deploy/restart booda baduu danda'u.

## 2. GitHub private repository qopheessi

1. GitHub irratti repository haaraa **Private** uumi.
2. Faayiloota source project qofa repository sana keessatti galchi; `uploads/` fi secrets hin galchin.
3. Render keessatti GitHub account walqabsiisi, repository kana filadhu.

## 3. MySQL database alaa qopheessi

Render web service keessatti MySQL local irratti kuusuu hin filatin; disk hin dhaabbataa ta'uu danda'a. Tajaajila MySQL managed (fakkeenyaaf Aiven ykn Clever Cloud) keessatti database uumi.

1. Database irratti `database.sql` import godhi. Yoo database provider-ku `CREATE DATABASE` dhoowwe, statement `CREATE DATABASE` fi `USE` keessaa haqi; database duraan uume filadhu.
2. Database host, port, database name, user fi password isaa qopheessi.
3. Render Environment Variables keessatti:
   - `DB_HOST`: host database
   - `DB_PORT`: port database kenname
   - `DB_NAME`: maqaa database
   - `DB_USER`: user database
   - `DB_PASS`: password database

Credentials kana GitHub, source code, screenshot ykn chat public keessatti hin galchin.

Yoo `DB_HOST`/credentials hin qindaa'in yookaan placeholder dogoggoraa ta'e, Docker entrypoint ofumaan MariaDB keessaa isaa jalqaba. Kun website jalqabsiisuuf fallback qofa; Render filesystem dhaabbataa miti, kanaaf database local keessatti data galmaa'e restart/deploy booda baduu danda'a. Production keessatti database managed alaa fi credentials sirrii fayyadami.

## 4. Render Web Service

1. Render keessatti **New > Web Service** filadhu; private GitHub repository walqabsiisi.
2. Runtime/build irratti **Docker** filadhu. Project keessatti `Dockerfile` jira; Render `PORT` ofumaan dabarsa.
3. Environment Variables armaan gadii dabali:
   - `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASS` (database managed irraa)
   - `GOOGLE_CLIENT_ID` (Google Cloud Console irraa OAuth 2.0 Web Client ID; Google sign-in filannoo qofa, galmee barataa harkaan gochuuf hin barbaachisu)
   - `ADMIN_EMAIL` (email admin)
4. Deploy godhi. Render URL kenna; fakkeenyaaf `https://guuta.onrender.com` (maqaan kun yoo argame).

## 5. Google Sign-In filannoo qindeessi

Google sign-in filannoo qofa. Galmee barataa email Gmail harkaan galchuun Google OAuth malee ni danda'ama. Google sign-in dabalataan barbaadde qofa Google Cloud Console keessatti OAuth 2.0 Web Client uumi. Render URL kee keessatti:

- Authorized JavaScript origin: `https://<render-service>.onrender.com`
- Authorized redirect URI: Google Identity Services popup flow'n yeroo baay'ee hin barbaachisu; yoo console'n gaafate, domain website kee qofa galchi.

`GOOGLE_CLIENT_ID` Environment Variable keessatti Web Client ID galchi; client secret hin barbaachisu. Domain custom fayyadamtu yoo ta'e, origin custom domain sanas Google OAuth irratti galchi.

## 6. Domain fi qorannoo

Domain `guuta.com` yoo qabdu, Render service settings keessatti custom domain itti dabali; DNS record Render agarsiisu qindeessi. Yoo hin qabne, Render subdomain fayyadami.

Deploy booda homepage, Google sign-in, student registration, admin sign-in, CSV import fi database persistence qoradhu. Uploads disk dhaabbataa irratti hin kuufamne yoo ta'e logo/avatar/photo upload godhaman yeroo deploy/restart baduu danda'u.
