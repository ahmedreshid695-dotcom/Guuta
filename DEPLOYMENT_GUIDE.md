# Qajeelfama Deploy Gochuu (Deployment Guide)

Pirojektiin kun sirna PHP fi MySQL waan ta'eef, karaalee tolaa (free) armaan gadiin online deploy gochuu dandeessa:

---

## Mala 1: InfinityFree (Karaan Hunda Caalaa Salphaa fi Tolaa)
InfinityFree tajaajila PHP fi MySQL tolaa (cPanel & phpMyAdmin) guutuu kenna.

### Tarkaanfilee:
1. **Account Bani**: [InfinityFree.com](https://www.infinityfree.com) deemiitii galmaa'i.
2. **Account Uumi**: Dashboard irratti "Create Account" jedhii subdomain tolaa filadhu (fkn `stu-portal.infinityfreeapp.com`).
3. **Database Qopheessi**:
   - Control Panel (cPanel) seenaa "MySQL Databases" banaa.
   - Database haaraa uumaa.
   - "phpMyAdmin" banaatii database keessan filadhaa.
   - Faayila `database.sql` jedhu "Import" godhaa.
4. **Faayiloota Ol Fe'aa (Upload)**:
   - "Online File Manager" seenaa folder `htdocs/` banaa.
   - Faayiloota pirojektii kanaa (`index.html`, `config.php`, `login.php`, `register.php`, `dashboard.php`, `logout.php`) ol fe'aa (upload).
5. **Config Qindeessaa**:
   - `config.php` keessatti ragaalee database InfinityFree isiniif kenne (DB Host, DB User, DB Password, DB Name) galchaa.

---

## Mala 2: Render.com / Railway (Docker & GitHub Fayyadamuun)

Pirojektii kanaaf [Dockerfile](Dockerfile) qophaa'ee jira.

### Tarkaanfilee:
1. Pirojektii kana GitHub repository irratti fe'aa.
2. [Render.com](https://render.com) irratti "New Web Service" filadhaa GitHub repo keessan waliin walqabsiisaa.
3. Database MySQL tolaa (fkn. [Aiven.io](https://aiven.io) ykn [Clever Cloud](https://www.clever-cloud.com)) irratti uumaa faayila `database.sql` achirratti run godhaa.
4. Render irratti Environment Variables armaan gadii galchaa:
   - `DB_HOST`: Host maqaa database keessanii
   - `DB_USER`: User database keessanii
   - `DB_PASS`: Password database keessanii
   - `DB_NAME`: Maqaa database keessanii
   - `DB_PORT`: 3306 (ykn port kenname)
