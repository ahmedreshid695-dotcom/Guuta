#!/bin/bash
set -e

external_db_configured=true
case "${DB_HOST,,}" in
    ""|localhost|127.0.0.1|mysql\ host|your\ host|host)
        external_db_configured=false
        ;;
esac
if [[ "$DB_HOST" == *[[:space:]]* ]]; then
    external_db_configured=false
fi

if [ -z "$DB_NAME" ] || [ -z "$DB_USER" ] || [ -z "$DB_PASS" ]; then
    external_db_configured=false
fi

if ! [[ "$DB_PORT" =~ ^[0-9]+$ ]] || [ "$DB_PORT" -lt 1 ] || [ "$DB_PORT" -gt 65535 ]; then
    external_db_configured=false
fi

if [ "$external_db_configured" = true ]; then
    echo ">> Using configured external database at $DB_HOST"
else
    echo ">> Starting local MariaDB service..."
    service mariadb start || /etc/init.d/mariadb start

    # Wait up to 20 seconds for MariaDB to respond
    database_ready=false
    for i in $(seq 1 20); do
        if mysqladmin ping --silent 2>/dev/null; then
            database_ready=true
            break
        fi
        sleep 1
    done

    if [ "$database_ready" != true ]; then
        echo "!! MariaDB did not become ready; cannot start the application database." >&2
        exit 1
    fi

    echo ">> Configuring database and permissions..."
    mysql -u root <<'EOSQL'
CREATE DATABASE IF NOT EXISTS stu_register;
CREATE USER IF NOT EXISTS 'stu_user'@'127.0.0.1' IDENTIFIED BY 'stu_pass123';
ALTER USER 'stu_user'@'127.0.0.1' IDENTIFIED BY 'stu_pass123';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX ON stu_register.* TO 'stu_user'@'127.0.0.1';

FLUSH PRIVILEGES;
EOSQL

    if [ -f /var/www/html/database.sql ]; then
        echo ">> Importing database.sql..."
        mysql -u root < /var/www/html/database.sql
    fi
    echo ">> Local database ready!"
    export DB_HOST=127.0.0.1
    export DB_PORT=3306
    export DB_NAME=stu_register
    export DB_USER=stu_user
    export DB_PASS=stu_pass123
fi

# Configure Apache port if Render or cloud provider specifies $PORT
if [ -n "$PORT" ]; then
    echo ">> Setting Apache port to $PORT..."
    sed -i "s/Listen 80/Listen $PORT/g" /etc/apache2/ports.conf 2>/dev/null || true
    sed -i "s/:80/:$PORT/g" /etc/apache2/sites-available/000-default.conf 2>/dev/null || true
fi

# Ensure uploads directory is writable
mkdir -p /var/www/html/uploads
chmod -R 777 /var/www/html/uploads

exec "$@"
