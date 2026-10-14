#!/bin/bash
set -e

# If external DB_HOST is set and not 127.0.0.1/localhost, skip local MariaDB
if [ -n "$DB_HOST" ] && [ "$DB_HOST" != "127.0.0.1" ] && [ "$DB_HOST" != "localhost" ]; then
    echo ">> Using external database at $DB_HOST"
else
    echo ">> Starting local MariaDB service..."
    service mariadb start || /etc/init.d/mariadb start

    # Wait up to 20 seconds for MariaDB to respond
    for i in $(seq 1 20); do
        if mysqladmin ping --silent 2>/dev/null; then
            break
        fi
        sleep 1
    done

    echo ">> Configuring database and permissions..."
    mysql -e "CREATE DATABASE IF NOT EXISTS stu_register;"
    mysql -e "CREATE USER IF NOT EXISTS 'root'@'127.0.0.1' IDENTIFIED BY '';" 2>/dev/null || true
    mysql -e "GRANT ALL PRIVILEGES ON *.* TO 'root'@'127.0.0.1' WITH GRANT OPTION;" 2>/dev/null || true
    mysql -e "GRANT ALL PRIVILEGES ON *.* TO 'root'@'localhost' WITH GRANT OPTION;" 2>/dev/null || true
    mysql -e "FLUSH PRIVILEGES;" 2>/dev/null || true

    if [ -f /var/www/html/database.sql ]; then
        echo ">> Importing database.sql..."
        mysql stu_register < /var/www/html/database.sql 2>/dev/null || true
    fi
    echo ">> Local database ready!"
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
