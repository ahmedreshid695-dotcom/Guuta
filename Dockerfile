FROM php:8.2-apache

# Install MariaDB server and PHP extensions
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        mariadb-server \
        mariadb-client \
        dos2unix && \
    docker-php-ext-install mysqli pdo pdo_mysql && \
    a2enmod rewrite && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /var/www/html

# Copy all project files
COPY . /var/www/html/

# Copy entrypoint script and ensure Unix line endings + execution permission
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN dos2unix /usr/local/bin/docker-entrypoint.sh && \
    chmod +x /usr/local/bin/docker-entrypoint.sh

# Expose default HTTP port
EXPOSE 80

# Run entrypoint script and start Apache
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["apache2-foreground"]
