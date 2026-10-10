FROM php:8.2-apache

# Enable MySQL extensions
RUN docker-php-ext-install mysqli pdo pdo_mysql

# Enable rewrite module
RUN a2enmod rewrite

# Copy project files into web root
COPY . /var/www/html/

# Expose HTTP port
EXPOSE 80

CMD ["apache2-foreground"]
