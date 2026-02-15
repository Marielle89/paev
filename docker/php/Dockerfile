FROM php:8.4-fpm

RUN apt-get update && apt-get install -y \
    git unzip curl \
    libicu-dev libzip-dev \
    libgmp-dev \
 && docker-php-ext-install intl zip opcache gmp \
 && pecl install redis \
 && docker-php-ext-enable redis \
 && rm -rf /var/lib/apt/lists/*

RUN docker-php-ext-install intl zip opcache

RUN if ! php -m | grep -qi '^redis$'; then pecl install redis; fi \
 && docker-php-ext-enable redis

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /var/www/html
