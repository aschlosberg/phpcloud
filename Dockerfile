FROM alpine:3.10
LABEL Maintainer="Arran Schlosberg (github.com/aschlosberg)" \
      Description="NGINX+PHP setup with awscryptod."

##### nginx #####

RUN apk add nginx

COPY docker/config/nginx.conf /etc/nginx/nginx.conf
COPY docker/config/nginx-fastcgi.conf /etc/nginx/fastcgi.conf
RUN rm /etc/nginx/conf.d/*
COPY docker/config/nginx-server.conf /etc/nginx/conf.d/server.conf

VOLUME /var/www/public
EXPOSE 8080

##### php #####

RUN apk add php7 php7-fpm php7-sockets composer

RUN addgroup phpuser
RUN adduser --system phpuser phpuser

RUN rm /etc/php7/php-fpm.d/*
COPY docker/config/fpm-www_pool.conf /etc/php7/php-fpm.d/www.conf

##### awscryptod #####

RUN addgroup awscrypto
RUN adduser --system awscrypto awscrypto
RUN adduser phpuser awscrypto

COPY docker/bin/awscryptod_amd64 /usr/sbin/awscryptod
RUN chown awscrypto:awscrypto /usr/sbin/awscryptod
RUN chmod 500 /usr/sbin/awscryptod

COPY docker/config/php.ini /usr/local/etc/php/conf.d/awscryptod.ini

COPY awscryptod/client/Client.php awscryptod/client/composer.* /usr/share/php7/awscryptod/
RUN chown phpuser:phpuser /usr/share/php7/awscryptod
WORKDIR /usr/share/php7/awscryptod
USER phpuser
RUN composer install --no-dev
USER root
WORKDIR /

##### /run/* directories #####

# All should be user-access only, except for awscryptod as it needs group access
# too.
RUN mkdir /run/supervisord
RUN chmod 700 /run/supervisord

RUN mkdir /run/nginx
RUN chown nginx:nginx /run/nginx
RUN chmod 700 /run/nginx

RUN mkdir /run/awscryptod
RUN chown awscrypto:awscrypto /run/awscryptod
RUN chmod 750 /run/awscryptod

##### supervisord #####

RUN apk add supervisor
COPY docker/config/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]