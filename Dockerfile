FROM alpine:3.10
LABEL Maintainer="Arran Schlosberg (github.com/aschlosberg)" \
      Description="NGINX+PHP setup with phpcloud deaemon."

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

##### phpcloud #####

RUN addgroup phpcloud
RUN adduser --system phpcloud phpcloud
RUN adduser phpuser phpcloud

COPY docker/bin/phpcloud_amd64 /usr/sbin/phpcloud
RUN chown phpcloud:phpcloud /usr/sbin/phpcloud
RUN chmod 500 /usr/sbin/phpcloud

COPY docker/config/php.ini /usr/local/etc/php/conf.d/phpcloud.ini

COPY phpcloud/client/Client.php phpcloud/client/composer.* /usr/share/php7/phpcloud/
RUN chown phpuser:phpuser /usr/share/php7/phpcloud
WORKDIR /usr/share/php7/phpcloud
USER phpuser
RUN composer install --no-dev
USER root
WORKDIR /

##### /run/* directories #####

# All should be user-access only, except for phpcloud as it needs group access
# too.
RUN mkdir /run/supervisord
RUN chmod 700 /run/supervisord

RUN mkdir /run/nginx
RUN chown nginx:nginx /run/nginx
RUN chmod 700 /run/nginx

RUN mkdir /run/phpcloud
RUN chown phpcloud:phpcloud /run/phpcloud
RUN chmod 750 /run/phpcloud

##### supervisord #####

RUN apk add supervisor
COPY docker/config/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]