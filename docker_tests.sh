#!/bin/sh
set -eux

apk add curl

curl --silent http://phpcloud:8080/fpm-ping \
    | tee /dev/stderr | grep -E '^pong$' >/dev/null

curl --silent http://phpcloud:8080 \
    | tee /dev/stderr | grep -E '^Tests pass$' >/dev/null