set -eu;

# TODO launch and kill the daemon binary automatically. Might involve writing
# this as a Go test.

./vendor/bin/phpunit \
    --bootstrap vendor/autoload.php \
    --bootstrap Client.php \
    --testdox tests;