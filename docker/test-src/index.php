<?php

use MyAspire\Crypto;
require "awscryptod/Client.php";

const PREFIX = '$argon2i$';
const PASSWORD = "password";
const BAD_PASSWORD = "incorrect";

$c = Crypto\Client::Default();
$hash = $c->HashPassword(PASSWORD);
$check_good = $c->CheckPassword($hash, PASSWORD, null);
$check_bad = $c->CheckPassword($hash, BAD_PASSWORD, null);

if (substr($hash, 0, strlen(PREFIX))==PREFIX && $check_good && !$check_bad) {
    echo "OK";
} else {
    $pw = PASSWORD;
    $bad = BAD_PASSWORD;
    echo <<<EOF
Password: ${pw}
Bad password: ${bad}

Got hash: ${hash}
Got check correct: ${check_good}
Got check bad: ${check_bad}
EOF;
}

?>
