<?php

namespace MyAspire\Crypto\Tests;

use MyAspire\Crypto;
use PHPUnit\Framework\TestCase;

class CheckPasswordTest {
    public $desc;
    public $hash;
    public $password;
    public $want_match;
    public $want_update_callbacks;

    public function __construct(string $desc, string $hash, string $password, bool $want_match, int $want_update_callbacks) {
        $this->desc = $desc;
        $this->hash = $hash;
        $this->password = $password;
        $this->want_match = $want_match;
        $this->want_update_callbacks = $want_update_callbacks;
    }
}

class ClientTest extends TestCase {
    const UNIX_SOCKET = "/tmp/awscryptod.sock";

    const PASSWORD = "password";

    const BAD_PASSWORD = "incorrect password";

    const STRONG_HASH_PREFIX = '$argon2i$';

    /** @var Client */
    private $client;

    public function setUp(): void {
        $this->client = new Crypto\Client(self::UNIX_SOCKET);
    }

    public function testCheckPassword(): void {
        $hash = $this->client->HashPassword(self::PASSWORD);
        $this->assertStringStartsWith(self::STRONG_HASH_PREFIX, $hash);

        $bcrypt = password_hash(self::PASSWORD, PASSWORD_BCRYPT);

        $cases = [
            new CheckPasswordTest("correct password", $hash, self::PASSWORD, true, 0),
            new CheckPasswordTest("incorrect password", $hash, self::BAD_PASSWORD, false, 0),
            new CheckPasswordTest("correct password for weak hash", $bcrypt, self::PASSWORD, true, 1),
            new CheckPasswordTest("incorrect password for weak hash", $bcrypt, self::BAD_PASSWORD, false, 0),
        ];

        foreach ($cases as $case) {
            $update_callbacks = 0;
            $updated_hash = "";
            
            $match = $this->client->CheckPassword($case->hash, $case->password, function($updated) use (&$update_callbacks, &$updated_hash) {
                $update_callbacks++;
                $updated_hash = $updated;
            });

            $this->assertEquals($case->want_match, $match, "CheckPassword() return value: ".$case->desc);
            $this->assertEquals($case->want_update_callbacks, $update_callbacks, "update callback called: ".$case->desc);
            if ($case->want_update_callbacks > 0) {
                $this->assertStringStartsWith(self::STRONG_HASH_PREFIX, $updated_hash, "updated weak password uses strong hash");
            }
        }
    }
}