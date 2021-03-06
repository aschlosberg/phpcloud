<?php
declare(strict_types=1);
/**
 * The phpcloud daemon handles cloud-provider tasks, allowing multiple PHP
 * requests to reuse resources such as data-encryption keys without having to
 * make individual requests.
 */

namespace PHPCloud;

use Spiral\Goridge\RPC;
use Spiral\Goridge\SocketRelay;
require "vendor/autoload.php";

/**
 * Client for the phpcloud daemon.
 */
class Client {
    /** @var RPC */
    private $rpc;

    /**
     * Instantiate a new Client connected to the default socket.
     * 
     * @static
     * 
     * @return Client
     */
    public static function Default() {
        return new Client("/run/phpcloud/phpcloud.sock");
    }

    /**
     * @param string $unix_socket The UNIX socket address on which phpcloud is
     * listening.
     *
     * @return void
     */
    public function __construct(string $unix_socket) {
        $relay = new SocketRelay($unix_socket, 0, SocketRelay::SOCK_UNIX);
        $this->rpc = new RPC($relay);
    }

    /**
     * Hashes a password.
     * 
     * @param string $password Plaintext password.
     * 
     * @return string The hashed password.
     */
    public function HashPassword(string $password) : string {
        $req = array("Password" => $password);
        $resp = $this->rpc->call("Crypto.HashPassword", $req);
        return $resp['Hash'];
    }

    /**
     * Hashes the password and confirms that it matches the hash. Supports
     * bcrypt and Argon2. If the password matches and the hash is weak, an
     * updated hash is passed to the update callback, which should store the new
     * hash for improved security.
     *
     * @param string $hash Hashed password.
     *
     * @param string $password Plaintext password to be checked against $hash.
     *
     * @param callable $update_cb Callback that will be called with an updated,
     * more secure hash, if both (a) the password matches; and (b) the existing
     * hash is too weak.
     * 
     * @return bool Whether the password matches the hash.
     */
    public function CheckPassword(string $hash, string $password, $update_cb) : bool {
        $req = array(
            "Hash" => $hash,
            "Password" => $password,
        );
        $resp = $this->rpc->call("Crypto.CheckPassword", $req);
        
        if ($resp['Update']) {
            $update_cb($resp['UpdatedHash']);
        }
        return $resp['Match'];
    }
}

?>