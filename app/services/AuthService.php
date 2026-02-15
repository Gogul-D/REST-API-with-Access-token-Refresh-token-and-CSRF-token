<?php

require_once __DIR__ . '/../models/User.php';
require_once __DIR__ . '/../helpers/JWT.php';
require_once __DIR__ . '/../helpers/Response.php';

class AuthService
{
    private User $user;

    public function __construct()
    {
        $this->user = new User();
    }

    // ========================
    // REGISTER
    // ========================
    public function register(array $data)
    {
        if (empty($data['name']) || empty($data['email']) || empty($data['password'])) {
            Response::error("All fields are required", 422);
        }

        if ($this->user->findByEmail($data['email'])) {
            Response::error("Email already exists", 409);
        }

        // Strong password hashing (Argon2id)
        $hashedPassword = password_hash(
            $data['password'],
            PASSWORD_ARGON2ID
        );

        $this->user->create(
            $data['name'],
            $data['email'],
            $hashedPassword
        );

        Response::success("User registered successfully", null, 201);
    }

    // ========================
    // LOGIN
    // ========================
    public function login(array $data)
    {
        if (empty($data['email']) || empty($data['password'])) {
            Response::error("Email and password required", 422);
        }

        $user = $this->user->findByEmail($data['email']);

        if (!$user || !password_verify($data['password'], $user['password'])) {
            Response::error("Invalid credentials", 401);
        }

        // Optional rehash check
        if (password_needs_rehash($user['password'], PASSWORD_ARGON2ID)) {
            $newHash = password_hash($data['password'], PASSWORD_ARGON2ID);
            $this->user->updatePassword($user['id'], $newHash);
        }

        //  Access Token
        $payload = [
            'user_id' => $user['id'],
            'email'   => $user['email']
        ];

        $accessToken = JWT::encode($payload);

        //  Refresh Token (RAW)
        $refreshToken = bin2hex(random_bytes(64));

        // Hash with Argon2id for better security
        $hashedToken = password_hash($refreshToken, PASSWORD_ARGON2ID);

        $refreshExpiry = date('Y-m-d H:i:s', strtotime('+7 days'));

        $this->user->storeRefreshToken(
            $user['id'],
            $hashedToken,
            $refreshExpiry
        );

        setcookie("refresh_token", $refreshToken, [
            'expires'  => time() + (7 * 24 * 60 * 60),
            'path'     => '/',
            'secure'   => false,
            'httponly' => true,
            'samesite' => 'Strict'
        ]);

        // Generate CSRF Token
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));


        Response::success("Login successful", [
            "access_token" => $accessToken,
            "csrf_token"   => $_SESSION['csrf_token'],
            "expires_in"   => (int) $_ENV['JWT_EXPIRY']
        ]);

    }

    // ========================
    // REFRESH
    // ========================
    public function refresh()
    {
        if (!isset($_COOKIE['refresh_token'])) {
            Response::error("Refresh token missing", 401);
        }

        $rawToken = $_COOKIE['refresh_token'];

        $tokenData = $this->user->findRefreshTokenByRawToken($rawToken);

        if (!$tokenData) {
           Response::error("Refresh token missing. Please login again.", 401);
        }

        if (strtotime($tokenData['expires_at']) < time()) {
            $this->user->deleteRefreshToken($tokenData['id']);
            Response::error("Refresh token expired", 401);
        }

        // Rotate token
        $this->user->deleteRefreshToken($tokenData['id']);

        $newToken = bin2hex(random_bytes(64));
        $newHashed = password_hash($newToken, PASSWORD_ARGON2ID);
        $newExpiry = date('Y-m-d H:i:s', strtotime('+7 days'));

        $this->user->storeRefreshToken(
            $tokenData['user_id'],
            $newHashed,
            $newExpiry
        );

        setcookie("refresh_token", $newToken, [
            'expires'  => time() + (7 * 24 * 60 * 60),
            'path'     => '/',
            'secure'   => false,
            'httponly' => true,
            'samesite' => 'Strict'
        ]);

        $newAccessToken = JWT::encode([
            'user_id' => $tokenData['user_id']
        ]);

        Response::success("Token refreshed successfully", [
            "access_token" => $newAccessToken,
            "expires_in"   => (int) $_ENV['JWT_EXPIRY']
        ]);
    }

    // ========================
    // LOGOUT
    // ========================
    public function logout()
    {
        if (!isset($_COOKIE['refresh_token'])) {
            Response::error("Refresh token missing", 401);
        }

        $rawToken = $_COOKIE['refresh_token'];
        $tokenData = $this->user->findRefreshTokenByRawToken($rawToken);

        if ($tokenData) {
            $this->user->deleteRefreshToken($tokenData['id']);
        }

        setcookie("refresh_token", "", [
            'expires' => time() - 3600,
            'path'    => '/'
        ]);

        Response::success("Logged out successfully");
    }
}
