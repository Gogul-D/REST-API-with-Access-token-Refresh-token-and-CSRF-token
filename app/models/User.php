<?php

require_once __DIR__ . '/../core/Database.php';

class User
{
    private PDO $db;

    public function __construct()
    {
        $this->db = Database::connect();
    }

    // =========================
    // USER METHODS
    // =========================

    public function findByEmail(string $email): ?array
    {
        $stmt = $this->db->prepare(
            "SELECT * FROM users WHERE email = :email LIMIT 1"
        );

        $stmt->execute(['email' => $email]);
        return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
    }

    public function create(string $name, string $email, string $password): bool
    {
        $stmt = $this->db->prepare(
            "INSERT INTO users (name, email, password)
             VALUES (:name, :email, :password)"
        );

        return $stmt->execute([
            'name'     => $name,
            'email'    => $email,
            'password' => $password
        ]);
    }

    public function updatePassword(int $userId, string $hashedPassword): bool
    {
        $stmt = $this->db->prepare(
            "UPDATE users SET password = :password WHERE id = :id"
        );

        return $stmt->execute([
            'password' => $hashedPassword,
            'id'       => $userId
        ]);
    }

    // =========================
    // REFRESH TOKEN METHODS
    // =========================

    public function storeRefreshToken(int $userId, string $token, string $expiresAt): bool
    {
        $stmt = $this->db->prepare(
            "INSERT INTO refresh_tokens (user_id, token, expires_at)
             VALUES (:user_id, :token, :expires_at)"
        );

        return $stmt->execute([
            'user_id'    => $userId,
            'token'      => $token,
            'expires_at' => $expiresAt
        ]);
    }

    public function findRefreshToken(string $hashedToken): ?array
    {
        $stmt = $this->db->prepare(
            "SELECT * FROM refresh_tokens WHERE token = :token LIMIT 1"
        );

        $stmt->execute(['token' => $hashedToken]);
        return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
    }

    public function findRefreshTokenByRawToken(string $rawToken): ?array
    {
        // 🔐 Retrieve all tokens from the database and verify with Argon2id
        // This is necessary because Argon2id hashes are non-deterministic
        $stmt = $this->db->prepare(
            "SELECT id, user_id, token, expires_at FROM refresh_tokens ORDER BY created_at DESC"
        );

        $stmt->execute();
        $tokens = $stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($tokens as $token) {
            // Verify raw token against stored Argon2id hash
            if (password_verify($rawToken, $token['token'])) {
                return $token;
            }
        }

        return null;
    }

    public function deleteRefreshToken(string $tokenIdOrHash): bool
    {
        // Support both ID (integer) and hash (string) for backward compatibility
        if (is_numeric($tokenIdOrHash)) {
            $stmt = $this->db->prepare(
                "DELETE FROM refresh_tokens WHERE id = :id"
            );
            return $stmt->execute(['id' => $tokenIdOrHash]);
        } else {
            // Legacy: delete by token hash for backward compatibility
            $stmt = $this->db->prepare(
                "DELETE FROM refresh_tokens WHERE token = :token"
            );
            return $stmt->execute(['token' => $tokenIdOrHash]);
        }
    }

    public function deleteUserRefreshTokens(int $userId): bool
    {
        $stmt = $this->db->prepare(
            "DELETE FROM refresh_tokens WHERE user_id = :user_id"
        );

        return $stmt->execute(['user_id' => $userId]);
    }
}
