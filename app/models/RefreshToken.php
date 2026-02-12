<?php

require_once __DIR__ . '/../models/User.php';

class RefreshTokenService
{
    private User $user;

    public function __construct()
    {
        $this->user = new User();
    }

    public function create(int $userId): string
    {
        $token  = bin2hex(random_bytes(64));
        $expiry = date('Y-m-d H:i:s', strtotime('+7 days'));

        $this->user->storeRefreshToken(
            $userId,
            $token,
            $expiry
        );

        return $token;
    }

    public function validateAndRotate(string $token): int
    {
        $tokenData = $this->user->findRefreshToken($token);

        if (!$tokenData) {
            throw new Exception("Invalid refresh token", 401);
        }

        if (strtotime($tokenData['expires_at']) < time()) {
            $this->user->deleteRefreshToken($token);
            throw new Exception("Refresh token expired", 401);
        }

        $this->user->deleteRefreshToken($token);

        $this->create((int)$tokenData['user_id']);

        return (int)$tokenData['user_id'];
    }

    public function delete(string $token): void
    {
        $this->user->deleteRefreshToken($token);
    }
}
