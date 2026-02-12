<?php

class JWT
{
    private static string $algo = 'sha256';

    private static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function base64UrlDecode(string $data): string
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $padLen = 4 - $remainder;
            $data .= str_repeat('=', $padLen);
        }

        return base64_decode(strtr($data, '-_', '+/'));
    }

    /**
     * Generate Access Token
     */
    public static function encode(array $payload): string
    {
        $secret = $_ENV['JWT_SECRET'] ?? null;
        $expiry = (int) ($_ENV['JWT_EXPIRY'] ?? 60);

        if (!$secret) {
            throw new Exception("JWT secret not configured", 500);
        }

        $header = [
            "alg" => "HS256",
            "typ" => "JWT"
        ];

        $payload['iat'] = time();
        $payload['exp'] = time() + $expiry;

        $base64Header  = self::base64UrlEncode(json_encode($header));
        $base64Payload = self::base64UrlEncode(json_encode($payload));

        $signature = hash_hmac(
            self::$algo,
            $base64Header . "." . $base64Payload,
            $secret,
            true
        );

        $base64Signature = self::base64UrlEncode($signature);

        return $base64Header . "." . $base64Payload . "." . $base64Signature;
    }

    /**
     * Decode & Validate JWT
     */
    public static function decode(string $token): ?array
    {
        $secret = $_ENV['JWT_SECRET'] ?? null;

        if (!$secret) {
            return null;
        }

        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            return null;
        }

        [$base64Header, $base64Payload, $base64Signature] = $parts;

        $header = json_decode(
            self::base64UrlDecode($base64Header),
            true
        );

        if (!$header || ($header['alg'] ?? '') !== 'HS256') {
            return null;
        }

        // Verify signature
        $expectedSignature = self::base64UrlEncode(
            hash_hmac(
                self::$algo,
                $base64Header . "." . $base64Payload,
                $secret,
                true
            )
        );

        if (!hash_equals($expectedSignature, $base64Signature)) {
            return null;
        }

        $payload = json_decode(
            self::base64UrlDecode($base64Payload),
            true
        );

        if (!$payload) {
            return null;
        }

        // Expiration check
        if (!isset($payload['exp']) || $payload['exp'] < time()) {
            return null;
        }

        return $payload;
    }
}
