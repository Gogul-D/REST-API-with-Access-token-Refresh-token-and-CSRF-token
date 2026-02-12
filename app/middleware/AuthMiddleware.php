<?php

require_once __DIR__ . '/../helpers/JWT.php';

class AuthMiddleware
{
    public static function handle()
    {
        $headers = getallheaders();

        if (!isset($headers['Authorization'])) {
            http_response_code(401);
            echo json_encode([
                "status" => false,
                "message" => "Authorization token missing"
            ]);
            exit;
        }

        // Expect: Bearer <token>
        if (!preg_match('/Bearer\s(\S+)/', $headers['Authorization'], $matches)) {
            http_response_code(401);
            echo json_encode([
                "status" => false,
                "message" => "Invalid Authorization format"
            ]);
            exit;
        }

        $token = $matches[1];
        $decoded = JWT::decode($token);

        if (!$decoded) {
            http_response_code(401);
            echo json_encode([
                "status" => false,
                "message" => "Invalid or expired token"
            ]);
            exit;
        }

        // Attach user data globally
        $GLOBALS['auth_user'] = $decoded;
    }
}