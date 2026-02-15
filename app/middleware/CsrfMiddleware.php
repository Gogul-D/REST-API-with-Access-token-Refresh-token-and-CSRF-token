<?php

class CsrfMiddleware
{
    public static function handle()
    {
        $headers = getallheaders();

        $csrfHeader = $headers['X-CSRF-Token'] ?? '';

        if (!isset($_SESSION['csrf_token'])) {
            http_response_code(403);
            echo json_encode([
                "status" => false,
                "message" => "CSRF token missing in session"
            ]);
            exit;
        }

        if (!hash_equals($_SESSION['csrf_token'], $csrfHeader)) {
            http_response_code(403);
            echo json_encode([
                "status" => false,
                "message" => "Invalid CSRF token"
            ]);
            exit;
        }
    }
}

