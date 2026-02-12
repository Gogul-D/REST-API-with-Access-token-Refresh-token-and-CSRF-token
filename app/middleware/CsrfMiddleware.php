<?php

class CsrfMiddleware
{
    public static function handle()
    {
        $method = $_SERVER['REQUEST_METHOD'];

        // Only validate for state-changing requests
        if (in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'])) {

            $headers = getallheaders();
            $clientToken = $headers['X-CSRF-Token'] ?? '';

            if (empty($_SESSION['csrf_token']) ||
                !hash_equals($_SESSION['csrf_token'], $clientToken)) {

                http_response_code(403);
                echo json_encode([
                    "status" => false,
                    "message" => "Invalid CSRF token"
                ]);
                exit;
            }
        }
    }
}
