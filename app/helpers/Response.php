<?php

class Response
{
    public static function success(string $message, $data = null, int $code = 200): void
    {
        http_response_code($code);

        echo json_encode([
            "status"  => true,
            "message" => $message,
            "data"    => $data
        ]);

        exit;
    }

    public static function error(string $message, int $code = 400): void
    {
        http_response_code($code);

        echo json_encode([
            "status"  => false,
            "message" => $message
        ]);

        exit;
    }
}
