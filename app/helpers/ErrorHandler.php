<?php

require_once __DIR__ . '/Response.php';
require_once __DIR__ . '/Logger.php';

class ErrorHandler
{
    public static function handleException(Throwable $e): void
    {
        // Log full error internally
        Logger::error(
            $e->getMessage() . ' | ' . $e->getFile() . ':' . $e->getLine()
        );

        $code = $e->getCode();
        if ($code < 400 || $code > 599) {
            $code = 500;
        }

        // Safe message for client
        Response::error(
            $code === 500 ? "Internal Server Error" : $e->getMessage(),
            $code
        );
    }
}
