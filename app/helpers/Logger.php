<?php

class Logger
{
    private static function write(string $file, string $message): void
    {
        $date = date('Y-m-d H:i:s');
        $log  = "[$date] $message" . PHP_EOL;

        file_put_contents(
            __DIR__ . "/../logs/$file",
            $log,
            FILE_APPEND
        );
    }

    /**
     * Log system / application errors
     */
    public static function error(string $message): void
    {
        self::write('error.log', $message);
    }

    /**
     * Log audit actions (who did what)
     */
    public static function audit(string $message): void
    {
        self::write('audit.log', $message);
    }
}
