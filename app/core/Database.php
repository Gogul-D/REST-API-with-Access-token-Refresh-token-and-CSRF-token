<?php

class Database
{
    private static ?PDO $conn = null;

    public static function connect(): PDO
    {
        if (self::$conn === null) {

            $host = $_ENV['DB_HOST'];
            $db   = $_ENV['DB_NAME'];
            $user = $_ENV['DB_USER'];
            $pass = $_ENV['DB_PASS'];

            try {
                self::$conn = new PDO(
                    "mysql:host=$host;dbname=$db;charset=utf8mb4",
                    $user,
                    $pass,
                    [
                        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
                    ]
                );
            } catch (PDOException $e) {
                http_response_code(500);
                echo json_encode([
                    "status" => false,
                    "message" => "Database connection failed",
                    "error" => $e->getMessage()
                ]);
                exit;
            }
        }

        return self::$conn;
    }
}
