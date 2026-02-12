<?php

require_once __DIR__ . '/../services/AuthService.php';
require_once __DIR__ . '/../helpers/Response.php';

class AuthController
{
    private AuthService $authService;

    public function __construct()
    {
        $this->authService = new AuthService();
    }

    public function register()
    {
        $data = $GLOBALS['request_body'] ?? [];
        $this->authService->register($data);
    }

    public function login()
    {
        $data = $GLOBALS['request_body'] ?? [];
        $this->authService->login($data);
    }

    public function refresh()
    {
        $this->authService->refresh();
    }

    public function logout()
    {
        $this->authService->logout();
    }
}
