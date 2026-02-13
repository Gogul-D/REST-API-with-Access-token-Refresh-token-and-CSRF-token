<?php
/**
 * --------------------------------------------------
 * SINGLE ENTRY POINT
 * public/index.php
 * 
 * Initializes and handles:
 * - Environment configuration
 * - Error handling
 * - Middleware processing
 * - Request routing
 * - Controller dispatch
 */
session_start();

require_once __DIR__ . '/../config/config.php';

//global error handler
require_once __DIR__ . '/../app/helpers/ErrorHandler.php';
set_exception_handler(['ErrorHandler', 'handleException']);

//Middleware
require_once __DIR__ . '/../app/middleware/JsonMiddleware.php';// validates request format
JsonMiddleware::handle();
require_once __DIR__ . '/../app/middleware/AuthMiddleware.php';// validates JWT token for protected routes
require_once __DIR__ . '/../app/middleware/CsrfMiddleware.php';

//Router 
require_once __DIR__ . '/../app/core/Router.php';
$router = new Router();

//load controllers
require_once __DIR__ . '/../app/controllers/AuthController.php';
require_once __DIR__ . '/../app/controllers/PatientController.php';

$authController     = new AuthController();
$patientController  = new PatientController();

// AUTH ROUTES (PUBLIC)

$router->add('POST', '/api/register', [$authController, 'register']);
$router->add('POST', '/api/login', [$authController, 'login']);
$router->add('POST', '/api/refresh', [$authController, 'refresh']);
$router->add('POST', '/api/logout', [$authController, 'logout']);


//protected routes (require authentication)

// =============================
// PROTECTED ROUTES
// =============================

// GET ALL PATIENTS
$router->add('GET', '/api/patients', function () use ($patientController) {
    AuthMiddleware::handle();
    $patientController->index();
});

// CREATE PATIENT
$router->add('POST', '/api/patients', function () use ($patientController) {
    AuthMiddleware::handle();
    CsrfMiddleware::handle();
    $patientController->store();
});

// UPDATE PATIENT
$router->add('PUT', '/api/patients/{id}', function ($params) use ($patientController) {
    AuthMiddleware::handle();
    CsrfMiddleware::handle();

    $id = $params['id'] ?? null;

    if (!$id) {
        http_response_code(400);
        echo json_encode([
            "status" => false,
            "message" => "Patient ID is required"
        ]);
        return;
    }

    $patientController->update($id);
});

$router->add('PATCH', '/api/patients/{id}', function ($params) use ($patientController) {

    AuthMiddleware::handle();
    CsrfMiddleware::handle();   // Important for security

    $id = $params['id'] ?? null;

    if (!$id) {
        http_response_code(400);
        echo json_encode([
            "status" => false,
            "message" => "Patient ID is required"
        ]);
        return;
    }

    $patientController->update($id);
});


// DELETE PATIENT
$router->add('DELETE', '/api/patients/{id}', function ($params) use ($patientController) {
    AuthMiddleware::handle();
    CsrfMiddleware::handle();

    $id = $params['id'] ?? null;

    if (!$id) {
        http_response_code(400);
        echo json_encode([
            "status" => false,
            "message" => "Patient ID is required"
        ]);
        return;
    }

    $patientController->destroy($id);
});

//DISPATCH REQUEST

$router->dispatch(
    $_SERVER['REQUEST_URI'],
    $_SERVER['REQUEST_METHOD']
);
