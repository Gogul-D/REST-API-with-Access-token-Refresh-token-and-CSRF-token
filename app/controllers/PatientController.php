<?php

require_once __DIR__ . '/../models/Patient.php';
require_once __DIR__ . '/../helpers/Response.php';
require_once __DIR__ . '/../helpers/Validator.php';
require_once __DIR__ . '/../helpers/Logger.php';

class PatientController
{
    private Patient $patient;

    public function __construct()
    {
        $this->patient = new Patient();
    }

    // =========================
    // GET ALL
    // =========================

    public function index()
    {
        $userId = $GLOBALS['auth_user']['user_id'];

        $patients = $this->patient->getAllByUser($userId);

        Response::success("Patients fetched successfully", $patients);
    }

    // =========================
    // CREATE
    // =========================

    public function store()
    {
        $data = $GLOBALS['request_body'] ?? [];

        Validator::validatePatient($data);

        $userId = $GLOBALS['auth_user']['user_id'];

        $this->patient->create($data, $userId);

        Logger::audit("User {$userId} created patient: {$data['name']}");

        Response::success("Patient created successfully", null, 201);
    }

    // =========================
    // UPDATE
    // =========================

    public function update($id)
    {
        $data = $GLOBALS['request_body'] ?? [];

        Validator::validatePatient($data, true);

        $userId = $GLOBALS['auth_user']['user_id'];

        $this->patient->update((int)$id, $userId, $data);

        Logger::audit("User {$userId} updated patient ID: {$id}");

        Response::success("Patient updated successfully");
    }

    // =========================
    // DELETE
    // =========================

    public function destroy($id)
    {
        $userId = $GLOBALS['auth_user']['user_id'];

        $this->patient->delete((int)$id, $userId);

        Logger::audit("User {$userId} deleted patient ID: {$id}");

        Response::success("Patient deleted successfully");
    }
}
