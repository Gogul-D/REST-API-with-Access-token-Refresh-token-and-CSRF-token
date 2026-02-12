<?php

require_once __DIR__ . '/Response.php';

class Validator
{
    /**
     * Validate patient data for create/update
     */
    public static function validatePatient(array $data, bool $isUpdate = false): void
    {
        // Name
        if (!$isUpdate || isset($data['name'])) {
            if (empty($data['name']) || strlen($data['name']) < 3) {
                Response::error("Name must be at least 3 characters", 422);
            }
        }

        // Age
        if (!$isUpdate || isset($data['age'])) {
            if (!isset($data['age']) || !is_numeric($data['age']) || $data['age'] < 1 || $data['age'] > 120) {
                Response::error("Age must be a number between 1 and 120", 422);
            }
        }

        // Gender
        if (!$isUpdate || isset($data['gender'])) {
            $allowedGenders = ['Male', 'Female', 'Other'];
            if (empty($data['gender']) || !in_array($data['gender'], $allowedGenders)) {
                Response::error("Gender must be Male, Female, or Other", 422);
            }
        }

        // Phone (optional)
        if (isset($data['phone']) && !preg_match('/^[0-9]{10}$/', $data['phone'])) {
            Response::error("Phone number must be 10 digits", 422);
        }
    }
}
