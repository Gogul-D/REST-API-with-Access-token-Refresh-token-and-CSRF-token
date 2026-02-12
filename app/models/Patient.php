<?php

require_once __DIR__ . '/../core/Database.php';

class Patient
{
    private PDO $db;

    public function __construct()
    {
        $this->db = Database::connect();
    }

    // =========================
    // GET PATIENTS BY USER
    // =========================

    public function getAllByUser(int $userId): array
    {
        $stmt = $this->db->prepare(
            "SELECT * FROM patients 
             WHERE user_id = :user_id
             ORDER BY id DESC"
        );

        $stmt->execute(['user_id' => $userId]);

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    // =========================
    // CREATE PATIENT
    // =========================

    public function create(array $data, int $userId): bool
    {
        $sql = "INSERT INTO patients 
                (user_id, name, age, gender, phone, address)
                VALUES
                (:user_id, :name, :age, :gender, :phone, :address)";

        $stmt = $this->db->prepare($sql);

        return $stmt->execute([
            'user_id' => $userId,
            'name'    => $data['name'],
            'age'     => $data['age'],
            'gender'  => $data['gender'],
            'phone'   => $data['phone'] ?? null,
            'address' => $data['address'] ?? null
        ]);
    }

    // =========================
    // UPDATE (USER SAFE)
    // =========================

    public function update(int $id, int $userId, array $data): bool
    {
        $sql = "UPDATE patients
                SET name = :name,
                    age = :age,
                    gender = :gender,
                    phone = :phone,
                    address = :address
                WHERE id = :id
                AND user_id = :user_id";

        $stmt = $this->db->prepare($sql);

        return $stmt->execute([
            'name'    => $data['name'],
            'age'     => $data['age'],
            'gender'  => $data['gender'],
            'phone'   => $data['phone'] ?? null,
            'address' => $data['address'] ?? null,
            'id'      => $id,
            'user_id' => $userId
        ]);
    }

    // =========================
    // DELETE (USER SAFE)
    // =========================

    public function delete(int $id, int $userId): bool
    {
        $stmt = $this->db->prepare(
            "DELETE FROM patients 
             WHERE id = :id
             AND user_id = :user_id"
        );

        return $stmt->execute([
            'id'      => $id,
            'user_id' => $userId
        ]);
    }
}
