# ✅ FULL SYSTEM TEST FLOW (Professional Way)

We will test:
Register
Login
Add Patient
Get Patients
Update Patient
Delete Patient
Access Token Expiry Test
Refresh Token Test
Csrf Token test

# 🧪 CSFR Token Test in Postman

## 1️⃣ Login

You will receive:

{
  "access_token": "...",
  "csrf_token": "abc123xyz..."
}

## 2️⃣ For Creating Patient

Add headers:

Authorization: Bearer <access_token>
X-CSRF-Token: <csrf_token>
Content-Type: application/json

### Now it will work.

## ❌ If CSRF Missing (without csrf token )

You will get:

{
  "status": false,
  "message": "Invalid CSRF token"
}


### Correct behavior(Got error).

# Multi-user Isolation Test

## 🟢 STEP 1 — Register User 1
POST
http://localhost/project/api/register

Body (JSON)
{
  "name": "User One",
  "email": "user1@test.com",
  "password": "123456"
}


### ✅ Expected:

User registered successfully

## 🟢 STEP 2 — Login User 1
POST
http://localhost/project/api/login

Body:
{
  "email": "user1@test.com",
  "password": "123456"
}


### ✅ You should get:

access_token
expires_in


🔐 Copy the access_token

## 🟢 STEP 3 — Add Patient (User 1)
POST
/api/patients

Authorization

Bearer Token → paste access token

Body
{
  "name": "John Doe",
  "age": 30,
  "gender": "Male",
  "phone": "9876543210",
  "address": "Chennai"
}


### ✅ Expected:

Patient created successfully

## 🟢 STEP 4 — Get Patients (User 1)
GET
/api/patients


Authorization: Bearer token

### ✅ You should see:

Only User 1's patients

## 🟢 STEP 5 — Create User 2

Register another user:

{
  "name": "User Two",
  "email": "user2@test.com",
  "password": "123456"
}


Login user2 and copy access token.

## 🟢 STEP 6 — Test User Isolation (IMPORTANT 🔥)

Login as User2.

GET
/api/patients


### ✅ Expected:

Empty list


User2 should NOT see User1's patients.

If this works → Your security is correct.

## 🟢 STEP 7 — Access Token Expiry Test (1 Minute)

Since you set:

JWT_EXPIRY = 60


Wait 1 minute.

Then try:

GET /api/patients


### ❌ Expected:

401 Invalid or expired token


✔ That means access token works correctly.

## 🟢 STEP 8 — Refresh Token Flow
POST
/api/refresh


(No body needed)

⚠ IMPORTANT:
Cookies must be enabled in Postman.

### Expected:

Token refreshed successfully
New access token


Copy new access token.

Now test:

GET /api/patients


✅ Should work again.

## 🟢 STEP 9 — Logout Test
POST /api/logout


Then try:

POST /api/refresh


❌ Expected:

Refresh token missing or invalid


System is secure.

## 🟢 STEP 10 — Database Check

Check DB:

patients table

Each record should have:

user_id


Meaning data is linked to user correctly.

### 🟢 FINAL SECURITY CHECK (Most Important)

Try this:

Login as User2
Try to update User1's patient ID.

PUT /api/patients/1


### ❌ Should fail.

If it updates → SECURITY BUG ❌
If it blocks → PRODUCTION READY ✔

