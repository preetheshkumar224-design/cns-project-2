import base64
import os
import tempfile
import unittest

from app import DEMO_DOCTOR, DEMO_PATIENT, create_app, sdes_crypt_byte


class PatientAppTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        database = os.path.join(self.temp_dir.name, "test.sqlite3")
        self.app = create_app({
            "TESTING": True,
            "DATABASE": database,
            "SECRET_KEY": b"t" * 32,
            "ENCRYPTION_KEY": base64.urlsafe_b64encode(b"t" * 32),
        })
        self.client = self.app.test_client()
        self.client.get("/")
        with self.client.session_transaction() as session:
            self.csrf = session["csrf_token"]

    def tearDown(self):
        self.temp_dir.cleanup()

    def post(self, url, json=None):
        return self.client.post(url, json=json, headers={"X-CSRF-Token": self.csrf})

    def sign_in(self, credentials):
        response = self.post("/api/login", {
            "username": credentials[0], "password": credentials[1],
            "role": "doctor" if credentials == DEMO_DOCTOR else "patient",
        })
        self.assertEqual(response.status_code, 200, response.get_json())
        self.csrf = self.client.get("/api/me").get_json()["csrfToken"]

    def test_sdes_known_vector_and_round_trip(self):
        self.assertEqual(sdes_crypt_byte(0b10101010, "1010000010"), 0b10001101)
        self.assertEqual(
            sdes_crypt_byte(0b10001101, "1010000010", decrypt=True), 0b10101010
        )

    def test_patient_cannot_list_or_view_another_patient(self):
        self.sign_in(DEMO_PATIENT)
        self.assertEqual(self.client.get("/api/patients").status_code, 403)
        self.assertEqual(self.client.get("/api/patients/not-owned").status_code, 403)

    def test_doctor_can_create_encrypted_record_and_patient_login(self):
        self.sign_in(DEMO_DOCTOR)
        payload = {
            "username": "alex.lee", "password": "SecureDemoPass1",
            "firstName": "Alex", "lastName": "Lee", "age": 41, "sex": "Male",
            "diagnosis": "Routine check-up", "medicalHistory": "No known allergies.",
            "heartRate": 68, "temperature": 36.8, "oxygenSaturation": 99,
        }
        response = self.post("/api/patients", payload)
        self.assertEqual(response.status_code, 201, response.get_json())
        patient_id = response.get_json()["patient"]["id"]
        self.sign_in(DEMO_PATIENT)
        self.assertEqual(self.client.get(f"/api/patients/{patient_id}").status_code, 403)
        self.sign_in(("alex.lee", "SecureDemoPass1"))
        self.assertEqual(self.client.get(f"/api/patients/{patient_id}").status_code, 200)
        self.assertEqual(self.client.get("/api/patients/not-owned").status_code, 403)

    def test_patient_record_is_not_stored_as_plaintext(self):
        self.sign_in(DEMO_DOCTOR)
        encrypted = self.client.get("/api/patients").get_json()["patients"][0]
        import sqlite3
        connection = sqlite3.connect(self.app.config["DATABASE"])
        try:
            row = connection.execute(
                "SELECT encrypted_record FROM patients WHERE id = ?", (encrypted["id"],)
            ).fetchone()
        finally:
            connection.close()
        self.assertNotIn(b"Maya", row[0])

    def test_sdes_tools_are_doctor_only(self):
        self.sign_in(DEMO_PATIENT)
        response = self.post("/api/sdes/encrypt", {"text": "hello", "key": "1010000010"})
        self.assertEqual(response.status_code, 403)

    def test_mutation_requires_csrf_token(self):
        response = self.client.post("/api/login", json={
            "username": DEMO_DOCTOR[0], "password": DEMO_DOCTOR[1], "role": "doctor"
        })
        self.assertEqual(response.status_code, 403)

    def test_selected_role_must_match_account_role(self):
        response = self.post("/api/login", {
            "username": DEMO_DOCTOR[0], "password": DEMO_DOCTOR[1], "role": "patient"
        })
        self.assertEqual(response.status_code, 403)
        self.assertIn("account type", response.get_json()["error"])
        self.assertEqual(self.client.get("/api/me").get_json()["user"], None)


if __name__ == "__main__":
    unittest.main()
