import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import time
import uuid
from pathlib import Path

from flask import Flask, g, jsonify, render_template, request, session


BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
DEMO_DOCTOR = ("doctor@medsecure.test", "DoctorDemo2026!")
DEMO_PATIENT = ("patient@medsecure.test", "PatientDemo2026!")
PASSWORD_ITERATIONS = 260_000

P10 = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
P8 = (6, 3, 7, 4, 8, 5, 10, 9)
IP = (2, 6, 3, 1, 4, 8, 5, 7)
IP_INVERSE = (4, 1, 3, 5, 7, 2, 8, 6)
EP = (4, 1, 2, 3, 2, 3, 4, 1)
P4 = (2, 4, 3, 1)
S0 = ((1, 0, 3, 2), (3, 2, 1, 0), (0, 2, 1, 3), (3, 1, 3, 2))
S1 = ((0, 1, 2, 3), (2, 0, 1, 3), (3, 0, 1, 0), (2, 1, 0, 3))


def _permute(bits, positions):
    return "".join(bits[position - 1] for position in positions)


def _left_shift(bits, amount):
    return bits[amount:] + bits[:amount]


def _keys(key):
    if not isinstance(key, str) or len(key) != 10 or any(bit not in "01" for bit in key):
        raise ValueError("The S-DES key must contain exactly 10 binary digits.")
    permuted = _permute(key, P10)
    left, right = permuted[:5], permuted[5:]
    left, right = _left_shift(left, 1), _left_shift(right, 1)
    first = _permute(left + right, P8)
    left, right = _left_shift(left, 2), _left_shift(right, 2)
    return first, _permute(left + right, P8)


def _sbox(bits, box):
    row = int(bits[0] + bits[3], 2)
    column = int(bits[1:3], 2)
    return format(box[row][column], "02b")


def _fk(bits, key):
    left, right = bits[:4], bits[4:]
    mixed = format(int(_permute(right, EP), 2) ^ int(key, 2), "08b")
    substituted = _sbox(mixed[:4], S0) + _sbox(mixed[4:], S1)
    return format(int(left, 2) ^ int(_permute(substituted, P4), 2), "04b") + right


def sdes_crypt_byte(value, key, decrypt=False):
    first, second = _keys(key)
    bits = _permute(format(value, "08b"), IP)
    bits = _fk(bits, second if decrypt else first)
    bits = bits[4:] + bits[:4]
    bits = _fk(bits, first if decrypt else second)
    return int(_permute(bits, IP_INVERSE), 2)


def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)
    return salt.hex() + "$" + digest.hex()


def verify_password(password, encoded):
    salt_hex, digest_hex = encoded.split("$", 1)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), PASSWORD_ITERATIONS
    )
    return hmac.compare_digest(digest.hex(), digest_hex)


def _persistent_secret(path, factory=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        try:
            with path.open("xb") as secret_file:
                secret_file.write(factory() if factory else secrets.token_bytes(32))
        except FileExistsError:
            pass
    return path.read_bytes()


def _sdes_key_for_secret(secret):
    if isinstance(secret, str):
        secret_bytes = secret.encode("utf-8")
    elif isinstance(secret, (bytes, bytearray)):
        secret_bytes = bytes(secret)
    else:
        secret_bytes = str(secret).encode("utf-8")
    digest = hashlib.sha256(secret_bytes).digest()
    return "".join(format(byte, "08b") for byte in digest)[:10]


def _encrypted_patient(secret, patient):
    key = _sdes_key_for_secret(secret)
    payload = json.dumps(patient, separators=(",", ":")).encode("utf-8")
    return bytes(sdes_crypt_byte(value, key) for value in payload)


def _decrypt_patient(secret, value):
    key = _sdes_key_for_secret(secret)
    try:
        decrypted = bytes(sdes_crypt_byte(byte, key, decrypt=True) for byte in value)
        return json.loads(decrypted.decode("utf-8"))
    except (TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("A patient record could not be decrypted; check the encryption key.") from error


def _validate_patient(payload, include_account=False):
    if not isinstance(payload, dict):
        raise ValueError("Submit a valid patient record.")
    fields = ("firstName", "lastName", "age", "sex", "diagnosis", "medicalHistory",
              "heartRate", "temperature", "oxygenSaturation")
    values = {field: payload.get(field) for field in fields}
    for field in ("firstName", "lastName", "sex", "diagnosis", "medicalHistory"):
        if not isinstance(values[field], str) or not values[field].strip():
            raise ValueError(f"{field} is required.")
        values[field] = values[field].strip()[:2000]
    try:
        values["age"] = int(values["age"])
        values["heartRate"] = int(values["heartRate"])
        values["temperature"] = round(float(values["temperature"]), 1)
        values["oxygenSaturation"] = int(values["oxygenSaturation"])
    except (TypeError, ValueError, OverflowError) as error:
        raise ValueError("Age and vital signs must be valid numbers.") from error
    if not 1 <= values["age"] <= 120:
        raise ValueError("Age must be between 1 and 120.")
    if not 20 <= values["heartRate"] <= 250:
        raise ValueError("Heart rate must be between 20 and 250 bpm.")
    if not 30 <= values["temperature"] <= 45:
        raise ValueError("Temperature must be between 30 and 45 °C.")
    if not 50 <= values["oxygenSaturation"] <= 100:
        raise ValueError("Oxygen saturation must be between 50 and 100%.")
    if include_account:
        username = payload.get("username")
        password = payload.get("password")
        if not isinstance(username, str) or not 3 <= len(username.strip()) <= 64:
            raise ValueError("Username must contain between 3 and 64 characters.")
        if not isinstance(password, str) or len(password) < 10:
            raise ValueError("The patient's initial password must contain at least 10 characters.")
        values["username"] = username.strip().lower()
        values["password"] = password
    values["updatedAt"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return values


def create_app(test_config=None):
    app = Flask(__name__, instance_path=str(INSTANCE_DIR))
    app.config.from_mapping(
        DATABASE=str(INSTANCE_DIR / "patients.sqlite3"),
        SECRET_KEY=_persistent_secret(INSTANCE_DIR / "session.secret"),
        ENCRYPTION_KEY=_persistent_secret(INSTANCE_DIR / "records.key", lambda: secrets.token_bytes(32)),
        DEMO_DATA=os.environ.get("DEMO_DATA", "true").lower() == "true",
        JSON_SORT_KEYS=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "").lower() == "true",
    )
    if test_config:
        app.config.update(test_config)
    logging.basicConfig(level=logging.INFO)

    def connect_db():
        connection = sqlite3.connect(app.config["DATABASE"], timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def initialize_db():
        Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)
        connection = connect_db()
        try:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS accounts (
                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK (role IN ('doctor', 'patient')),
                    patient_id TEXT
                );
                CREATE TABLE IF NOT EXISTS patients (
                    id TEXT PRIMARY KEY,
                    encrypted_record BLOB NOT NULL
                );
                """
            )
            if app.config["DEMO_DATA"]:
                _seed_demo_data(connection)
            connection.commit()
        finally:
            connection.close()

    def _seed_demo_data(connection):
        doctor_username, doctor_password = DEMO_DOCTOR
        patient_username, patient_password = DEMO_PATIENT
        doctor = connection.execute(
            "SELECT id FROM accounts WHERE username = ?", (doctor_username,)
        ).fetchone()
        if doctor is None:
            connection.execute(
                "INSERT INTO accounts VALUES (?, ?, ?, ?, NULL)",
                (uuid.uuid4().hex, doctor_username, hash_password(
                    os.environ.get("DEMO_DOCTOR_PASSWORD", doctor_password)
                ), "doctor"),
            )
        patient = connection.execute(
            "SELECT id FROM accounts WHERE username = ?", (patient_username,)
        ).fetchone()
        if patient is None:
            patient_id = uuid.uuid4().hex
            record = {
                "firstName": "Maya", "lastName": "Chen", "age": 34, "sex": "Female",
                "diagnosis": "Seasonal asthma", "medicalHistory": "Mild asthma; no known allergies.",
                "heartRate": 72, "temperature": 36.7, "oxygenSaturation": 98,
                "updatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            connection.execute(
                "INSERT INTO patients VALUES (?, ?)",
                (patient_id, _encrypted_patient(app.config["ENCRYPTION_KEY"], record)),
            )
            connection.execute(
                "INSERT INTO accounts VALUES (?, ?, ?, ?, ?)",
                (uuid.uuid4().hex, patient_username, hash_password(
                    os.environ.get("DEMO_PATIENT_PASSWORD", patient_password)
                ), "patient", patient_id),
            )

    @app.before_request
    def open_db():
        g.db = connect_db()

    @app.teardown_request
    def close_db(_error=None):
        connection = g.pop("db", None)
        if connection is not None:
            connection.close()

    def error(message, status=400):
        return jsonify(error=message), status

    def current_account():
        account_id = session.get("account_id")
        if not account_id:
            return None
        return g.db.execute(
            "SELECT id, username, role, patient_id FROM accounts WHERE id = ?", (account_id,)
        ).fetchone()

    def require_role(*roles):
        account = current_account()
        if account is None:
            return None, error("Please sign in to continue.", 401)
        if account["role"] not in roles:
            return None, error("You do not have permission to access this resource.", 403)
        return account, None

    @app.before_request
    def protect_mutations():
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            token = session.get("csrf_token")
            if not token or not hmac.compare_digest(
                token, request.headers.get("X-CSRF-Token", "")
            ):
                return error("Your session token has expired. Refresh the page and try again.", 403)

    @app.route("/")
    def index():
        session.setdefault("csrf_token", secrets.token_urlsafe(32))
        return render_template("index.html", csrf_token=session["csrf_token"])

    @app.get("/api/me")
    def me():
        account = current_account()
        if account is None:
            session.setdefault("csrf_token", secrets.token_urlsafe(32))
            return jsonify(user=None, csrfToken=session["csrf_token"])
        return jsonify(user={
            "username": account["username"], "role": account["role"],
            "patientId": account["patient_id"],
        }, csrfToken=session["csrf_token"])

    @app.post("/api/login")
    def login():
        payload = request.get_json(silent=True) or {}
        username, password = payload.get("username"), payload.get("password")
        if not isinstance(username, str) or not isinstance(password, str):
            return error("Enter your username and password.")
        selected_role = payload.get("role")
        if selected_role not in {"doctor", "patient"}:
            return error("Choose whether you are signing in as a doctor or patient.")
        account = g.db.execute(
            "SELECT id, username, password_hash, role, patient_id "
            "FROM accounts WHERE username = ?",
            (username.strip().lower(),),
        ).fetchone()
        if account is None or not verify_password(password, account["password_hash"]):
            return error("The username or password is incorrect.", 401)
        if account["role"] != selected_role:
            return error("The selected account type does not match these credentials.", 403)
        session.clear()
        session["account_id"] = account["id"]
        session["csrf_token"] = secrets.token_urlsafe(32)
        return jsonify(user={
            "username": account["username"], "role": account["role"],
            "patientId": account["patient_id"],
        })

    @app.post("/api/logout")
    def logout():
        session.clear()
        session["csrf_token"] = secrets.token_urlsafe(32)
        return jsonify(ok=True, csrfToken=session["csrf_token"])

    @app.get("/api/patients")
    def list_patients():
        account, denied = require_role("doctor")
        if denied:
            return denied
        records = g.db.execute(
            "SELECT p.id, p.encrypted_record FROM patients p "
            "JOIN accounts a ON a.patient_id = p.id WHERE a.role = 'patient' ORDER BY p.id"
        ).fetchall()
        search = request.args.get("q", "").strip().casefold()
        patients = []
        for row in records:
            record = _decrypt_patient(app.config["ENCRYPTION_KEY"], row["encrypted_record"])
            if not search or search in " ".join(
                str(record.get(key, "")) for key in ("firstName", "lastName", "diagnosis")
            ).casefold():
                patients.append({"id": row["id"], **record})
        return jsonify(patients=patients)

    @app.post("/api/patients")
    def add_patient():
        account, denied = require_role("doctor")
        if denied:
            return denied
        try:
            record = _validate_patient(request.get_json(silent=True), include_account=True)
        except ValueError as validation_error:
            return error(str(validation_error))
        if g.db.execute("SELECT 1 FROM accounts WHERE username = ?", (record["username"],)).fetchone():
            return error("That username is already in use.")
        patient_id = uuid.uuid4().hex
        account_id = uuid.uuid4().hex
        password = record.pop("password")
        username = record.pop("username")
        try:
            g.db.execute(
                "INSERT INTO patients VALUES (?, ?)",
                (patient_id, _encrypted_patient(app.config["ENCRYPTION_KEY"], record)),
            )
            g.db.execute(
                "INSERT INTO accounts VALUES (?, ?, ?, 'patient', ?)",
                (account_id, username, hash_password(password), patient_id),
            )
            g.db.commit()
        except sqlite3.IntegrityError:
            g.db.rollback()
            return error("That username is already in use.")
        return jsonify(patient={"id": patient_id, **record}, username=username), 201

    @app.get("/api/patients/<patient_id>")
    def get_patient(patient_id):
        account, denied = require_role("doctor", "patient")
        if denied:
            return denied
        if account["role"] == "patient" and account["patient_id"] != patient_id:
            return error("You do not have permission to access this patient record.", 403)
        row = g.db.execute(
            "SELECT encrypted_record FROM patients WHERE id = ?", (patient_id,)
        ).fetchone()
        if row is None:
            return error("Patient record not found.", 404)
        return jsonify(patient={"id": patient_id, **_decrypt_patient(
            app.config["ENCRYPTION_KEY"], row["encrypted_record"]
        )})

    @app.put("/api/patients/<patient_id>")
    def update_patient(patient_id):
        account, denied = require_role("doctor")
        if denied:
            return denied
        row = g.db.execute(
            "SELECT id FROM patients WHERE id = ?", (patient_id,)
        ).fetchone()
        if row is None:
            return error("Patient record not found.", 404)
        try:
            record = _validate_patient(request.get_json(silent=True))
        except ValueError as validation_error:
            return error(str(validation_error))
        g.db.execute(
            "UPDATE patients SET encrypted_record = ? WHERE id = ?",
            (_encrypted_patient(app.config["ENCRYPTION_KEY"], record), patient_id),
        )
        g.db.commit()
        return jsonify(patient={"id": patient_id, **record})

    @app.post("/api/sdes/encrypt")
    def sdes_encrypt():
        account, denied = require_role("doctor")
        if denied:
            return denied
        payload = request.get_json(silent=True) or {}
        text, key = payload.get("text"), payload.get("key")
        if not isinstance(text, str) or len(text) > 500:
            return error("Enter text of up to 500 characters.")
        if not isinstance(key, str):
            return error("The S-DES key must contain exactly 10 binary digits.")
        try:
            _keys(key)
        except ValueError as validation_error:
            return error(str(validation_error))
        encrypted = bytes(sdes_crypt_byte(value, key) for value in text.encode("utf-8"))
        return jsonify(ciphertext=encrypted.hex())

    @app.post("/api/sdes/decrypt")
    def sdes_decrypt():
        account, denied = require_role("doctor")
        if denied:
            return denied
        payload = request.get_json(silent=True) or {}
        ciphertext, key = payload.get("ciphertext"), payload.get("key")
        if not isinstance(ciphertext, str) or len(ciphertext) > 1000:
            return error("Enter valid hexadecimal ciphertext.")
        if not isinstance(key, str):
            return error("The S-DES key must contain exactly 10 binary digits.")
        try:
            _keys(key)
            encrypted = bytes.fromhex(ciphertext)
            decrypted = bytes(sdes_crypt_byte(value, key, decrypt=True) for value in encrypted)
            text = decrypted.decode("utf-8")
        except ValueError as validation_error:
            return error(str(validation_error))
        except UnicodeDecodeError:
            return error("Ciphertext did not decrypt to valid UTF-8. Check the key and input.")
        return jsonify(text=text)

    @app.post("/api/sdes/verify")
    def sdes_verify():
        account, denied = require_role("doctor")
        if denied:
            return denied
        payload = request.get_json(silent=True) or {}
        try:
            key = payload.get("key")
            _keys(key)
            plaintext = payload.get("text")
            if not isinstance(plaintext, str) or len(plaintext) > 500:
                return error("Enter text of up to 500 characters.")
            encoded = plaintext.encode("utf-8")
            encrypted = bytes(sdes_crypt_byte(value, key) for value in encoded)
            recovered = bytes(
                sdes_crypt_byte(value, key, decrypt=True) for value in encrypted
            )
        except ValueError as validation_error:
            return error(str(validation_error))
        return jsonify(verified=hmac.compare_digest(encoded, recovered))

    @app.get("/api/performance")
    def performance():
        account, denied = require_role("doctor")
        if denied:
            return denied
        sample = b"MedSecure performance sample"
        key = "1010000010"
        start = time.perf_counter()
        encrypted = bytes(sdes_crypt_byte(value, key) for value in sample)
        sdes_encryption_ms = (time.perf_counter() - start) * 1000
        start = time.perf_counter()
        bytes(sdes_crypt_byte(value, key, decrypt=True) for value in encrypted)
        sdes_decryption_ms = (time.perf_counter() - start) * 1000
        return jsonify(sampleBytes=len(sample), timings={
            "S-DES": {"encryptMs": round(sdes_encryption_ms, 4),
                      "decryptMs": round(sdes_decryption_ms, 4)},
        })

    @app.errorhandler(500)
    def internal_error(_error):
        app.logger.exception("Unhandled server error")
        return error("Something went wrong. Please try again.", 500)

    initialize_db()
    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "").lower() == "true")
