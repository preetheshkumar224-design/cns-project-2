# MedSecure

A compact Flask and SQLite academic project for fictional patient records. The
doctor can register patients, manage encrypted records, search records, use the
S-DES demonstration tools, and compare encryption timings. Patients can only
view the record linked to their own account.

## Run locally

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

The local demo account credentials are:

| Role | Username | Password |
| --- | --- | --- |
| Doctor | `doctor@medsecure.test` | `DoctorDemo2026!` |
| Patient | `patient@medsecure.test` | `PatientDemo2026!` |

Set `DEMO_DOCTOR_PASSWORD` and `DEMO_PATIENT_PASSWORD` before the first run to
choose different demo passwords; set `DEMO_DATA=false` to disable demo account
seeding. SQLite records and locally generated signing and encryption keys live
under `instance/`. Keep these keys backed up and private; losing `records.key`
makes encrypted records unreadable. Set `COOKIE_SECURE=true` when serving the
application over HTTPS.

## Security notes

This is a fictional-data academic demo, **not a production electronic health
record system**. Patient record JSON is encrypted at rest using Fernet and a
local key; passwords are salted and hashed; sessions, CSRF checks, validation,
and server-side role and patient ownership checks protect the demo endpoints.
S-DES is provided as an educational, reversible block-cipher demonstration
only. Its small key and block sizes make it unsuitable for medical records or
any real personal data. The timing screen is an illustrative local sample, not
a cryptographic benchmark.

## Tests

```powershell
python -m unittest discover -s tests -v
```
