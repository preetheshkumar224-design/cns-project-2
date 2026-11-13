# MedSecure

A compact Flask healthcare-management demo. Locally, it uses SQLite; on Vercel,
it uses Neon PostgreSQL for persistent account and encrypted-record storage.
Doctors can register patients, manage encrypted records, search records, use
the S-DES demonstration tools, and compare encryption timings. Patients can
only view the record linked to their own account.

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
seeding. Local SQLite records and generated signing and encryption keys live
under `instance/`. Keep these files backed up and private; losing
`records.key` makes encrypted records unreadable.

## Deploy to Vercel with Neon

1. Create a Neon PostgreSQL database and copy its connection string. Add it to
   the Vercel project's **Production** environment variables as `DATABASE_URL`.
   A Neon pooled connection string is suitable for the serverless app.
2. Set `SECRET_KEY` and `ENCRYPTION_KEY` as Vercel environment variables. Both
   values must remain unchanged across deployments and provide at least 32
   bytes of key material. For a new installation, use independent,
   randomly-generated secrets. For example, generate a Flask key with
   `python -c "import secrets; print(secrets.token_urlsafe(48))"` and an
   encryption key with
   `python -c "import secrets,base64; print('base64:'+base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"`.
3. To preserve records from an existing local installation, transfer the
   existing key files into the Vercel environment as base64 values. In
   PowerShell, run these commands locally and add the printed values (including
   the `base64:` prefix) as `SECRET_KEY` and `ENCRYPTION_KEY`:

   ```powershell
   "base64:$([Convert]::ToBase64String([IO.File]::ReadAllBytes('instance\session.secret')))"
   "base64:$([Convert]::ToBase64String([IO.File]::ReadAllBytes('instance\records.key')))"
   ```

   This encodes each file's exact bytes; the app decodes the values before use.
   Never regenerate or rotate `ENCRYPTION_KEY` while records encrypted with it
   remain in the database. A changed `SECRET_KEY` signs new sessions and
   requires users to sign in again.
4. Set `DEMO_DATA=false` before the first deployment unless you intentionally
   want demo accounts. Set `COOKIE_SECURE=true` when using HTTPS (it defaults
   to true on Vercel). Vercel supplies the `VERCEL` environment flag, which
   makes the app require PostgreSQL and both secrets rather than falling back
   to local files.
5. To copy an existing SQLite database into Neon, install the requirements
   locally, set `DATABASE_URL` in the shell to the Neon connection string, then
   run:

   ```powershell
   python migrate_sqlite_to_postgres.py
   ```

   The script copies account hashes and encrypted record bytes as-is, preserves
   IDs, and leaves the SQLite database untouched. It is safe to rerun for rows
   already copied. Configure the same `ENCRYPTION_KEY` in Vercel as was used by
   the source app. Keep the local database and key files as a backup.
6. Deploy the project from Vercel. `vercel.json` configures the Flask Python
   function and includes the `templates/` and `static/` assets.

Vercel/Neon setup is manual: create the database, add the environment variables
to each Vercel environment you use (Production, Preview, Development), and
deploy. Do not commit credentials or local key files.

## Security notes

This is a fictional-data academic demo, **not a production electronic health
record system**. Patient record JSON is encrypted at rest with a secret key
supplied through environment configuration in deployment; passwords are salted
and hashed; sessions, CSRF checks, validation, and server-side role and patient
ownership checks protect the demo endpoints. S-DES is provided as an
educational, reversible block-cipher demonstration only. Its small key and
block sizes make it unsuitable for medical records or any real personal data.
The timing screen is an illustrative local sample, not a cryptographic
benchmark.

## Tests

```powershell
python -m unittest discover -s tests -v
```
