# MedSecure

A responsive healthcare-management demo built with Node.js, Express, and
PostgreSQL on Vercel. Doctors can manage patient profiles and records; patients
can only view the record linked to their account. The interface works on
desktop and mobile browsers.

## Run locally

Install Node.js 26, then from the repository root run:

```powershell
npm install
npm start
```

Open `http://localhost:5000`. Locally, the app uses Node's built-in SQLite
support and stores the database and generated keys in `instance/`. The demo
accounts are:

| Role | Username | Password |
| --- | --- | --- |
| Doctor | `doctor@medsecure.test` | `DoctorDemo2026!` |
| Patient | `patient@medsecure.test` | `PatientDemo2026!` |

Set `DEMO_DOCTOR_PASSWORD` and `DEMO_PATIENT_PASSWORD` before the first run to
choose different demo passwords. Set `DEMO_DATA=false` to disable demo account
seeding. Local secrets are generated automatically; keep `instance/` private
and backed up.

## Deploy to Vercel with Neon

1. Create a Neon PostgreSQL database and add its connection string to the
   Vercel project's Production environment as `DATABASE_URL`.
2. Add `SECRET_KEY` and `ENCRYPTION_KEY` to Vercel. Both must stay stable across
   deployments and contain at least 32 bytes. Generate independent secrets
   with Node.js:

   ```powershell
   node -e "console.log(require('node:crypto').randomBytes(48).toString('base64url'))"
   node -e "console.log('base64:'+require('node:crypto').randomBytes(32).toString('base64url'))"
   ```

3. To preserve an existing installation, configure the same `ENCRYPTION_KEY`
   used by the old app. For the existing Flask setup, the exact key files can
   be encoded in PowerShell and set as environment values:

   ```powershell
   "base64:$([Convert]::ToBase64String([IO.File]::ReadAllBytes('instance\records.key')))"
   "base64:$([Convert]::ToBase64String([IO.File]::ReadAllBytes('instance\session.secret')))"
   ```

   Set the first value as `ENCRYPTION_KEY` and the second as `SECRET_KEY`.
   This preserves record decryption. Users will need to sign in again because
   the Node app uses its own signed session cookie.
4. Set `DEMO_DATA=false` unless demo accounts are wanted. Set `COOKIE_SECURE=true`
   for HTTPS; it defaults to true on Vercel. Add the environment variables to
   each Vercel environment you use.
5. To copy an existing SQLite database into Neon, set `DATABASE_URL` in the
   PowerShell session and run:

   ```powershell
   npm install
   npm run migrate -- --source instance\patients.sqlite3
   ```

   The migration copies account hashes and encrypted record bytes without
   changing the source database. It is safe to rerun for rows already copied.
   Keep the source database and its encryption key backed up.
6. Import the repository into Vercel with the repository root as the project
   root. Vercel uses Node.js 26, serves `public/` assets, and deploys
   `api/[...path].js` as the API function. No Python runtime is required.

## Security notes

This is a fictional-data academic demo, **not a production electronic health
record system**. Patient record JSON is encrypted at rest with a secret key
supplied through environment configuration in deployment; passwords are salted
and hashed; signed sessions, CSRF checks, validation, and server-side role and
patient ownership checks protect the demo endpoints. S-DES is an educational
cipher only and is unsuitable for medical records or real personal data.

## Tests

```powershell
npm test
```
