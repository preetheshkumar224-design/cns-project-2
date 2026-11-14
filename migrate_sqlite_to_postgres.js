"use strict";

const path = require("node:path");
const { DatabaseSync } = require("node:sqlite");
const { Client } = require("pg");

async function migrate(sourcePath, databaseUrl) {
  const source = new DatabaseSync(sourcePath, { readOnly: true });
  let accounts;
  let patients;
  try {
    accounts = source.prepare(
      "SELECT id, username, password_hash, role, patient_id FROM accounts",
    ).all();
    patients = source.prepare("SELECT id, encrypted_record FROM patients").all();
  } finally {
    source.close();
  }

  const destination = new Client({
    connectionString: databaseUrl,
    ssl: { rejectUnauthorized: false },
    connectionTimeoutMillis: 10_000,
  });
  await destination.connect();
  try {
    await destination.query("BEGIN");
    await destination.query(`
      CREATE TABLE IF NOT EXISTS accounts (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('doctor', 'patient')),
        patient_id TEXT
      );
      CREATE TABLE IF NOT EXISTS patients (
        id TEXT PRIMARY KEY,
        encrypted_record BYTEA NOT NULL
      )
    `);
    for (const patient of patients) {
      await destination.query(
        "INSERT INTO patients (id, encrypted_record) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING",
        [patient.id, Buffer.from(patient.encrypted_record)],
      );
    }
    for (const account of accounts) {
      await destination.query(
        "INSERT INTO accounts (id, username, password_hash, role, patient_id) " +
          "VALUES ($1, $2, $3, $4, $5) ON CONFLICT (id) DO NOTHING",
        [account.id, account.username, account.password_hash, account.role, account.patient_id],
      );
    }
    await destination.query("COMMIT");
  } catch (error) {
    await destination.query("ROLLBACK");
    throw error;
  } finally {
    await destination.end();
  }
  return { accounts: accounts.length, patients: patients.length };
}

async function main() {
  const sourceIndex = process.argv.indexOf("--source");
  const sourcePath = sourceIndex >= 0
    ? path.resolve(process.argv[sourceIndex + 1])
    : path.join(__dirname, "instance", "patients.sqlite3");
  const databaseUrl = process.env.DATABASE_URL || process.env.POSTGRES_URL;
  if (!databaseUrl) throw new Error("Set DATABASE_URL (or POSTGRES_URL) to the Neon connection string.");
  const result = await migrate(sourcePath, databaseUrl);
  console.log(`Processed ${result.accounts} account rows and ${result.patients} encrypted patient rows.`);
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}

module.exports = { migrate };
