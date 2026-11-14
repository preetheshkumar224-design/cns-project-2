"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { DatabaseSync } = require("node:sqlite");
const express = require("express");

const BASE_DIR = __dirname;
const INSTANCE_DIR = path.join(BASE_DIR, "instance");
const PUBLIC_DIR = path.join(BASE_DIR, "public");
const DEMO_DOCTOR = ["doctor@medsecure.test", "DoctorDemo2026!"];
const DEMO_PATIENT = ["patient@medsecure.test", "PatientDemo2026!"];
const PASSWORD_ITERATIONS = 260_000;
const SESSION_COOKIE = "medsecure_session";

const P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6];
const P8 = [6, 3, 7, 4, 8, 5, 10, 9];
const IP = [2, 6, 3, 1, 4, 8, 5, 7];
const IP_INVERSE = [4, 1, 3, 5, 7, 2, 8, 6];
const EP = [4, 1, 2, 3, 2, 3, 4, 1];
const P4 = [2, 4, 3, 1];
const S0 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]];
const S1 = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]];

let sqlite;
let pool;
let databaseReady;
let encryptionKey;
let signingKey;
let databaseUrl;
let isVercel;

function permute(bits, positions) {
  return positions.map((position) => bits[position - 1]).join("");
}

function leftShift(bits, amount) {
  return bits.slice(amount) + bits.slice(0, amount);
}

function deriveSdesKeys(key) {
  if (typeof key !== "string" || !/^[01]{10}$/.test(key)) {
    throw new Error("The S-DES key must contain exactly 10 binary digits.");
  }
  const permuted = permute(key, P10);
  let left = leftShift(permuted.slice(0, 5), 1);
  let right = leftShift(permuted.slice(5), 1);
  const first = permute(left + right, P8);
  left = leftShift(left, 2);
  right = leftShift(right, 2);
  return [first, permute(left + right, P8)];
}

function sbox(bits, box) {
  const row = Number.parseInt(bits[0] + bits[3], 2);
  const column = Number.parseInt(bits.slice(1, 3), 2);
  return box[row][column].toString(2).padStart(2, "0");
}

function roundFunction(bits, key) {
  const left = bits.slice(0, 4);
  const right = bits.slice(4);
  const mixed = (Number.parseInt(permute(right, EP), 2) ^ Number.parseInt(key, 2))
    .toString(2).padStart(8, "0");
  const substituted = sbox(mixed.slice(0, 4), S0) + sbox(mixed.slice(4), S1);
  const result = (Number.parseInt(left, 2) ^ Number.parseInt(permute(substituted, P4), 2))
    .toString(2).padStart(4, "0");
  return result + right;
}

function sdesCryptByte(value, key, decrypt = false) {
  const [first, second] = deriveSdesKeys(key);
  let bits = permute(value.toString(2).padStart(8, "0"), IP);
  bits = roundFunction(bits, decrypt ? second : first);
  bits = bits.slice(4) + bits.slice(0, 4);
  bits = roundFunction(bits, decrypt ? first : second);
  return Number.parseInt(permute(bits, IP_INVERSE), 2);
}

function passwordHash(password) {
  const salt = crypto.randomBytes(16);
  const digest = crypto.pbkdf2Sync(password, salt, PASSWORD_ITERATIONS, 32, "sha256");
  return `${salt.toString("hex")}$${digest.toString("hex")}`;
}

function verifyPassword(password, encoded) {
  const [saltHex, digestHex, extra] = encoded.split("$");
  if (extra !== undefined || !/^[\da-f]{32}$/i.test(saltHex) ||
      !/^[\da-f]{64}$/i.test(digestHex)) return false;
  const actual = crypto.pbkdf2Sync(password, Buffer.from(saltHex, "hex"), PASSWORD_ITERATIONS, 32, "sha256");
  return crypto.timingSafeEqual(actual, Buffer.from(digestHex, "hex"));
}

function envSecret(name) {
  const value = process.env[name];
  if (value === undefined) return null;
  if (!value.startsWith("base64:")) return Buffer.from(value, "utf8");
  const encoded = value.slice(7);
  if (!/^[A-Za-z0-9+/_-]*={0,2}$/.test(encoded)) {
    throw new Error(`${name} must contain valid base64 after the base64: prefix.`);
  }
  const decoded = Buffer.from(encoded.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  const normalized = encoded.replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
  if (decoded.toString("base64").replace(/=+$/, "") !== normalized) {
    throw new Error(`${name} must contain valid base64 after the base64: prefix.`);
  }
  return decoded;
}

function persistentSecret(filePath) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  try {
    const descriptor = fs.openSync(filePath, "wx", 0o600);
    try {
      fs.writeSync(descriptor, crypto.randomBytes(32));
    } finally {
      fs.closeSync(descriptor);
    }
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
  }
  return fs.readFileSync(filePath);
}

function secretBytes(secret) {
  return Buffer.isBuffer(secret) ? secret : Buffer.from(String(secret), "utf8");
}

function sdesKeyForSecret(secret) {
  const digest = crypto.createHash("sha256").update(secretBytes(secret)).digest();
  return [...digest.subarray(0, 2)]
    .map((byte) => byte.toString(2).padStart(8, "0")).join("").slice(0, 10);
}

function encryptPatient(secret, patient) {
  const key = sdesKeyForSecret(secret);
  return Buffer.from(Buffer.from(pythonJsonStringify(patient), "utf8")
    .map((value) => sdesCryptByte(value, key)));
}

function decryptPatient(secret, encrypted) {
  try {
    const key = sdesKeyForSecret(secret);
    const bytes = Buffer.from(encrypted).map((value) => sdesCryptByte(value, key, true));
    return JSON.parse(bytes.toString("utf8"));
  } catch (error) {
    throw new Error("A patient record could not be decrypted; check the encryption key.", { cause: error });
  }
}

function pythonJsonStringify(value) {
  return JSON.stringify(value).replace(/[\u007f-\uffff]/g, (character) =>
    `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`);
}

function validatePatient(payload, includeAccount = false) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("Submit a valid patient record.");
  }
  const values = {};
  for (const field of ["firstName", "lastName", "sex", "diagnosis", "medicalHistory"]) {
    if (typeof payload[field] !== "string" || !payload[field].trim()) {
      throw new Error(`${field} is required.`);
    }
    values[field] = payload[field].trim().slice(0, 2000);
  }
  const parseInteger = (value) => {
    if (typeof value === "string" && !/^[+-]?\d+$/.test(value.trim())) return Number.NaN;
    return Number(value);
  };
  const age = parseInteger(payload.age);
  const heartRate = parseInteger(payload.heartRate);
  const temperature = Number(payload.temperature);
  const oxygenSaturation = parseInteger(payload.oxygenSaturation);
  if (![age, heartRate, temperature, oxygenSaturation].every(Number.isFinite) ||
      !Number.isInteger(age) || !Number.isInteger(heartRate) || !Number.isInteger(oxygenSaturation)) {
    throw new Error("Age and vital signs must be valid numbers.");
  }
  values.age = age;
  values.heartRate = heartRate;
  values.temperature = Math.round((temperature + Number.EPSILON) * 10) / 10;
  values.oxygenSaturation = oxygenSaturation;
  if (age < 1 || age > 120) throw new Error("Age must be between 1 and 120.");
  if (heartRate < 20 || heartRate > 250) throw new Error("Heart rate must be between 20 and 250 bpm.");
  if (temperature < 30 || temperature > 45) throw new Error("Temperature must be between 30 and 45 °C.");
  if (oxygenSaturation < 50 || oxygenSaturation > 100) {
    throw new Error("Oxygen saturation must be between 50 and 100%.");
  }
  if (includeAccount) {
    const username = payload.username;
    const password = payload.password;
    if (typeof username !== "string" || username.trim().length < 3 || username.trim().length > 64) {
      throw new Error("Username must contain between 3 and 64 characters.");
    }
    if (typeof password !== "string" || password.length < 10) {
      throw new Error("The patient's initial password must contain at least 10 characters.");
    }
    values.username = username.trim().toLowerCase();
    values.password = password;
  }
  values.updatedAt = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  return values;
}

function convertPlaceholders(statement) {
  let index = 0;
  return statement.replace(/\?/g, () => `$${++index}`);
}

async function queryAll(statement, parameters = [], client = null) {
  if (databaseUrl) {
    const result = await (client || pool).query(convertPlaceholders(statement), parameters);
    return result.rows;
  }
  return sqlite.prepare(statement).all(...parameters);
}

async function queryOne(statement, parameters = [], client = null) {
  if (databaseUrl) {
    const result = await (client || pool).query(convertPlaceholders(statement), parameters);
    return result.rows[0] || null;
  }
  return sqlite.prepare(statement).get(...parameters) || null;
}

async function execute(statement, parameters = [], client = null) {
  if (databaseUrl) {
    return (await (client || pool).query(convertPlaceholders(statement), parameters)).rowCount;
  }
  return sqlite.prepare(statement).run(...parameters).changes;
}

async function transaction(callback) {
  if (databaseUrl) {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const result = await callback(client);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }
  sqlite.exec("BEGIN IMMEDIATE");
  try {
    const result = await callback(null);
    sqlite.exec("COMMIT");
    return result;
  } catch (error) {
    sqlite.exec("ROLLBACK");
    throw error;
  }
}

function createDatabase() {
  isVercel = process.env.VERCEL === "1";
  databaseUrl = process.env.DATABASE_URL || process.env.POSTGRES_URL || null;
  if (isVercel && !databaseUrl) {
    throw new Error("Set DATABASE_URL to your Neon PostgreSQL connection string on Vercel.");
  }
  const envSigningKey = envSecret("SECRET_KEY");
  const envEncryptionKey = envSecret("ENCRYPTION_KEY");
  if (isVercel && envSigningKey === null) {
    throw new Error("Set SECRET_KEY in the Vercel project environment variables.");
  }
  if (isVercel && envEncryptionKey === null) {
    throw new Error("Set ENCRYPTION_KEY in the Vercel project environment variables.");
  }
  signingKey = envSigningKey || persistentSecret(path.join(INSTANCE_DIR, "session.secret"));
  encryptionKey = envEncryptionKey || persistentSecret(path.join(INSTANCE_DIR, "records.key"));
  for (const [name, key] of [["SECRET_KEY", signingKey], ["ENCRYPTION_KEY", encryptionKey]]) {
    if (secretBytes(key).length < 32) throw new Error(`${name} must contain at least 32 bytes of key material.`);
  }
  if (databaseUrl) {
    const { Pool } = require("pg");
    pool = new Pool({
      connectionString: databaseUrl,
      ssl: { rejectUnauthorized: false },
      max: 1,
      idleTimeoutMillis: 10_000,
      connectionTimeoutMillis: 10_000,
    });
  } else {
    fs.mkdirSync(INSTANCE_DIR, { recursive: true });
    const databasePath = process.env.DATABASE_PATH || path.join(INSTANCE_DIR, "patients.sqlite3");
    sqlite = new DatabaseSync(databasePath);
    sqlite.exec("PRAGMA foreign_keys = ON");
  }
}

async function initializeDatabase() {
  if (!databaseReady) {
    databaseReady = (async () => {
      createDatabase();
      const binaryType = databaseUrl ? "BYTEA" : "BLOB";
      if (databaseUrl) {
        await pool.query(`
          CREATE TABLE IF NOT EXISTS accounts (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('doctor', 'patient')),
            patient_id TEXT
          );
          CREATE TABLE IF NOT EXISTS patients (
            id TEXT PRIMARY KEY,
            encrypted_record ${binaryType} NOT NULL
          )
        `);
      } else {
        sqlite.exec(`
          CREATE TABLE IF NOT EXISTS accounts (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('doctor', 'patient')),
            patient_id TEXT
          );
          CREATE TABLE IF NOT EXISTS patients (
            id TEXT PRIMARY KEY,
            encrypted_record ${binaryType} NOT NULL
          )
        `);
      }
      if ((process.env.DEMO_DATA || (isVercel ? "false" : "true")).toLowerCase() === "true") {
        await seedDemoData();
      }
    })();
  }
  return databaseReady;
}

async function seedDemoData() {
  if (!(await queryOne("SELECT id FROM accounts WHERE username = ?", [DEMO_DOCTOR[0]]))) {
    await execute("INSERT INTO accounts VALUES (?, ?, ?, ?, NULL)", [
      crypto.randomUUID().replace(/-/g, ""),
      DEMO_DOCTOR[0],
      passwordHash(process.env.DEMO_DOCTOR_PASSWORD || DEMO_DOCTOR[1]),
      "doctor",
    ]);
  }
  if (!(await queryOne("SELECT id FROM accounts WHERE username = ?", [DEMO_PATIENT[0]]))) {
    const patientId = crypto.randomUUID().replace(/-/g, "");
    const record = {
      firstName: "Maya",
      lastName: "Chen",
      age: 34,
      sex: "Female",
      diagnosis: "Seasonal asthma",
      medicalHistory: "Mild asthma; no known allergies.",
      heartRate: 72,
      temperature: 36.7,
      oxygenSaturation: 98,
      updatedAt: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    };
    await transaction(async (client) => {
      await execute("INSERT INTO patients VALUES (?, ?)", [
        patientId, encryptPatient(encryptionKey, record),
      ], client);
      await execute("INSERT INTO accounts VALUES (?, ?, ?, 'patient', ?)", [
        crypto.randomUUID().replace(/-/g, ""),
        DEMO_PATIENT[0],
        passwordHash(process.env.DEMO_PATIENT_PASSWORD || DEMO_PATIENT[1]),
        patientId,
      ], client);
    });
  }
}

function randomToken() {
  return crypto.randomBytes(32).toString("base64url");
}

function signSession(session) {
  const payload = Buffer.from(JSON.stringify(session)).toString("base64url");
  const signature = crypto.createHmac("sha256", secretBytes(signingKey)).update(payload).digest("base64url");
  return `${payload}.${signature}`;
}

function readSession(cookieHeader) {
  const cookie = (cookieHeader || "").split(";").map((part) => part.trim())
    .find((part) => part.startsWith(`${SESSION_COOKIE}=`));
  if (cookie) {
    const value = cookie.slice(SESSION_COOKIE.length + 1);
    const separator = value.lastIndexOf(".");
    if (separator > 0) {
      const payload = value.slice(0, separator);
      const expected = crypto.createHmac("sha256", secretBytes(signingKey)).update(payload).digest();
      try {
        const actual = Buffer.from(value.slice(separator + 1), "base64url");
        if (actual.length === expected.length && crypto.timingSafeEqual(actual, expected)) {
          const parsed = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
          if (parsed && typeof parsed === "object" && typeof parsed.csrf_token === "string") {
            return parsed;
          }
        }
      } catch {
        // Malformed cookies start a fresh session.
      }
    }
  }
  return { csrf_token: randomToken() };
}

function setSessionCookie(res, session) {
  const parts = [
    `${SESSION_COOKIE}=${signSession(session)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
  ];
  if ((process.env.COOKIE_SECURE || (isVercel ? "true" : "")).toLowerCase() === "true") {
    parts.push("Secure");
  }
  res.setHeader("Set-Cookie", parts.join("; "));
}

function error(res, message, status = 400) {
  return res.status(status).json({ error: message });
}

async function currentAccount(req) {
  if (!req.session.account_id) return null;
  return queryOne(
    "SELECT id, username, role, patient_id FROM accounts WHERE id = ?",
    [req.session.account_id],
  );
}

async function requireRole(req, res, ...roles) {
  const account = await currentAccount(req);
  if (!account) {
    error(res, "Please sign in to continue.", 401);
    return null;
  }
  if (!roles.includes(account.role)) {
    error(res, "You do not have permission to access this resource.", 403);
    return null;
  }
  return account;
}

function accountResponse(account) {
  return {
    username: account.username,
    role: account.role,
    patientId: account.patient_id,
  };
}

function isDuplicateError(cause) {
  return cause.code === "23505" || cause.code === "ERR_SQLITE_CONSTRAINT_UNIQUE" ||
    cause.code === "ERR_SQLITE_CONSTRAINT_PRIMARYKEY";
}

function asyncRoute(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

const app = express();
app.disable("x-powered-by");
app.use((req, _res, next) => {
  if (req.url === "/api" || req.url.startsWith("/api/")) {
    req.url = req.url.slice(4) || "/";
  }
  next();
});
app.use(express.json({ limit: "1mb" }));
app.use(asyncRoute(async (req, res, next) => {
  await initializeDatabase();
  req.session = readSession(req.headers.cookie);
  req.saveSession = () => setSessionCookie(res, req.session);
  next();
}));
app.use((req, res, next) => {
  if (["POST", "PUT", "PATCH", "DELETE"].includes(req.method)) {
    const token = req.headers["x-csrf-token"];
    const expected = Buffer.from(req.session.csrf_token || "");
    const supplied = Buffer.from(typeof token === "string" ? token : "");
    if (!expected.length || expected.length !== supplied.length ||
        !crypto.timingSafeEqual(expected, supplied)) {
      req.saveSession();
      return error(res, "Your session token has expired. Refresh the page and try again.", 403);
    }
  }
  next();
});
app.use((req, res, next) => {
  const end = res.end;
  res.end = function endWithSession(...args) {
    if (req.session && !res.headersSent) req.saveSession();
    return end.apply(this, args);
  };
  next();
});
app.use("/static", express.static(path.join(PUBLIC_DIR, "static"), { fallthrough: false }));

app.get("/", (_req, res) => res.sendFile(path.join(PUBLIC_DIR, "index.html")));

app.get("/me", asyncRoute(async (req, res) => {
  const account = await currentAccount(req);
  res.json({ user: account ? accountResponse(account) : null, csrfToken: req.session.csrf_token });
}));

app.post("/login", asyncRoute(async (req, res) => {
  const payload = req.body || {};
  const { username, password, role } = payload;
  if (typeof username !== "string" || typeof password !== "string") {
    return error(res, "Enter your username and password.");
  }
  if (!["doctor", "patient"].includes(role)) {
    return error(res, "Choose whether you are signing in as a doctor or patient.");
  }
  const account = await queryOne(
    "SELECT id, username, password_hash, role, patient_id FROM accounts WHERE username = ?",
    [username.trim().toLowerCase()],
  );
  if (!account || !verifyPassword(password, account.password_hash)) {
    return error(res, "The username or password is incorrect.", 401);
  }
  if (account.role !== role) {
    return error(res, "The selected account type does not match these credentials.", 403);
  }
  req.session = { account_id: account.id, csrf_token: randomToken() };
  res.json({ user: accountResponse(account) });
}));

app.post("/logout", (req, res) => {
  req.session = { csrf_token: randomToken() };
  res.json({ ok: true, csrfToken: req.session.csrf_token });
});

app.get("/patients", asyncRoute(async (req, res) => {
  if (!await requireRole(req, res, "doctor")) return;
  const records = await queryAll(
    "SELECT p.id, p.encrypted_record FROM patients p " +
    "JOIN accounts a ON a.patient_id = p.id WHERE a.role = 'patient' ORDER BY p.id",
  );
  const search = String(req.query.q || "").trim().toLocaleLowerCase();
  const patients = [];
  for (const row of records) {
    const record = decryptPatient(encryptionKey, row.encrypted_record);
    const searchable = ["firstName", "lastName", "diagnosis"]
      .map((key) => String(record[key] || "")).join(" ").toLocaleLowerCase();
    if (!search || searchable.includes(search)) patients.push({ id: row.id, ...record });
  }
  res.json({ patients });
}));

app.post("/patients", asyncRoute(async (req, res) => {
  if (!await requireRole(req, res, "doctor")) return;
  let record;
  try {
    record = validatePatient(req.body, true);
  } catch (validationError) {
    return error(res, validationError.message);
  }
  if (await queryOne("SELECT 1 FROM accounts WHERE username = ?", [record.username])) {
    return error(res, "That username is already in use.");
  }
  const patientId = crypto.randomUUID().replace(/-/g, "");
  const accountId = crypto.randomUUID().replace(/-/g, "");
  const password = record.password;
  const username = record.username;
  delete record.password;
  delete record.username;
  try {
    await transaction(async (client) => {
      await execute("INSERT INTO patients VALUES (?, ?)", [
        patientId, encryptPatient(encryptionKey, record),
      ], client);
      await execute("INSERT INTO accounts VALUES (?, ?, ?, 'patient', ?)", [
        accountId, username, passwordHash(password), patientId,
      ], client);
    });
  } catch (cause) {
    if (isDuplicateError(cause)) return error(res, "That username is already in use.");
    throw cause;
  }
  res.status(201).json({ patient: { id: patientId, ...record }, username });
}));

app.get("/patients/:patientId", asyncRoute(async (req, res) => {
  const account = await requireRole(req, res, "doctor", "patient");
  if (!account) return;
  const { patientId } = req.params;
  if (account.role === "patient" && account.patient_id !== patientId) {
    return error(res, "You do not have permission to access this patient record.", 403);
  }
  const row = await queryOne("SELECT encrypted_record FROM patients WHERE id = ?", [patientId]);
  if (!row) return error(res, "Patient record not found.", 404);
  res.json({ patient: { id: patientId, ...decryptPatient(encryptionKey, row.encrypted_record) } });
}));

app.put("/patients/:patientId", asyncRoute(async (req, res) => {
  if (!await requireRole(req, res, "doctor")) return;
  const { patientId } = req.params;
  if (!await queryOne("SELECT id FROM patients WHERE id = ?", [patientId])) {
    return error(res, "Patient record not found.", 404);
  }
  let record;
  try {
    record = validatePatient(req.body);
  } catch (validationError) {
    return error(res, validationError.message);
  }
  await execute("UPDATE patients SET encrypted_record = ? WHERE id = ?", [
    encryptPatient(encryptionKey, record), patientId,
  ]);
  res.json({ patient: { id: patientId, ...record } });
}));

app.post("/sdes/encrypt", asyncRoute(async (req, res) => {
  if (!await requireRole(req, res, "doctor")) return;
  const { text, key } = req.body || {};
  if (typeof text !== "string" || text.length > 500) return error(res, "Enter text of up to 500 characters.");
  if (typeof key !== "string") return error(res, "The S-DES key must contain exactly 10 binary digits.");
  let encrypted;
  try {
    deriveSdesKeys(key);
    encrypted = Buffer.from(Buffer.from(text, "utf8").map((value) => sdesCryptByte(value, key)));
  } catch (cause) {
    return error(res, cause.message);
  }
  res.json({ ciphertext: encrypted.toString("hex") });
}));

app.post("/sdes/decrypt", asyncRoute(async (req, res) => {
  if (!await requireRole(req, res, "doctor")) return;
  const { ciphertext, key } = req.body || {};
  if (typeof ciphertext !== "string" || ciphertext.length > 1000) {
    return error(res, "Enter valid hexadecimal ciphertext.");
  }
  if (typeof key !== "string") return error(res, "The S-DES key must contain exactly 10 binary digits.");
  let encrypted;
  try {
    deriveSdesKeys(key);
    if (!/^(?:[\da-f]{2})*$/i.test(ciphertext)) throw new Error("Non-hexadecimal digit found");
    encrypted = Buffer.from(ciphertext, "hex");
  } catch (cause) {
    if (cause.message.includes("10 binary digits")) return error(res, cause.message);
    return error(res, "Enter valid hexadecimal ciphertext.");
  }
  const decrypted = Buffer.from(encrypted.map((value) => sdesCryptByte(value, key, true)));
  try {
    return res.json({ text: new TextDecoder("utf-8", { fatal: true }).decode(decrypted) });
  } catch {
    return error(res, "Ciphertext did not decrypt to valid UTF-8. Check the key and input.");
  }
}));

app.post("/sdes/verify", asyncRoute(async (req, res) => {
  if (!await requireRole(req, res, "doctor")) return;
  const { key, text } = req.body || {};
  try {
    deriveSdesKeys(key);
  } catch (cause) {
    return error(res, cause.message);
  }
  if (typeof text !== "string" || text.length > 500) return error(res, "Enter text of up to 500 characters.");
  const encoded = Buffer.from(text, "utf8");
  const encrypted = Buffer.from(encoded.map((value) => sdesCryptByte(value, key)));
  const recovered = Buffer.from(encrypted.map((value) => sdesCryptByte(value, key, true)));
  res.json({ verified: encoded.equals(recovered) });
}));

app.post("/sdes/demo", asyncRoute(async (req, res) => {
  if (!await requireRole(req, res, "doctor")) return;
  const { key, patientId } = req.body || {};
  if (typeof key !== "string") return error(res, "The S-DES key must contain exactly 10 binary digits.");
  try {
    deriveSdesKeys(key);
  } catch (cause) {
    return error(res, cause.message);
  }
  let selectedPatientId = patientId;
  let row;
  if (typeof selectedPatientId !== "string" || !selectedPatientId.trim()) {
    row = await queryOne(
      "SELECT p.id, p.encrypted_record FROM patients p " +
      "JOIN accounts a ON a.patient_id = p.id WHERE a.role = 'patient' ORDER BY p.id LIMIT 1",
    );
    if (!row) return error(res, "No patient record available for the encryption demo.", 404);
    selectedPatientId = row.id;
  } else {
    row = await queryOne("SELECT encrypted_record FROM patients WHERE id = ?", [selectedPatientId]);
    if (!row) return error(res, "Patient record not found.", 404);
  }
  const record = decryptPatient(encryptionKey, row.encrypted_record);
  const plaintext = pythonJsonStringify(record);
  const encoded = Buffer.from(plaintext, "utf8");
  const encrypted = Buffer.from(encoded.map((value) => sdesCryptByte(value, key)));
  const decrypted = Buffer.from(encrypted.map((value) => sdesCryptByte(value, key, true)));
  const fields = [];
  let offset = 0;
  for (const [name, value] of Object.entries(record)) {
    const entry = Buffer.from(`${pythonJsonStringify(name)}:${pythonJsonStringify(value)}`, "utf8");
    const entryStart = encoded.indexOf(entry, offset);
    if (entryStart < 0) throw new Error(`Could not locate patient field ${JSON.stringify(name)} in serialized record.`);
    const entryEnd = entryStart + entry.length;
    const encryptedEntry = encrypted.subarray(entryStart, entryEnd);
    const decryptedEntry = Buffer.from(encryptedEntry.map((byte) => sdesCryptByte(byte, key, true)));
    const decryptedPair = JSON.parse(`{${decryptedEntry.toString("utf8")}}`);
    fields.push({
      name,
      plaintext: value,
      encryptedHex: encryptedEntry.toString("hex"),
      decrypted: decryptedPair[name],
    });
    offset = entryEnd;
  }
  res.json({
    key,
    patientId: selectedPatientId,
    encryptedHex: encrypted.toString("hex"),
    plaintext,
    decrypted: decrypted.toString("utf8"),
    fields,
  });
}));

app.get("/performance", asyncRoute(async (req, res) => {
  if (!await requireRole(req, res, "doctor")) return;
  const sample = Buffer.from("MedSecure performance sample", "utf8");
  const key = "1010000010";
  let start = process.hrtime.bigint();
  const encrypted = sample.map((value) => sdesCryptByte(value, key));
  const encryptionMs = Number(process.hrtime.bigint() - start) / 1e6;
  start = process.hrtime.bigint();
  encrypted.map((value) => sdesCryptByte(value, key, true));
  const decryptionMs = Number(process.hrtime.bigint() - start) / 1e6;
  res.json({
    sampleBytes: sample.length,
    timings: {
      "S-DES": {
        encryptMs: Math.round(encryptionMs * 10_000) / 10_000,
        decryptMs: Math.round(decryptionMs * 10_000) / 10_000,
      },
    },
  });
}));

app.use((req, res) => error(res, "Not found.", 404));
app.use((cause, _req, res, _next) => {
  if (res.headersSent) return;
  if (cause.type === "entity.parse.failed") return error(res, "Submit valid JSON.");
  console.error("Unhandled MedSecure server error:", cause);
  return error(res, "Something went wrong. Please try again.", 500);
});

if (require.main === module) {
  const port = Number(process.env.PORT) || 5000;
  app.listen(port, () => console.log(`MedSecure listening on http://127.0.0.1:${port}`));
}

app.locals.close = async () => {
  if (pool) await pool.end();
  if (sqlite) sqlite.close();
};

module.exports = app;
