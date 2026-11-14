"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { after, before, test } = require("node:test");
const { DatabaseSync } = require("node:sqlite");

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "medsecure-node-test-"));
process.env.DATABASE_PATH = path.join(tempDir, "test.sqlite3");
process.env.DEMO_DATA = "true";
process.env.SECRET_KEY = crypto.randomBytes(32).toString("base64");
process.env.ENCRYPTION_KEY = crypto.randomBytes(32).toString("base64");
delete process.env.DATABASE_URL;
delete process.env.POSTGRES_URL;
delete process.env.VERCEL;

const app = require("../server");
let server;
let origin;

before(async () => {
  server = app.listen(0);
  await new Promise((resolve) => server.once("listening", resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  if (server) await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  await app.locals.close();
  fs.rmSync(tempDir, { recursive: true, force: true });
});

function cookieFrom(response, existing = "") {
  const header = response.headers.get("set-cookie");
  return header ? header.split(";")[0] : existing;
}

async function request(url, { cookie = "", csrf = "", ...options } = {}) {
  const headers = new Headers(options.headers || {});
  if (cookie) headers.set("Cookie", cookie);
  if (csrf) headers.set("X-CSRF-Token", csrf);
  if (options.body) headers.set("Content-Type", "application/json");
  const response = await fetch(`${origin}${url}`, { ...options, headers });
  const body = await response.json();
  return { response, body, cookie: cookieFrom(response, cookie) };
}

test("Node app serves the UI and preserves the authenticated API", async () => {
  const home = await fetch(origin);
  assert.equal(home.status, 200);
  assert.match(await home.text(), /MedSecure — Patient care, protected/);
  const stylesheet = await fetch(`${origin}/static/styles.css`);
  assert.equal(stylesheet.status, 200);

  const unauthorized = await request("/api/patients");
  assert.equal(unauthorized.response.status, 401);

  let state = await request("/api/me");
  assert.equal(state.response.status, 200);
  assert.equal(state.body.user, null);
  let cookie = state.cookie;
  let csrf = state.body.csrfToken;

  const rejectedCsrf = await request("/api/login", {
    method: "POST",
    body: JSON.stringify({ username: "doctor@medsecure.test", password: "DoctorDemo2026!", role: "doctor" }),
  });
  assert.equal(rejectedCsrf.response.status, 403);

  let login = await request("/api/login", {
    method: "POST",
    cookie,
    csrf,
    body: JSON.stringify({ username: "doctor@medsecure.test", password: "DoctorDemo2026!", role: "doctor" }),
  });
  assert.equal(login.response.status, 200, JSON.stringify(login.body));
  cookie = login.cookie;
  state = await request("/api/me", { cookie });
  assert.equal(state.body.user.role, "doctor");
  csrf = state.body.csrfToken;

  let patients = await request("/api/patients", { cookie });
  assert.equal(patients.response.status, 200);
  assert.equal(patients.body.patients.length, 1);
  const seededPatient = patients.body.patients[0];
  assert.equal(seededPatient.firstName, "Maya");

  const created = await request("/api/patients", {
    method: "POST",
    cookie,
    csrf,
    body: JSON.stringify({
      username: "alex.lee",
      password: "SecureDemoPass1",
      firstName: "Alex",
      lastName: "Lee",
      age: 41,
      sex: "Male",
      diagnosis: "Routine check-up",
      medicalHistory: "No known allergies.",
      heartRate: 68,
      temperature: 36.8,
      oxygenSaturation: 99,
    }),
  });
  assert.equal(created.response.status, 201, JSON.stringify(created.body));

  let patientState = await request("/api/me");
  let patientCookie = patientState.cookie;
  const patientLogin = await request("/api/login", {
    method: "POST",
    cookie: patientCookie,
    csrf: patientState.body.csrfToken,
    body: JSON.stringify({ username: "alex.lee", password: "SecureDemoPass1", role: "patient" }),
  });
  assert.equal(patientLogin.response.status, 200);
  patientCookie = patientLogin.cookie;
  patientState = await request("/api/me", { cookie: patientCookie });
  assert.equal(patientState.body.user.role, "patient");
  const ownRecord = await request(`/api/patients/${created.body.patient.id}`, { cookie: patientCookie });
  assert.equal(ownRecord.response.status, 200);
  const otherRecord = await request(`/api/patients/${seededPatient.id}`, { cookie: patientCookie });
  assert.equal(otherRecord.response.status, 403);
  const patientList = await request("/api/patients", { cookie: patientCookie });
  assert.equal(patientList.response.status, 403);

  const encryption = await request("/api/sdes/encrypt", {
    method: "POST",
    cookie,
    csrf,
    body: JSON.stringify({ text: "ª", key: "1010000010" }),
  });
  assert.equal(encryption.response.status, 200);
  assert.equal(encryption.body.ciphertext.slice(-2), "8d");
  const decryption = await request("/api/sdes/decrypt", {
    method: "POST",
    cookie,
    csrf,
    body: JSON.stringify({ ciphertext: encryption.body.ciphertext, key: "1010000010" }),
  });
  assert.equal(decryption.body.text, "ª");

  const demo = await request("/api/sdes/demo", {
    method: "POST",
    cookie,
    csrf,
    body: JSON.stringify({ key: "1010000010" }),
  });
  assert.equal(demo.response.status, 200, JSON.stringify(demo.body));
  assert.deepEqual(JSON.parse(demo.body.decrypted), JSON.parse(demo.body.plaintext));

  const inspectionDb = new DatabaseSync(process.env.DATABASE_PATH);
  const stored = inspectionDb.prepare(
    "SELECT encrypted_record FROM patients WHERE id = ?",
  ).get(seededPatient.id);
  inspectionDb.close();
  assert.equal(Buffer.from(stored.encrypted_record).includes(Buffer.from("Maya")), false);
});
