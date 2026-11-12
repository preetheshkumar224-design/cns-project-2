(() => {
  const $ = (selector, root = document) => root.querySelector(selector);
  const loginView = $("#login-view");
  const roleSelection = $("#role-selection");
  const loginForm = $("#login-form");
  const dashboardView = $("#dashboard-view");
  const pageContent = $("#page-content");
  const dialog = $("#patient-dialog");
  const patientForm = $("#patient-form");
  let user = null;
  let csrfToken = $('meta[name="csrf-token"]').content;
  let selectedRole = null;
  let selectedPatient = null;
  let patientCount = 0;
  let toastTimer;

  const icon = (name, className = "") =>
    `<svg class="${className}" aria-hidden="true"><use href="#i-${name}"></use></svg>`;
  const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[character]);
  const initials = (patient) =>
    `${patient.firstName?.[0] || ""}${patient.lastName?.[0] || ""}`.toUpperCase();
  const prettyDate = (value) =>
    value ? new Date(value).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" }) : "Recently";

  const sdesP10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6];
  const sdesP8 = [6, 3, 7, 4, 8, 5, 10, 9];
  const sdesIP = [2, 6, 3, 1, 4, 8, 5, 7];
  const sdesIPInverse = [4, 1, 3, 5, 7, 2, 8, 6];
  const sdesEP = [4, 1, 2, 3, 2, 3, 4, 1];
  const sdesP4 = [2, 4, 3, 1];
  const sdesS0 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]];
  const sdesS1 = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]];

  function sdesPermute(bits, positions) {
    return positions.map((position) => bits[position - 1]).join("");
  }

  function sdesLeftShift(bits, amount) {
    return bits.slice(amount) + bits.slice(0, amount);
  }

  function deriveSdesKeys(key) {
    if (typeof key !== "string" || key.length !== 10 || !/^[01]+$/.test(key)) {
      return { valid: false };
    }
    const permuted = sdesPermute(key, sdesP10);
    let left = permuted.slice(0, 5);
    let right = permuted.slice(5);
    left = sdesLeftShift(left, 1);
    right = sdesLeftShift(right, 1);
    const k1 = sdesPermute(left + right, sdesP8);
    left = sdesLeftShift(left, 2);
    right = sdesLeftShift(right, 2);
    const k2 = sdesPermute(left + right, sdesP8);
    return {
      valid: true,
      permuted,
      leftAfterRoundOne: left,
      rightAfterRoundOne: right,
      k1,
      k2,
    };
  }

  function renderSdesTrace(key) {
    const panel = document.getElementById("sdes-trace-panel");
    if (!panel) return;
    const schedule = deriveSdesKeys(key);
    if (!schedule.valid) {
      panel.innerHTML = `
        <div class="trace-key"><span class="trace-label">Current key</span><strong>Invalid key</strong></div>
        <div class="trace-line"><span>Expected</span><strong>10 binary digits only</strong></div>
      `;
      return;
    }
    panel.innerHTML = `
      <div class="trace-key"><span class="trace-label">Current key</span><strong>${escapeHtml(key)}</strong></div>
      <div class="trace-line"><span>P10</span><strong>${escapeHtml(schedule.permuted)}</strong></div>
      <div class="trace-line"><span>Round key K1</span><strong>${escapeHtml(schedule.k1)}</strong></div>
      <div class="trace-line"><span>Round key K2</span><strong>${escapeHtml(schedule.k2)}</strong></div>
      <div class="trace-flow"><span>Flow</span><strong>IP → F(K1) → swap → F(K2) → IP⁻¹</strong></div>
    `;
  }

  async function api(url, options = {}) {
    const headers = { ...(options.headers || {}) };
    if (options.body) headers["Content-Type"] = "application/json";
    if (!["GET", "HEAD"].includes((options.method || "GET").toUpperCase())) {
      headers["X-CSRF-Token"] = csrfToken;
    }
    let response;
    try {
      response = await fetch(url, { ...options, headers, credentials: "same-origin" });
    } catch {
      throw new Error("Unable to reach the server. Check your connection and try again.");
    }
    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
      if (response.status === 401 && user) showLogin();
      throw new Error(result.error || "Something went wrong. Please try again.");
    }
    return result;
  }

  function showToast(message, isError = false) {
    const toast = $("#toast");
    toast.textContent = message;
    toast.classList.toggle("toast-error", isError);
    toast.classList.add("toast-visible");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove("toast-visible"), 3400);
  }

  function showError(element, message) {
    element.textContent = message;
    element.hidden = false;
  }

  function chooseRole(role) {
    selectedRole = role;
    roleSelection.hidden = true;
    loginForm.hidden = false;
    $("#login-title").textContent = role === "doctor" ? "Doctor sign in" : "Patient sign in";
    $("#login-intro").textContent = role === "doctor"
      ? "Sign in to your secure doctor workspace."
      : "Sign in to view your personal health information.";
    $("#username-label").textContent = role === "doctor" ? "Doctor username or email" : "Patient username";
    $("#username").placeholder = role === "doctor"
      ? "doctor@clinic.com"
      : "Enter your patient username";
    $("#login-error").hidden = true;
  }

  function showLogin() {
    user = null;
    selectedRole = null;
    dashboardView.hidden = true;
    loginView.hidden = false;
    roleSelection.hidden = false;
    loginForm.hidden = true;
    $("#username").value = "";
    $("#password").value = "";
    $("#login-error").hidden = true;
  }

  function setNavigation(active = "overview") {
    const links = user.role === "doctor"
      ? [["overview", "grid", "Overview"], ["patients", "users", "Patients"], ["encryption", "shield", "Encryption lab"], ["performance", "chart", "Performance"], ["logout", "logout", "Sign out"]]
      : [["health", "heart", "My health"], ["logout", "logout", "Sign out"]];
    $("#navigation").classList.toggle("navigation-patient", user.role === "patient");
    $("#navigation").innerHTML = links.map(([id, symbol, label]) =>
      `<button class="nav-link ${active === id ? "nav-active" : ""} ${id === "logout" ? "nav-signout" : ""}" type="button" data-page="${id}">${icon(symbol)}<span>${label}</span>${id === "patients" ? `<span class="nav-count" id="patient-nav-count">${patientCount}</span>` : ""}</button>`
    ).join("");
    $("#navigation").querySelectorAll("[data-page]").forEach((button) => {
      button.addEventListener("click", () => {
        if (button.dataset.page === "logout") signOut();
        else loadPage(button.dataset.page);
      });
    });
  }

  function shell(page, content) {
    const labels = {
      overview: "Overview", patients: "Patients", encryption: "Encryption lab",
      performance: "Performance", health: "My health",
    };
    $("#page-title").textContent = labels[page] || "Overview";
    setNavigation(page);
    pageContent.innerHTML = content;
  }

  function patientRow(patient) {
    return `<button type="button" class="patient-row" data-patient-id="${escapeHtml(patient.id)}">
      <span class="patient-avatar">${escapeHtml(initials(patient))}</span>
      <span class="patient-info"><strong>${escapeHtml(patient.firstName)} ${escapeHtml(patient.lastName)}</strong><small>${escapeHtml(patient.diagnosis)}</small></span>
      <span class="patient-date">${escapeHtml(prettyDate(patient.updatedAt))}</span>
      ${icon("arrow", "row-arrow")}
    </button>`;
  }

  function bindPatientRows() {
    pageContent.querySelectorAll("[data-patient-id]").forEach((row) => {
      row.addEventListener("click", () => openPatient(row.dataset.patientId));
    });
  }

  async function loadPatients(search = "") {
    const { patients } = await api(`/api/patients?q=${encodeURIComponent(search)}`);
    if (!search) patientCount = patients.length;
    const count = $("#patient-nav-count");
    if (count) count.textContent = String(patients.length);
    return patients;
  }

  async function loadOverview() {
    const patients = await loadPatients();
    const activePatients = patients.length;
    const averageHeartRate = activePatients
      ? Math.round(patients.reduce((sum, patient) => sum + patient.heartRate, 0) / activePatients)
      : 0;
    shell("overview", `
      <section class="welcome-banner"><div class="welcome-copy"><span class="eyebrow welcome-eyebrow"><span class="pulse-dot"></span> YOUR CARE WORKSPACE</span>
        <h1>Good ${new Date().getHours() < 12 ? "morning" : "afternoon"}, ${escapeHtml(user.username.split("@")[0])}.</h1>
        <p>Every detail, thoughtfully cared for.</p></div><div class="welcome-art" aria-hidden="true"><span class="art-orbit orbit-outer"></span><span class="art-orbit orbit-inner"></span><span class="art-cross">✚</span><svg class="art-heart"><use href="#i-heart"/></svg></div>
        <svg class="banner-wave" viewBox="0 0 480 80" preserveAspectRatio="none" aria-hidden="true"><path d="M0 50h85l20-4 18-21 20 48 22-62 24 61 24-22h267"/></svg>
      </section>
      <section class="stat-grid">
        <article class="stat-card"><span class="stat-icon blue-icon">${icon("users")}</span><div class="stat-label">Total patients</div><div class="stat-number">${activePatients}<span class="stat-caption">active records</span></div><span class="stat-foot">All profiles encrypted at rest</span></article>
        <article class="stat-card"><span class="stat-icon mint-icon">${icon("shield")}</span><div class="stat-label">Data protection</div><div class="stat-number">S-DES <span class="stat-caption">local key</span></div><span class="stat-foot"><span class="status-dot"></span> Encrypted and secure</span></article>
        <article class="stat-card"><span class="stat-icon coral-icon">${icon("pulse")}</span><div class="stat-label">Average heart rate</div><div class="stat-number">${averageHeartRate}<span class="stat-caption">bpm</span></div><span class="stat-foot">Across your patient list</span></article>
      </section>
      <section class="content-card patient-list-card"><div class="section-heading"><div><p class="eyebrow muted-eyebrow">YOUR CARE TEAM</p><h2>Recent patients</h2></div><button class="button button-outline" data-action="all-patients">View all ${icon("arrow")}</button></div>
        <div class="patient-list">${patients.slice(0, 4).map(patientRow).join("") || '<div class="empty-state">Your patient list is ready when you are.</div>'}</div>
        <div class="list-footer"><span>${activePatients} patient${activePatients === 1 ? "" : "s"} in your care</span><span class="list-encrypted">${icon("lock")} Private & secure</span></div>
      </section>`);
    $("#patient-nav-count").textContent = String(patientCount);
    bindPatientRows();
    $("[data-action='all-patients']")?.addEventListener("click", () => loadPage("patients"));
  }

  async function loadPatientList(search = "") {
    const patients = await loadPatients(search);
    shell("patients", `
      <section class="page-heading-row"><div><p class="eyebrow muted-eyebrow">CARE MANAGEMENT</p><h1>Your patients</h1><p class="page-subtitle">A secure overview of the people in your care.</p></div><button class="button button-primary" data-action="add-patient">${icon("plus")} Add patient</button></section>
      <section class="content-card directory-card"><div class="directory-toolbar"><div class="search-wrap">${icon("search")}<input id="patient-search" type="search" value="${escapeHtml(search)}" placeholder="Search patients or diagnoses..." autocomplete="off"></div><span class="directory-count">${patients.length} patient${patients.length === 1 ? "" : "s"}</span></div><div class="patient-list">${patients.map(patientRow).join("") || '<div class="empty-state">No patients found. Try a different search.</div>'}</div></section>`);
    $("#patient-nav-count").textContent = String(patientCount);
    bindPatientRows();
    $("[data-action='add-patient']").addEventListener("click", () => openPatientDialog());
    let timer;
    $("#patient-search").addEventListener("input", (event) => {
      clearTimeout(timer);
      timer = setTimeout(() => loadPatientList(event.target.value).catch((error) => showToast(error.message, true)), 180);
    });
  }

  async function openPatient(patientId) {
    try {
      const { patient } = await api(`/api/patients/${encodeURIComponent(patientId)}`);
      if (user.role === "patient") {
        renderPatientHealth(patient);
        return;
      }
      selectedPatient = patient;
      shell("patients", `
        <button class="back-link" type="button" data-action="back">${icon("arrow")} Back to patients</button>
        <section class="profile-heading"><span class="profile-avatar">${escapeHtml(initials(patient))}</span><div><p class="eyebrow muted-eyebrow">PATIENT PROFILE</p><h1>${escapeHtml(patient.firstName)} ${escapeHtml(patient.lastName)}</h1><p class="page-subtitle">Age ${escapeHtml(patient.age)} · ${escapeHtml(patient.sex)} · Updated ${escapeHtml(prettyDate(patient.updatedAt))}</p></div><button class="button button-outline edit-patient" type="button" data-action="edit">${icon("plus")} Edit record</button></section>
        <section class="stat-grid vitals-grid">${vitalCard("pulse", "Heart rate", `${escapeHtml(patient.heartRate)} <small>bpm</small>`, "mint-icon", "Resting pulse")}${vitalCard("temp", "Temperature", `${escapeHtml(patient.temperature)} <small>°C</small>`, "coral-icon", "Body temperature")}${vitalCard("lungs", "Oxygen saturation", `${escapeHtml(patient.oxygenSaturation)}<small>%</small>`, "blue-icon", "Blood oxygen")}</section>
        <section class="content-card history-card"><div class="section-heading"><div><p class="eyebrow muted-eyebrow">CLINICAL NOTES</p><h2>Medical history</h2></div><span class="encrypted-pill">${icon("lock")} Encrypted</span></div><div class="diagnosis-box"><span>PRIMARY DIAGNOSIS</span><strong>${escapeHtml(patient.diagnosis)}</strong></div><p class="history-copy">${escapeHtml(patient.medicalHistory)}</p></section>`);
      $("[data-action='back']").addEventListener("click", () => loadPatientList());
      $("[data-action='edit']").addEventListener("click", () => openPatientDialog(patient));
    } catch (error) {
      showToast(error.message, true);
    }
  }

  function vitalCard(symbol, label, value, color, note) {
    return `<article class="stat-card vital-card"><span class="stat-icon ${color}">${icon(symbol)}</span><div class="stat-label">${label}</div><div class="stat-number">${value}</div><span class="stat-foot">${note}</span></article>`;
  }

  function renderPatientHealth(patient) {
    shell("health", `
      <section class="welcome-banner patient-banner"><div class="welcome-copy"><span class="eyebrow welcome-eyebrow"><span class="pulse-dot"></span> YOUR PERSONAL HEALTH</span><h1>Welcome, ${escapeHtml(patient.firstName)}.</h1><p>Your health information, all in one secure place.</p></div><div class="welcome-art" aria-hidden="true"><span class="art-orbit orbit-outer"></span><span class="art-orbit orbit-inner"></span><span class="art-cross">✚</span>${icon("heart", "art-heart")}</div></section>
      <section class="stat-grid vitals-grid">${vitalCard("pulse", "Heart rate", `${escapeHtml(patient.heartRate)} <small>bpm</small>`, "mint-icon", "Latest recorded reading")}${vitalCard("temp", "Temperature", `${escapeHtml(patient.temperature)} <small>°C</small>`, "coral-icon", "Latest recorded reading")}${vitalCard("lungs", "Oxygen saturation", `${escapeHtml(patient.oxygenSaturation)}<small>%</small>`, "blue-icon", "Latest recorded reading")}</section>
      <section class="content-card history-card"><div class="section-heading"><div><p class="eyebrow muted-eyebrow">YOUR CARE</p><h2>Medical history</h2></div><span class="encrypted-pill">${icon("lock")} Encrypted</span></div><div class="patient-meta"><span>AGE <strong>${escapeHtml(patient.age)}</strong></span><span>SEX <strong>${escapeHtml(patient.sex)}</strong></span><span>UPDATED <strong>${escapeHtml(prettyDate(patient.updatedAt))}</strong></span></div><div class="diagnosis-box"><span>PRIMARY DIAGNOSIS</span><strong>${escapeHtml(patient.diagnosis)}</strong></div><p class="history-copy">${escapeHtml(patient.medicalHistory)}</p>
        <div class="patient-assurance">${icon("shield")} Only you and your care team can access this information.</div></section>`);
  }

  function openPatientDialog(patient = null) {
    patientForm.reset();
    $("#form-error").hidden = true;
    $("#dialog-title").textContent = patient ? "Update patient record" : "Add a patient";
    $("#save-patient").textContent = patient ? "Save changes" : "Save patient";
    $("#account-fields").hidden = Boolean(patient);
    patientForm.elements.username.required = !patient;
    patientForm.elements.password.required = !patient;
    if (patient) {
      for (const field of ["firstName", "lastName", "age", "sex", "diagnosis", "medicalHistory", "heartRate", "temperature", "oxygenSaturation"]) {
        patientForm.elements[field].value = patient[field] ?? "";
      }
    }
    dialog.showModal();
  }

  async function savePatient(event) {
    event.preventDefault();
    const editingPatient = selectedPatient;
    const button = $("#save-patient");
    const originalText = button.textContent;
    button.disabled = true;
    button.textContent = "Saving…";
    $("#form-error").hidden = true;
    const data = Object.fromEntries(new FormData(patientForm).entries());
    for (const field of ["age", "heartRate", "oxygenSaturation"]) data[field] = Number(data[field]);
    data.temperature = Number(data.temperature);
    try {
      const url = editingPatient ? `/api/patients/${encodeURIComponent(editingPatient.id)}` : "/api/patients";
      const result = await api(url, {
        method: editingPatient ? "PUT" : "POST",
        body: JSON.stringify(data),
      });
      dialog.close();
      const added = !editingPatient;
      const savedPatient = result.patient;
      selectedPatient = null;
      showToast(added ? `Patient added. Login username: ${result.username}` : "Patient record updated securely.");
      if (added) await loadPatientList();
      else await openPatient(savedPatient.id);
    } catch (error) {
      showError($("#form-error"), error.message);
    } finally {
      button.disabled = false;
      button.textContent = originalText;
    }
  }

  async function loadEncryption() {
    shell("encryption", `
      <section class="page-heading-row"><div><p class="eyebrow muted-eyebrow">ACADEMIC TOOL</p><h1>S-DES encryption lab</h1><p class="page-subtitle">Explore the Simplified DES block cipher with a reversible text example.</p></div><span class="educational-badge">${icon("shield")} Educational only</span></section>
      <div class="sdes-warning"><span class="warning-symbol">i</span><p><strong>Not for real patient data.</strong> S-DES is an educational cipher with a small key and block size. Patient records are protected with a local secret key in this demo-only setup.</p></div>
      <section class="content-card lab-card"><div class="lab-heading"><div class="lab-step">01</div><div><p class="eyebrow muted-eyebrow">S-DES KEY</p><h2>Set your 10-bit key</h2></div></div><label class="standalone-label" for="sdes-key">Enter a binary key</label><input id="sdes-key" class="mono-input" maxlength="10" inputmode="numeric" value="1010000010" placeholder="1010000010"><div class="lab-columns"><div><label class="standalone-label" for="sdes-plaintext">Plaintext</label><textarea id="sdes-plaintext" rows="4" maxlength="500" placeholder="Type a message to encrypt...">Hello, care team.</textarea><button id="sdes-encrypt" class="button button-primary lab-button" type="button">${icon("lock")} Encrypt message</button></div><div><label class="standalone-label" for="sdes-ciphertext">Ciphertext <span class="mono-hint">HEX</span></label><textarea id="sdes-ciphertext" rows="4" placeholder="Encrypted output appears here..."></textarea><button id="sdes-decrypt" class="button button-outline lab-button" type="button">${icon("shield")} Decrypt message</button></div></div><div id="sdes-error" class="form-error" role="alert" hidden></div><div id="sdes-verified" class="verification-note" hidden>${icon("shield")} Round-trip verified — decrypted output matches the original.</div></section>
      <section class="content-card sdes-trace-card"><div class="lab-heading"><div class="lab-step">02</div><div><p class="eyebrow muted-eyebrow">LIVE TRACE</p><h2>S-DES operation</h2></div></div><div id="sdes-trace-panel" class="sdes-trace-panel"></div></section>`);
    renderSdesTrace($("#sdes-key").value);
    $("#sdes-key").addEventListener("input", (event) => renderSdesTrace(event.target.value));
    $("#sdes-encrypt").addEventListener("click", encryptText);
    $("#sdes-decrypt").addEventListener("click", decryptText);
  }

  async function encryptText() {
    const button = $("#sdes-encrypt");
    const text = $("#sdes-plaintext").value;
    $("#sdes-error").hidden = true;
    button.disabled = true;
    button.innerHTML = '<span class="spinner"></span> Encrypting…';
    try {
      const key = $("#sdes-key").value;
      renderSdesTrace(key);
      const result = await api("/api/sdes/encrypt", {
        method: "POST",
        body: JSON.stringify({ text, key }),
      });
      $("#sdes-ciphertext").value = result.ciphertext;
      const verification = await api("/api/sdes/verify", {
        method: "POST",
        body: JSON.stringify({ text, key: $("#sdes-key").value }),
      });
      $("#sdes-verified").hidden = !verification.verified;
    } catch (error) {
      showError($("#sdes-error"), error.message);
    } finally {
      button.disabled = false;
      button.innerHTML = `${icon("lock")} Encrypt message`;
    }
  }

  async function decryptText() {
    const button = $("#sdes-decrypt");
    $("#sdes-error").hidden = true;
    button.disabled = true;
    button.innerHTML = '<span class="spinner"></span> Decrypting…';
    try {
      const key = $("#sdes-key").value;
      renderSdesTrace(key);
      const result = await api("/api/sdes/decrypt", {
        method: "POST",
        body: JSON.stringify({ ciphertext: $("#sdes-ciphertext").value, key }),
      });
      $("#sdes-plaintext").value = result.text;
      $("#sdes-verified").hidden = true;
    } catch (error) {
      showError($("#sdes-error"), error.message);
    } finally {
      button.disabled = false;
      button.innerHTML = `${icon("shield")} Decrypt message`;
    }
  }

  async function loadPerformance() {
    shell("performance", '<div class="loading-state"><span class="spinner"></span> Measuring local encryption performance…</div>');
    try {
      const result = await api("/api/performance");
      shell("performance", `
        <section class="page-heading-row"><div><p class="eyebrow muted-eyebrow">LOCAL SAMPLE · ${escapeHtml(result.sampleBytes)} BYTES</p><h1>Performance snapshot</h1><p class="page-subtitle">One small sample, measured on this server. Results change between runs.</p></div><button id="refresh-performance" class="button button-outline" type="button">Run again ↻</button></section>
        <section class="content-card performance-card"><div class="section-heading"><div><p class="eyebrow muted-eyebrow">ENCRYPTION & DECRYPTION</p><h2>Operation times</h2></div>${icon("clock", "performance-icon")}</div>
        <div class="performance-row"><span class="performance-name"><span class="performance-dot dot-blue"></span><span><strong>S-DES</strong><small>Educational cipher</small></span></span><span><small>ENCRYPT</small><strong>${escapeHtml(result.timings["S-DES"].encryptMs)} <em>ms</em></strong></span><span><small>DECRYPT</small><strong>${escapeHtml(result.timings["S-DES"].decryptMs)} <em>ms</em></strong></span></div>
        <p class="performance-footnote">${icon("shield")} These illustrative timings use a single short message. They are not a security comparison or formal benchmark.</p></section>`);
      $("#refresh-performance").addEventListener("click", loadPerformance);
    } catch (error) {
      shell("performance", `<div class="empty-state">${escapeHtml(error.message)}</div><button id="retry-performance" class="button button-outline" type="button">Try again</button>`);
      $("#retry-performance").addEventListener("click", loadPerformance);
    }
  }

  async function loadPage(page) {
    pageContent.innerHTML = '<div class="loading-state"><span class="spinner"></span> Loading your workspace…</div>';
    try {
      if (page === "overview") await loadOverview();
      else if (page === "patients") await loadPatientList();
      else if (page === "encryption") await loadEncryption();
      else if (page === "performance") await loadPerformance();
      else if (page === "health" && user.role === "patient") {
        const { patient } = await api(`/api/patients/${encodeURIComponent(user.patientId || "")}`);
        renderPatientHealth(patient);
      }
    } catch (error) {
      pageContent.innerHTML = `<section class="empty-state error-state">${escapeHtml(error.message)}<button class="button button-outline" id="retry-page" type="button">Try again</button></section>`;
      $("#retry-page").addEventListener("click", () => loadPage(page));
    }
  }

  async function showDashboard(account, csrf) {
    user = account;
    if (csrf) csrfToken = csrf;
    loginView.hidden = true;
    dashboardView.hidden = false;
    const displayName = account.username.split("@")[0].replace(/[._-]/g, " ");
    const letter = displayName[0]?.toUpperCase() || "M";
    $("#user-name").textContent = displayName;
    $("#user-role").textContent = account.role === "doctor" ? "Care provider" : "Patient account";
    $("#user-avatar").textContent = letter;
    $("#top-avatar").textContent = letter;
    $("#today-label").textContent = new Date().toLocaleDateString(undefined, {
      weekday: "short", month: "short", day: "numeric",
    });
    selectedPatient = null;
    await loadPage(account.role === "doctor" ? "overview" : "health");
  }

  loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = $(".login-submit");
    const message = $("#login-error");
    message.hidden = true;
    if (!selectedRole) {
      showError(message, "Choose whether you are signing in as a doctor or patient.");
      return;
    }
    button.disabled = true;
    button.innerHTML = '<span class="spinner"></span> Signing in…';
    try {
      const result = await api("/api/login", {
        method: "POST",
        body: JSON.stringify({
          username: $("#username").value,
          password: $("#password").value,
          role: selectedRole,
        }),
      });
      const profile = await api("/api/me");
      await showDashboard(profile.user, profile.csrfToken);
    } catch (error) {
      showError(message, error.message);
    } finally {
      button.disabled = false;
      button.innerHTML = `<span>Sign in securely</span>${icon("arrow")}`;
    }
  });

  document.querySelectorAll("[data-start-role]").forEach((button) => {
    button.addEventListener("click", () => chooseRole(button.dataset.startRole));
  });

  $("[data-back-role]").addEventListener("click", showLogin);

  document.querySelectorAll("[data-demo]").forEach((button) => {
    button.addEventListener("click", () => {
      chooseRole(button.dataset.demo);
      const demo = button.dataset.demo === "doctor"
        ? ["doctor@medsecure.test", "DoctorDemo2026!"]
        : ["patient@medsecure.test", "PatientDemo2026!"];
      $("#username").value = demo[0];
      $("#password").value = demo[1];
      $("#login-form").requestSubmit();
    });
  });

  async function signOut() {
    try {
      const result = await api("/api/logout", { method: "POST" });
      csrfToken = result.csrfToken;
      showLogin();
    } catch (error) {
      showToast(error.message, true);
    }
  }

  $("#logout-button").addEventListener("click", signOut);

  patientForm.addEventListener("submit", savePatient);
  $(".dialog-close").addEventListener("click", () => dialog.close());
  $(".dialog-cancel").addEventListener("click", () => dialog.close());
  dialog.addEventListener("close", () => { selectedPatient = null; });

  api("/api/me").then(({ user: account, csrfToken: token }) => {
    csrfToken = token;
    if (account) showDashboard(account, token);
    else showLogin();
  }).catch(() => showLogin());
})();
