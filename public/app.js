const state = {
  accessToken: localStorage.getItem("accessToken"),
  refreshToken: localStorage.getItem("refreshToken"),
  verificationToken: localStorage.getItem("verificationToken")
};

const $ = (selector) => document.querySelector(selector);

function toast(message) {
  const el = $("#toast");
  el.textContent = message;
  el.hidden = false;

  setTimeout(() => {
    el.hidden = true;
  }, 3000);
}

async function request(path, options = {}) {
  const headers = {
    "content-type": "application/json",
    ...(options.headers ?? {})
  };

  if (state.accessToken) {
    headers.authorization = `Bearer ${state.accessToken}`;
  }

  const response = await fetch(path, { ...options, headers });
  const body = await response.json().catch(() => ({}));

  if (!response.ok && response.status !== 206) {
    throw new Error(body.error ?? "Solicitud fallida");
  }

  return body;
}

function credentials() {
  const mfaCode = $("#mfaCode").value.trim();

  if (mfaCode && !/^\d{6}$/.test(mfaCode)) {
    throw new Error("MFA debe estar vacio o tener 6 digitos.");
  }

  return {
    email: $("#email").value,
    password: $("#password").value,
    mfaCode: mfaCode || undefined
  };
}

function saveSession(body) {
  state.accessToken = body.accessToken;
  state.refreshToken = body.refreshToken;
  localStorage.setItem("accessToken", body.accessToken);
  localStorage.setItem("refreshToken", body.refreshToken);
}

function clearSession() {
  localStorage.removeItem("accessToken");
  localStorage.removeItem("refreshToken");
  state.accessToken = null;
  state.refreshToken = null;
}

function statCard(label, value) {
  return `
    <article class="stat">
      <span>${label}</span>
      <strong>${value}</strong>
    </article>
  `;
}

function auditRow(event) {
  const riskScore = event.riskScore ?? "-";
  const createdAt = new Date(event.createdAt).toLocaleString();

  return `
    <tr>
      <td>${event.eventType}</td>
      <td>${riskScore}</td>
      <td>${createdAt}</td>
    </tr>
  `;
}

function renderStats(stats) {
  const cards = [
    ["Usuarios", stats.users],
    ["Verificados", stats.verifiedUsers],
    ["MFA activo", stats.mfaEnabledUsers],
    ["Eventos 24h", stats.eventsLast24h],
    ["Fallos 24h", stats.failedLoginsLast24h],
    ["Alto riesgo 24h", stats.highRiskLoginsLast24h],
    ["Refresh activos", stats.activeRefreshTokens]
  ];

  $("#stats").innerHTML = cards.map(([label, value]) => {
    return statCard(label, value);
  }).join("");
}

function renderAudit(events) {
  $("#auditRows").innerHTML = events.map(auditRow).join("");
}

async function loadDashboard() {
  if (!state.accessToken) return;

  const summary = await request("/dashboard/summary");
  const audit = await request("/dashboard/audit");
  const mfaState = summary.user.mfaEnabled ? "activo" : "inactivo";

  $("#sessionState").textContent = `${summary.user.email} | MFA ${mfaState}`;
  renderStats(summary.stats);
  renderAudit(audit.events);
}

async function registerUser() {
  const body = await request("/auth/register", {
    method: "POST",
    body: JSON.stringify(credentials())
  });

  state.verificationToken = body.devVerificationToken;
  localStorage.setItem("verificationToken", body.devVerificationToken);
  $("#devToken").textContent =
    body.devVerificationToken ?? "Revisa tu email configurado";

  toast("Usuario registrado. Verifica el email.");
}

async function verifyEmail() {
  const token = state.verificationToken || $("#devToken").textContent;

  await request("/auth/verify-email", {
    method: "POST",
    body: JSON.stringify({ token })
  });

  toast("Email verificado.");
}

async function login(event) {
  event.preventDefault();

  const body = await request("/auth/login", {
    method: "POST",
    body: JSON.stringify(credentials())
  });

  if (body.mfaRequired) {
    toast("Ingresa el codigo MFA.");
    return;
  }

  saveSession(body);
  toast("Sesion iniciada.");
  await loadDashboard();
}

async function refreshSession() {
  if (state.refreshToken) {
    const body = await request("/auth/refresh", {
      method: "POST",
      body: JSON.stringify({ refreshToken: state.refreshToken })
    });

    saveSession(body);
  }

  await loadDashboard();
}

async function requestPasswordReset() {
  const body = await request("/auth/password/forgot", {
    method: "POST",
    body: JSON.stringify({ email: $("#email").value })
  });

  $("#devToken").textContent = body.devPasswordResetToken ?? "Reset solicitado";
  toast("Token de reset generado.");
}

async function logout() {
  if (state.accessToken) {
    await request("/auth/logout", {
      method: "POST",
      body: "{}"
    });
  }

  clearSession();
  $("#sessionState").textContent = "Sin sesion";
  $("#stats").innerHTML = "";
  $("#auditRows").innerHTML = "";
  toast("Sesiones cerradas.");
}

function bindEvents() {
  $("#registerBtn").addEventListener("click", () => {
    registerUser().catch((error) => toast(error.message));
  });

  $("#verifyBtn").addEventListener("click", () => {
    verifyEmail().catch((error) => toast(error.message));
  });

  $("#authForm").addEventListener("submit", (event) => {
    login(event).catch((error) => toast(error.message));
  });

  $("#refreshBtn").addEventListener("click", () => {
    refreshSession().catch((error) => toast(error.message));
  });

  $("#forgotBtn").addEventListener("click", () => {
    requestPasswordReset().catch((error) => toast(error.message));
  });

  $("#logoutBtn").addEventListener("click", () => {
    logout().catch((error) => toast(error.message));
  });
}

bindEvents();
loadDashboard().catch(() => {});
