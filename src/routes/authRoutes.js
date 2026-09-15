import { randomUUID } from "node:crypto";
import { Router } from "express";
import { z } from "zod";
import { audit } from "../audit.js";
import {
  createAccessToken,
  createOneTimeTokenRecord,
  createRefreshTokenRecord,
  createTotpSecret,
  hashOpaqueToken,
  hashPassword,
  verifyPassword,
  verifyTotp
} from "../auth.js";
import { config } from "../config.js";
import { db } from "../database.js";
import { requireAuth } from "../middleware.js";
import { scoreLoginRisk } from "../riskClient.js";

const router = Router();

const registerSchema = z.object({
  email: z.string().email().transform((value) => value.toLowerCase()),
  password: z.string().min(12).max(128)
});

const loginSchema = registerSchema.extend({
  mfaCode: z.string().regex(/^\d{6}$/).optional()
});

const tokenSchema = z.object({ token: z.string().min(20) });
const refreshSchema = z.object({ refreshToken: z.string().min(20) });
const mfaSchema = z.object({ code: z.string().regex(/^\d{6}$/) });

const resetRequestSchema = z.object({
  email: z.string().email().transform((value) => value.toLowerCase())
});

const resetConfirmSchema = z.object({
  token: z.string().min(20),
  password: z.string().min(12).max(128)
});

function auditRequest(req, event) {
  audit({
    ipAddress: req.ip,
    userAgent: req.get("user-agent"),
    ...event
  });
}

function exposeDevToken(name, token) {
  return config.devExposeTokens ? { [name]: token } : {};
}

async function createSession(user, req) {
  const accessToken = await createAccessToken(user);
  const refresh = createRefreshTokenRecord(user.id, req);

  db.createRefreshToken(refresh.record);

  return {
    accessToken,
    refreshToken: refresh.rawToken,
    expiresIn: 900,
    refreshExpiresAt: refresh.record.expiresAt
  };
}

router.post("/register", async (req, res) => {
  const parsed = registerSchema.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      error: "Email valido y password de minimo 12 caracteres requeridos."
    });
  }

  const { email, password } = parsed.data;
  const existing = db.findUserByEmail(email);

  if (existing) {
    auditRequest(req, { email, eventType: "register_duplicate" });
    return res.status(409).json({ error: "No se pudo crear la cuenta." });
  }

  const user = {
    id: randomUUID(),
    email,
    passwordHash: await hashPassword(password),
    role: "user",
    emailVerified: false,
    mfaEnabled: false,
    mfaSecret: null,
    failedAttempts: 0,
    lockedUntil: null,
    createdAt: new Date().toISOString()
  };

  db.createUser(user);

  const verification = createOneTimeTokenRecord(user.id, 60);
  db.createEmailVerificationToken(verification.record);

  auditRequest(req, {
    userId: user.id,
    email,
    eventType: "register_success"
  });
  auditRequest(req, {
    userId: user.id,
    email,
    eventType: "email_verification_sent"
  });

  return res.status(201).json({
    id: user.id,
    email: user.email,
    emailVerified: false,
    verificationUrl: `${config.appUrl}/auth/verify-email`,
    ...exposeDevToken("devVerificationToken", verification.rawToken)
  });
});

router.post("/verify-email", (req, res) => {
  const parsed = tokenSchema.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({ error: "Token requerido." });
  }

  const verification = db.findEmailVerificationToken(
    hashOpaqueToken(parsed.data.token)
  );

  if (!verification) {
    auditRequest(req, { eventType: "email_verification_failed" });
    return res.status(400).json({ error: "Token invalido o expirado." });
  }

  db.updateUser(verification.userId, { emailVerified: true });
  db.markEmailVerificationTokenUsed(verification.id);

  const user = db.findUserById(verification.userId);
  auditRequest(req, {
    userId: verification.userId,
    email: user?.email,
    eventType: "email_verified"
  });

  return res.json({ ok: true, emailVerified: true });
});

router.post("/login", async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  const email = parsed.success ? parsed.data.email : req.body?.email;
  const risk = await scoreLoginRisk({
    email,
    ipAddress: req.ip,
    userAgent: req.get("user-agent")
  });

  if (!parsed.success) {
    auditRequest(req, {
      email,
      eventType: "login_invalid_payload",
      riskScore: risk.score
    });
    return res.status(400).json({ error: "Credenciales invalidas." });
  }

  const user = db.findUserByEmail(parsed.data.email);

  if (!user) {
    auditRequest(req, {
      email: parsed.data.email,
      eventType: "login_unknown_user",
      riskScore: risk.score
    });
    return res.status(401).json({ error: "Credenciales invalidas." });
  }

  if (!user.emailVerified) {
    auditRequest(req, {
      userId: user.id,
      email: user.email,
      eventType: "login_unverified_email",
      riskScore: risk.score
    });
    return res.status(403).json({
      error: "Debes verificar tu email antes de iniciar sesion."
    });
  }

  if (user.lockedUntil && new Date(user.lockedUntil) > new Date()) {
    auditRequest(req, {
      userId: user.id,
      email: user.email,
      eventType: "login_locked",
      riskScore: risk.score
    });
    return res.status(423).json({ error: "Cuenta temporalmente bloqueada." });
  }

  const passwordOk = await verifyPassword(
    user.passwordHash,
    parsed.data.password
  );

  if (!passwordOk) {
    const lockedUntil = new Date(Date.now() + 15 * 60 * 1000).toISOString();

    db.recordFailure(user.id, lockedUntil);
    auditRequest(req, {
      userId: user.id,
      email: user.email,
      eventType: "login_failed",
      riskScore: risk.score
    });

    return res.status(401).json({ error: "Credenciales invalidas." });
  }

  const invalidMfa =
    user.mfaEnabled &&
    !(await verifyTotp(user.mfaSecret, parsed.data.mfaCode ?? ""));

  if (invalidMfa) {
    auditRequest(req, {
      userId: user.id,
      email: user.email,
      eventType: "mfa_required",
      riskScore: risk.score
    });
    return res.status(206).json({
      mfaRequired: true,
      error: "Codigo MFA requerido."
    });
  }

  db.resetFailures(user.id);

  const session = await createSession(user, req);
  auditRequest(req, {
    userId: user.id,
    email: user.email,
    eventType: "login_success",
    riskScore: risk.score
  });

  return res.json({ ...session, risk, user: db.findUserById(user.id) });
});

router.post("/refresh", async (req, res) => {
  const parsed = refreshSchema.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({ error: "Refresh token requerido." });
  }

  const tokenHash = hashOpaqueToken(parsed.data.refreshToken);
  const existing = db.findActiveRefreshToken(tokenHash);

  if (!existing) {
    auditRequest(req, { eventType: "refresh_failed" });
    return res.status(401).json({ error: "Refresh token invalido." });
  }

  const user = db.findUserById(existing.userId);

  if (!user) {
    return res.status(401).json({ error: "Usuario no encontrado." });
  }

  const session = await createSession(user, req);
  const replacement = db.findActiveRefreshToken(
    hashOpaqueToken(session.refreshToken)
  );

  db.revokeRefreshToken(existing.id, replacement?.id ?? null);
  auditRequest(req, {
    userId: user.id,
    email: user.email,
    eventType: "refresh_rotated"
  });

  return res.json(session);
});

router.post("/logout", requireAuth, (req, res) => {
  db.revokeUserRefreshTokens(req.user.id);
  auditRequest(req, {
    userId: req.user.id,
    eventType: "logout_all_sessions"
  });

  return res.json({ ok: true });
});

router.post("/password/forgot", (req, res) => {
  const parsed = resetRequestSchema.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({ error: "Email valido requerido." });
  }

  const user = db.findUserByEmail(parsed.data.email);

  if (!user) {
    auditRequest(req, {
      email: parsed.data.email,
      eventType: "password_reset_requested_unknown"
    });
    return res.json({ ok: true });
  }

  const reset = createOneTimeTokenRecord(user.id, 20);
  db.createPasswordResetToken(reset.record);
  auditRequest(req, {
    userId: user.id,
    email: user.email,
    eventType: "password_reset_requested"
  });

  return res.json({
    ok: true,
    resetUrl: `${config.appUrl}/auth/password/reset`,
    ...exposeDevToken("devPasswordResetToken", reset.rawToken)
  });
});

router.post("/password/reset", async (req, res) => {
  const parsed = resetConfirmSchema.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      error: "Token y nuevo password seguro requeridos."
    });
  }

  const reset = db.findPasswordResetToken(hashOpaqueToken(parsed.data.token));

  if (!reset) {
    auditRequest(req, { eventType: "password_reset_failed" });
    return res.status(400).json({ error: "Token invalido o expirado." });
  }

  const user = db.updateUser(reset.userId, {
    passwordHash: await hashPassword(parsed.data.password),
    failedAttempts: 0,
    lockedUntil: null
  });

  db.markPasswordResetTokenUsed(reset.id);
  db.revokeUserRefreshTokens(reset.userId);
  auditRequest(req, {
    userId: reset.userId,
    email: user?.email,
    eventType: "password_reset_success"
  });

  return res.json({ ok: true });
});

router.post("/mfa/setup", requireAuth, (req, res) => {
  const user = db.findUserById(req.user.id);
  const setup = createTotpSecret(user.email);

  db.updateUser(req.user.id, {
    mfaSecret: setup.secret,
    mfaEnabled: false
  });
  auditRequest(req, {
    userId: req.user.id,
    email: user.email,
    eventType: "mfa_setup_started"
  });

  return res.json(setup);
});

router.post("/mfa/enable", requireAuth, async (req, res) => {
  const parsed = mfaSchema.safeParse(req.body);
  const safeUser = db.findUserById(req.user.id);
  const rawUser = safeUser ? db.findUserByEmail(safeUser.email) : null;
  const invalidCode =
    !parsed.success ||
    !rawUser?.mfaSecret ||
    !(await verifyTotp(rawUser.mfaSecret, parsed.data.code));

  if (invalidCode) {
    auditRequest(req, {
      userId: req.user.id,
      email: rawUser?.email,
      eventType: "mfa_enable_failed"
    });
    return res.status(400).json({ error: "Codigo MFA invalido." });
  }

  db.updateUser(req.user.id, { mfaEnabled: true });
  auditRequest(req, {
    userId: req.user.id,
    email: rawUser.email,
    eventType: "mfa_enabled"
  });

  return res.json({ ok: true, mfaEnabled: true });
});

router.post("/mfa/disable", requireAuth, (req, res) => {
  const user = db.findUserById(req.user.id);

  db.updateUser(req.user.id, {
    mfaEnabled: false,
    mfaSecret: null
  });
  auditRequest(req, {
    userId: req.user.id,
    email: user?.email,
    eventType: "mfa_disabled"
  });

  return res.json({ ok: true, mfaEnabled: false });
});

router.get("/me", requireAuth, (req, res) => {
  const user = db.findUserById(req.user.id);

  if (!user) {
    return res.status(404).json({ error: "Usuario no encontrado." });
  }

  return res.json(user);
});

export default router;
