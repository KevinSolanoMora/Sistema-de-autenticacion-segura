import { dirname } from "node:path";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { config } from "./config.js";

mkdirSync(dirname(config.databasePath), { recursive: true });

const initialState = {
  users: [],
  auditEvents: [],
  refreshTokens: [],
  emailVerificationTokens: [],
  passwordResetTokens: []
};

function loadState() {
  if (!existsSync(config.databasePath)) {
    writeFileSync(config.databasePath, JSON.stringify(initialState, null, 2));
    return structuredClone(initialState);
  }

  const loaded = JSON.parse(readFileSync(config.databasePath, "utf8"));
  return {
    ...structuredClone(initialState),
    ...loaded,
    users: (loaded.users ?? []).map((user) => ({
      emailVerified: false,
      mfaEnabled: false,
      mfaSecret: null,
      ...user
    }))
  };
}

let state = loadState();

function saveState() {
  writeFileSync(config.databasePath, JSON.stringify(state, null, 2));
}

export const db = {
  findUserByEmail(email) {
    return state.users.find((user) => user.email === email) ?? null;
  },
  findUserById(id) {
    const user = state.users.find((item) => item.id === id);
    if (!user) return null;
    const {
      passwordHash: _passwordHash,
      failedAttempts: _failedAttempts,
      lockedUntil: _lockedUntil,
      mfaSecret: _mfaSecret,
      ...safeUser
    } = user;
    return safeUser;
  },
  listUsers() {
    return state.users.map((user) => this.findUserById(user.id));
  },
  createUser(user) {
    state.users.push(user);
    saveState();
  },
  updateUser(id, patch) {
    const user = state.users.find((item) => item.id === id);
    if (!user) return null;
    Object.assign(user, patch);
    saveState();
    return user;
  },
  resetFailures(id) {
    const user = state.users.find((item) => item.id === id);
    if (!user) return;
    user.failedAttempts = 0;
    user.lockedUntil = null;
    saveState();
  },
  recordFailure(id, lockedUntil) {
    const user = state.users.find((item) => item.id === id);
    if (!user) return;
    user.failedAttempts += 1;
    if (user.failedAttempts >= 5) {
      user.lockedUntil = lockedUntil;
    }
    saveState();
  },
  addAuditEvent(event) {
    state.auditEvents.push(event);
    saveState();
  },
  listAuditEvents(limit = 50) {
    return [...state.auditEvents]
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
      .slice(0, limit);
  },
  createRefreshToken(token) {
    state.refreshTokens.push(token);
    saveState();
  },
  findActiveRefreshToken(tokenHash) {
    return state.refreshTokens.find(
      (token) => token.tokenHash === tokenHash && !token.revokedAt && new Date(token.expiresAt) > new Date()
    ) ?? null;
  },
  revokeRefreshToken(id, replacedByTokenId = null) {
    const token = state.refreshTokens.find((item) => item.id === id);
    if (!token) return;
    token.revokedAt = new Date().toISOString();
    token.replacedByTokenId = replacedByTokenId;
    saveState();
  },
  revokeUserRefreshTokens(userId) {
    for (const token of state.refreshTokens) {
      if (token.userId === userId && !token.revokedAt) {
        token.revokedAt = new Date().toISOString();
      }
    }
    saveState();
  },
  createEmailVerificationToken(token) {
    state.emailVerificationTokens.push(token);
    saveState();
  },
  findEmailVerificationToken(tokenHash) {
    return state.emailVerificationTokens.find(
      (token) => token.tokenHash === tokenHash && !token.usedAt && new Date(token.expiresAt) > new Date()
    ) ?? null;
  },
  markEmailVerificationTokenUsed(id) {
    const token = state.emailVerificationTokens.find((item) => item.id === id);
    if (!token) return;
    token.usedAt = new Date().toISOString();
    saveState();
  },
  createPasswordResetToken(token) {
    state.passwordResetTokens.push(token);
    saveState();
  },
  findPasswordResetToken(tokenHash) {
    return state.passwordResetTokens.find(
      (token) => token.tokenHash === tokenHash && !token.usedAt && new Date(token.expiresAt) > new Date()
    ) ?? null;
  },
  markPasswordResetTokenUsed(id) {
    const token = state.passwordResetTokens.find((item) => item.id === id);
    if (!token) return;
    token.usedAt = new Date().toISOString();
    saveState();
  },
  getSecurityStats() {
    const now = Date.now();
    const dayAgo = now - 24 * 60 * 60 * 1000;
    const recentEvents = state.auditEvents.filter((event) => new Date(event.createdAt).getTime() >= dayAgo);
    return {
      users: state.users.length,
      verifiedUsers: state.users.filter((user) => user.emailVerified).length,
      mfaEnabledUsers: state.users.filter((user) => user.mfaEnabled).length,
      activeRefreshTokens: state.refreshTokens.filter(
        (token) => !token.revokedAt && new Date(token.expiresAt) > new Date()
      ).length,
      eventsLast24h: recentEvents.length,
      failedLoginsLast24h: recentEvents.filter((event) => event.eventType === "login_failed").length,
      highRiskLoginsLast24h: recentEvents.filter((event) => Number(event.riskScore ?? 0) >= 70).length
    };
  }
};
