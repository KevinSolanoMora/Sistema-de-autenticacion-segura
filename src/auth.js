import { hash, verify } from "@node-rs/argon2";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { SignJWT, jwtVerify } from "jose";
import { generateSecret, generateURI, verify as verifyOtp } from "otplib";
import { config } from "./config.js";

const encoder = new TextEncoder();
const secret = encoder.encode(config.jwtSecret);

export async function hashPassword(password) {
  return hash(password, {
    memoryCost: 19456,
    timeCost: 2,
    outputLen: 32,
    parallelism: 1
  });
}

export async function verifyPassword(passwordHash, password) {
  return verify(passwordHash, password);
}

export async function createAccessToken(user) {
  return new SignJWT({ role: user.role })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(user.id)
    .setIssuer(config.jwtIssuer)
    .setAudience(config.jwtAudience)
    .setIssuedAt()
    .setExpirationTime("15m")
    .sign(secret);
}

export const createToken = createAccessToken;

export async function verifyToken(token) {
  return jwtVerify(token, secret, {
    issuer: config.jwtIssuer,
    audience: config.jwtAudience
  });
}

export function createOpaqueToken() {
  return randomBytes(32).toString("base64url");
}

export function hashOpaqueToken(token) {
  return createHash("sha256").update(token).digest("hex");
}

export function createRefreshTokenRecord(userId, req) {
  const token = createOpaqueToken();
  const id = randomUUID();
  return {
    rawToken: token,
    record: {
      id,
      userId,
      tokenHash: hashOpaqueToken(token),
      ipAddress: req.ip,
      userAgent: req.get("user-agent") ?? null,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
      revokedAt: null,
      replacedByTokenId: null
    }
  };
}

export function createOneTimeTokenRecord(userId, minutes = 30) {
  const token = createOpaqueToken();
  return {
    rawToken: token,
    record: {
      id: randomUUID(),
      userId,
      tokenHash: hashOpaqueToken(token),
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + minutes * 60 * 1000).toISOString(),
      usedAt: null
    }
  };
}

export function createTotpSecret(email) {
  const secret = generateSecret();
  return {
    secret,
    otpauthUrl: generateURI({
      issuer: "Sistema de autenticacion segura",
      label: email,
      secret
    })
  };
}

export async function verifyTotp(secret, code) {
  const result = await verifyOtp({ secret, token: code });
  return result.valid;
}
