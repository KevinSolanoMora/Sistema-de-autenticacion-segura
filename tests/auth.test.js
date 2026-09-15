import assert from "node:assert/strict";
import test from "node:test";
import {
  createAccessToken,
  createOpaqueToken,
  createTotpSecret,
  hashOpaqueToken,
  hashPassword,
  verifyPassword,
  verifyToken
} from "../src/auth.js";

test("passwords are hashed and verified with Argon2", async () => {
  const password = "PasswordSeguro123";
  const passwordHash = await hashPassword(password);

  assert.notEqual(passwordHash, password);
  assert.equal(await verifyPassword(passwordHash, password), true);
  assert.equal(await verifyPassword(passwordHash, "PasswordIncorrecto123"), false);
});

test("access tokens are signed with expected claims", async () => {
  const user = { id: "user-123", role: "user" };
  const token = await createAccessToken(user);
  const { payload } = await verifyToken(token);

  assert.equal(payload.sub, user.id);
  assert.equal(payload.role, user.role);
});

test("opaque tokens are random and stored as hashes", () => {
  const first = createOpaqueToken();
  const second = createOpaqueToken();

  assert.notEqual(first, second);
  assert.equal(hashOpaqueToken(first).length, 64);
  assert.notEqual(hashOpaqueToken(first), first);
});

test("totp setup returns a secret and otpauth url", () => {
  const setup = createTotpSecret("demo@correo.com");

  assert.ok(setup.secret.length > 10);
  assert.match(setup.otpauthUrl, /^otpauth:\/\/totp\//);
});
