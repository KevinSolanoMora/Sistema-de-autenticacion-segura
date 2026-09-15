import dotenv from "dotenv";

dotenv.config();

export const config = {
  port: Number(process.env.PORT ?? 3000),
  jwtSecret: process.env.JWT_SECRET ?? "dev-only-secret-change-me-please-32chars",
  jwtIssuer: process.env.JWT_ISSUER ?? "sistema-auth-segura",
  jwtAudience: process.env.JWT_AUDIENCE ?? "portfolio-users",
  databasePath: process.env.DATABASE_PATH ?? "./data/auth.db",
  riskServiceUrl: process.env.PYTHON_RISK_SERVICE_URL ?? "http://127.0.0.1:8000",
  appUrl: process.env.APP_URL ?? "http://localhost:3000",
  devExposeTokens: process.env.DEV_EXPOSE_TOKENS !== "false"
};
