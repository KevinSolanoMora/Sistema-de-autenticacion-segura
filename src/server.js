import cors from "cors";
import express from "express";
import helmet from "helmet";
import morgan from "morgan";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import authRoutes from "./routes/authRoutes.js";
import dashboardRoutes from "./routes/dashboardRoutes.js";
import { authRateLimit } from "./middleware.js";
import { config } from "./config.js";
import "./database.js";

const app = express();
const __dirname = dirname(fileURLToPath(import.meta.url));

app.disable("x-powered-by");
app.use(helmet());
app.use(cors({ origin: false }));
app.use(express.json({ limit: "20kb" }));
app.use(morgan("combined"));
app.use(express.static(join(__dirname, "..", "public")));

app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: "secure-auth-api" });
});

app.use("/auth", authRateLimit, authRoutes);
app.use("/dashboard", dashboardRoutes);

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: "Error interno." });
});

app.listen(config.port, () => {
  console.log(`Secure auth API running on http://localhost:${config.port}`);
});
