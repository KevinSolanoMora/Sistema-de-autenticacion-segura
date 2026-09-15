import { Router } from "express";
import { db } from "../database.js";
import { requireAdmin, requireAuth } from "../middleware.js";

const router = Router();

router.get("/summary", requireAuth, (req, res) => {
  res.json({
    stats: db.getSecurityStats(),
    user: db.findUserById(req.user.id)
  });
});

router.get("/audit", requireAuth, (req, res) => {
  const limit = Math.min(Number(req.query.limit ?? 50), 200);
  const events = db
    .listAuditEvents(limit)
    .filter((event) => event.userId === req.user.id || !event.userId)
    .map((event) => ({
      id: event.id,
      eventType: event.eventType,
      riskScore: event.riskScore,
      createdAt: event.createdAt
    }));

  res.json({ events });
});

router.get("/admin/audit", requireAuth, requireAdmin, (req, res) => {
  const limit = Math.min(Number(req.query.limit ?? 100), 500);
  res.json({ events: db.listAuditEvents(limit) });
});

router.get("/admin/users", requireAuth, requireAdmin, (_req, res) => {
  res.json({ users: db.listUsers() });
});

export default router;
