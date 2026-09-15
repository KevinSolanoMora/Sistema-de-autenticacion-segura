import { randomUUID } from "node:crypto";
import { db } from "./database.js";

export function audit(event) {
  db.addAuditEvent({
    id: randomUUID(),
    userId: event.userId ?? null,
    email: event.email ?? null,
    eventType: event.eventType,
    ipAddress: event.ipAddress ?? null,
    userAgent: event.userAgent ?? null,
    riskScore: event.riskScore ?? null,
    createdAt: new Date().toISOString()
  });
}
