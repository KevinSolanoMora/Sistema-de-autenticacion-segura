import { config } from "./config.js";

export async function scoreLoginRisk({ email, ipAddress, userAgent }) {
  try {
    const response = await fetch(`${config.riskServiceUrl}/risk/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, ip_address: ipAddress, user_agent: userAgent })
    });

    if (!response.ok) {
      return { score: 50, reason: "risk-service-unavailable" };
    }

    return response.json();
  } catch {
    return { score: 50, reason: "risk-service-offline" };
  }
}
