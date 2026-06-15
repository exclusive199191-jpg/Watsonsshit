import { Router, type IRouter } from "express";
import { HealthCheckResponse } from "@workspace/api-zod";

const router: IRouter = Router();

// Lightweight health check — returns 200 as soon as the HTTP server is up.
// Railway uses this to decide whether the deployment succeeded; we keep it
// fast and dependency-free so it never blocks behind DB or bot startup.
router.get("/healthz", (_req, res) => {
  const data = HealthCheckResponse.parse({ status: "ok" });
  res.json(data);
});

export default router;
