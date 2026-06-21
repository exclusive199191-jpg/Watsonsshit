import { drizzle } from "drizzle-orm/node-postgres";
import pg from "pg";
import * as schema from "./schema";

const { Pool } = pg;

const url = process.env.DATABASE_URL;

if (!url) {
  console.warn(
    "[db] WARNING: DATABASE_URL is not set. " +
    "All database-backed commands will be unavailable until it is configured."
  );
}

// Determine SSL config from the URL:
// - railway.internal hosts are on a private VPC — no SSL needed
// - sslmode=disable in the URL → no SSL
// - Everything else (external Railway proxy, Supabase, etc.) → SSL with self-signed cert support
function resolveSsl(connectionString: string): pg.PoolConfig["ssl"] {
  try {
    const u = new URL(connectionString);
    const sslmode = u.searchParams.get("sslmode");
    if (sslmode === "disable") return false;
    if (u.hostname.endsWith(".railway.internal")) return false;
    return { rejectUnauthorized: false };
  } catch {
    return { rejectUnauthorized: false };
  }
}

export const pool = url
  ? new Pool({
      connectionString: url,
      ssl: resolveSsl(url),
      keepAlive: true,
      keepAliveInitialDelayMillis: 10_000,
      idleTimeoutMillis: 5_000,
      connectionTimeoutMillis: 15_000,
      max: 5,
    })
  : null;

// Log pool-level errors so they appear in Railway structured logs
pool?.on("error", (err: Error) => {
  console.error(`[db] Pool connection error: ${err.message}`);
});

// Export the DB hostname (no credentials) for diagnostic logging
export function dbHostname(): string {
  if (!url) return "(not configured)";
  try {
    const u = new URL(url);
    return `${u.hostname}:${u.port || "5432"}`;
  } catch {
    return "(invalid URL)";
  }
}

export const db = url ? drizzle(pool as pg.Pool, { schema }) : null;

export * from "./schema";
