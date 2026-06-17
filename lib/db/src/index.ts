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

export const pool = url ? new Pool({ connectionString: url }) : null;
export const db = url ? drizzle(pool as pg.Pool, { schema }) : null;

export * from "./schema";
