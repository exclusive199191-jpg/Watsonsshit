import app from "./app";
import { logger } from "./lib/logger";
import { startBot } from "./bot";
import { runMigrations } from "./migrate";

const rawPort = process.env["PORT"];

if (!rawPort) {
  throw new Error(
    "PORT environment variable is required but was not provided.",
  );
}

const port = Number(rawPort);

if (Number.isNaN(port) || port <= 0) {
  throw new Error(`Invalid PORT value: "${rawPort}"`);
}

// Start listening immediately so Railway health checks pass right away.
// Migration and bot startup happen async after the server is ready.
app.listen(port, async (err) => {
  if (err) {
    logger.error({ err }, "Error listening on port");
    process.exit(1);
  }

  logger.info({ port }, "Server listening");

  // Run migrations then start the bot — failures here are logged but do not
  // kill the HTTP server, so the health check keeps passing.
  try {
    await runMigrations();
  } catch (err) {
    logger.error({ err }, "Database migration failed");
  }

  startBot().catch((err) => {
    logger.error({ err }, "Discord bot failed to start");
  });
});
