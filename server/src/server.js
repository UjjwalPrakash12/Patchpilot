const mongoose = require('mongoose');
const app = require('./app');
const config = require('./config');

let server;

async function startServer() {
  try {
    console.log(`[INFO] Connecting to MongoDB at ${config.MONGODB_URI}...`);
    await mongoose.connect(config.MONGODB_URI, {
      serverSelectionTimeoutMS: 5000,
    });
    console.log('[INFO] Successfully connected to MongoDB database.');

    server = app.listen(config.PORT, () => {
      console.log(`[INFO] PatchPilot server listening on port ${config.PORT} (${config.NODE_ENV})`);
      console.log(`[INFO] Health check available at http://localhost:${config.PORT}/api/health`);
    });
  } catch (err) {
    console.error('[ERROR] Failed to start server:', err.message);
    process.exit(1);
  }
}

// Graceful shutdown handling
function gracefulShutdown(signal) {
  console.log(`\n[INFO] Received ${signal}. Closing server gracefully...`);
  if (server) {
    server.close(async () => {
      console.log('[INFO] HTTP server closed.');
      try {
        await mongoose.connection.close();
        console.log('[INFO] MongoDB connection closed.');
      } catch (dbErr) {
        console.error('[ERROR] Error closing MongoDB connection:', dbErr.message);
      }
      process.exit(0);
    });
  } else {
    process.exit(0);
  }
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

startServer();

module.exports = server;
