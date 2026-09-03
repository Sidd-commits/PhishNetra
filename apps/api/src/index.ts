import { createApp } from './app';
import { config } from './config/env';
import { prisma } from './db/prisma';

const app = createApp();

const server = app.listen(config.port, () => {
  console.log(`
======================================================
🛡️  PhishNetra REST API (Milestone 1)
------------------------------------------------------
• Environment: ${config.env}
• Port:        ${config.port}
• CORS Origin: ${config.corsOrigin}
• ML Service:  ${config.mlService.url}
• Status:      Active & Ready
======================================================
  `);
});

const gracefulShutdown = async () => {
  console.log('\n[PhishNetra] Shutting down server gracefully...');
  server.close(async () => {
    await prisma.$disconnect();
    console.log('[PhishNetra] Database connections closed. Process terminated.');
    process.exit(0);
  });
};

process.on('SIGINT', gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);
