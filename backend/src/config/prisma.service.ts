import { INestApplication, Injectable, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit {
  async onModuleInit() {
    await this.$connect();
      // create TTL index for sessions
    try {
      await this.$runCommandRaw({
        createIndexes: 'Session',
        indexes: [
          {
            key: { expiresAt: 1 },
            name: 'Session_expiresAt_ttl',
            expireAfterSeconds: 0, // TTL index
          },
        ],
      });
    } catch (e) {
      // ignore if index already exists
      if (!e.message.includes('Index with name')) {
        throw e;
      }
    }
  }
  async enableShutdownHooks(app: INestApplication) {
    process.on('beforeExit', () => {
      app.close();
    });
  }
}