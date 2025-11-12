import { INestApplication, Injectable, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';


@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit {
  async onModuleInit() {
    await this.$connect();

    // (Optional but recommended) Ensure TTL index on Session.expiresAt.
    // This code will NOT crash if an equivalent index already exists.
    try {
      // 1) List current indexes
      const list: any = await this.$runCommandRaw({ listIndexes: 'Session' });
      const indexes = list?.cursor?.firstBatch ?? [];

      // find index on { expiresAt: 1 }
      const targetKey = JSON.stringify({ expiresAt: 1 });
      const existing = indexes.find((i: any) => JSON.stringify(i.key) === targetKey);

      // 2) If no index → create TTL index
      if (!existing) {
        await this.$runCommandRaw({
          createIndexes: 'Session',
          indexes: [
            {
              key: { expiresAt: 1 },
              name: 'Session_expiresAt_ttl',
              expireAfterSeconds: 0, // expire exactly at expiresAt
            },
          ],
        });
      } else {
        // 3) If index exists but is NOT TTL, drop and recreate as TTL
        if (typeof existing.expireAfterSeconds !== 'number') {
          await this.$runCommandRaw({ dropIndexes: 'Session', index: existing.name });
          await this.$runCommandRaw({
            createIndexes: 'Session',
            indexes: [
              {
                key: { expiresAt: 1 },
                name: 'Session_expiresAt_ttl',
                expireAfterSeconds: 0,
              },
            ],
          });
        }
        // If it is already TTL, we’re fine (even if the name differs).
      }
    } catch (e: any) {
      // Don’t crash the app if index ops fail in dev
      console.warn('TTL index setup skipped:', e?.message ?? e);
    }
  }

  // If you still want graceful shutdown:
  async enableShutdownHooks(app: INestApplication) {
    process.on('beforeExit', () => {
      app.close();
    });
  }
}