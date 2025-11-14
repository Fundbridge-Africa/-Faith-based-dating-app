import { INestApplication } from '@nestjs/common';
import { IoAdapter } from '@nestjs/platform-socket.io';
import { createAdapter } from '@socket.io/redis-adapter';
import type { ServerOptions } from 'socket.io';
import Redis from 'ioredis';

export class RedisIoAdapter extends IoAdapter {
  private adapter: ReturnType<typeof createAdapter> | null = null;

  constructor(
    app: INestApplication,
    private readonly pubClient: Redis, // <-- now valid
    private readonly subClient: Redis,
  ) {
    super(app);
  }

   async connectToRedis() {
    await this.pubClient.ping();
    await this.subClient.ping();
    this.adapter = createAdapter(this.pubClient, this.subClient);
  }

  override createIOServer(port: number, options?: ServerOptions) {
    const cors = {
      origin: (process.env.FRONTEND_ORIGIN ?? 'http://localhost:5173').split(','),
      credentials: true,
    };
    const server = super.createIOServer(port, { ...options, cors });
    // Attach the Redis adapter if it's been initialized
    if (this.adapter) server.adapter(this.adapter);
    return server;
  }
}
