import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import cookieParser from 'cookie-parser';
import { RedisIoAdapter } from './core/ws/socket.adapter';
import { REDIS_PUB, REDIS_SUB } from './core/redis/redis.module';
import type Redis from 'ioredis';


async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.use(cookieParser());
  app.setGlobalPrefix(process.env.API_PREFIX ?? 'api/v1');
  app.enableCors({ origin: (process.env.FRONTEND_ORIGIN ?? 'http://localhost:5173').split(','), credentials: true });

  try {
    const pub = app.get<Redis>(REDIS_PUB);
    const sub = app.get<Redis>(REDIS_SUB);
    const adapter = new RedisIoAdapter(app, pub, sub);
    await adapter.connectToRedis();
    app.useWebSocketAdapter(adapter);
    console.log('WS: Redis adapter enabled');
  } catch (e: any) {
    console.warn('WS: Redis not connected, using default in-memory adapter:', e?.message ?? e);
  }

  await app.listen(process.env.PORT ? +process.env.PORT : 3000);
}
bootstrap();