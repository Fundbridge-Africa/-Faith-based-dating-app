import { Global, Module } from '@nestjs/common';
import Redis, { RedisOptions } from 'ioredis';

export const REDIS_PUB = Symbol('REDIS_PUB');
export const REDIS_SUB = Symbol('REDIS_SUB');

function buildRedis(): Redis {
  const url = process.env.REDIS_URL;
  if (url) return new Redis(url);
  const opts: RedisOptions = {
    host: process.env.REDIS_HOST ?? '127.0.0.1',
    port: +(process.env.REDIS_PORT ?? 6379),
    password: process.env.REDIS_PASSWORD || undefined,
  };
  return new Redis(opts);
}

@Global()
@Module({
  providers: [
    {
      provide: REDIS_PUB,
      useFactory: () => buildRedis(),
    },
    {
      provide: REDIS_SUB,
      useFactory: (pub: Redis) => pub.duplicate(),
      inject: [REDIS_PUB],
    },
  ],
  exports: [REDIS_PUB, REDIS_SUB],
})
export class RedisModule {}
