import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import cookieParser from 'cookie-parser';
import { PrismaService } from './config/prisma.service';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const prismaService = app.get(PrismaService);
  const port = process.env.PORT ? Number(process.env.PORT) : 3000;
  const prefix = process.env.API_PREFIX || '/api/v1';

  app.use(cookieParser());
  await prismaService.enableShutdownHooks(app);
  app.setGlobalPrefix(prefix);
  await app.listen(port);
}
bootstrap();
