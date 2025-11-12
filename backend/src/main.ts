import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import cookieParser from 'cookie-parser';
import { PrismaService } from './config/prisma.service';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const prismaService = app.get(PrismaService);
  const port = process.env.PORT ? Number(process.env.PORT) : 3000;

  app.use(cookieParser());
  await prismaService.enableShutdownHooks(app);
  app.setGlobalPrefix(process.env.API_PREFIX || '/api/v1');
  app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }));
  await app.listen(port);
}
bootstrap();