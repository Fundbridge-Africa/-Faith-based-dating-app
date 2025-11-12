import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ConfigModule } from '@nestjs/config';
import { AppConfigModule } from './config/config.module';

@Module({
  imports: [ConfigModule.forRoot({ isGlobal: true }),AppConfigModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
