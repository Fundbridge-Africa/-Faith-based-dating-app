import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterUserDto } from './dto/register-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import type { Request, Response } from 'express';
import { Req, Res } from '@nestjs/common';


@Controller('auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @Post('register')
  register(@Body() dto: RegisterUserDto) {
    return this.auth.register(dto);
  }

  @Post('login')
  login(@Body() dto: LoginUserDto, @Req() req: Request, @Res({ passthrough: true }) res: Response) {
    return this.auth.login(dto, req, res);
  }

  @Post('refresh')
  refresh(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    return this.auth.refresh(req, res);
  }

  @Post('logout')
  logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    return this.auth.logout(req, res);
  }
}