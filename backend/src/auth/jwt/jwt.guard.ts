import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(private readonly jwt: JwtService) {}

  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest<Request>();

    const cookieToken = req.cookies?.['accessToken'];
    const header = req.headers['authorization'];
    const headerToken = typeof header === 'string' && header.startsWith('Bearer ')
      ? header.slice(7)
      : undefined;

    const token = cookieToken || headerToken;
    if (!token) throw new UnauthorizedException('Missing access token');

    try {
      const payload = this.jwt.verify(token, { secret: process.env.JWT_ACCESS_SECRET! });

      (req as any).user = payload;
      return true;
    } catch {
      throw new UnauthorizedException('Invalid or expired access token');
    }
  }
}
