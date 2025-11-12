import { Injectable, UnauthorizedException, ConflictException } from '@nestjs/common';
import { PrismaService } from '../config/prisma.service';
import * as bcrypt from 'bcryptjs';
import { RegisterUserDto } from './dto/register-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { JwtService } from '@nestjs/jwt';
import { Response, Request } from 'express';
import * as crypto from 'crypto';
import { ACCESS_COOKIE, REFRESH_COOKIE, cookieOpts } from './cookie.util/cookie.util';
import { JwtPayload } from '../auth/jwt-payload/jwt-payload';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwt: JwtService) {}

  private genRefreshToken() {
    return crypto.randomBytes(48).toString('hex'); // 96 chars
  }

  private async hash(value: string) {
    return await bcrypt.hash(value, 12);
  }

  private accessTtlMs() { return 15 * 60 * 1000; } 
  
  private refreshTtlMs() { return 7 * 24 * 60 * 60 * 1000; } 

  async register(dto: RegisterUserDto) {
    const email = dto.email.toLowerCase();

    const exists = await this.prisma.user.findUnique({
      where: { email },
      select: { id: true },
    });
    if (exists) throw new ConflictException('Email already in use');

    const passwordHash = await bcrypt.hash(dto.password, 12);

    // fallback display name if not provided
    const fallbackName = email.split('@')[0];
    const displayName = dto.displayName?.trim() || fallbackName;

    const user = await this.prisma.user.create({
      data: { email, passwordHash, displayName },
      select: { id: true, email: true, displayName: true, verified: true, createdAt: true },
    });

    return { user };
  }

  async login(dto: LoginUserDto, req: Request, res: Response) {
  const user = await this.prisma.user.findUnique({
    where: { email: dto.email.toLowerCase() },
    select: { id: true, email: true, displayName: true, passwordHash: true, verified: true },
  });
  if (!user) throw new UnauthorizedException('Invalid credentials');

  const ok = await bcrypt.compare(dto.password, user.passwordHash);
  if (!ok) throw new UnauthorizedException('Invalid credentials');

  // issue access
  const accessToken = await this.jwt.signAsync({ sub: user.id, email: user.email });

  // create refresh session (per device)
  const rawRefresh = this.genRefreshToken();
  const refreshHash = await this.hash(rawRefresh);
  const now = new Date();
  const expires = new Date(now.getTime() + this.refreshTtlMs());

  const ua = req.headers['user-agent'] || undefined;
  const ip =
    (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
    req.socket?.remoteAddress ||
    undefined;

  await this.prisma.session.create({
    data: {
      userId: user.id,
      userAgent: typeof ua === 'string' ? ua : undefined,
      ip: typeof ip === 'string' ? ip : undefined,
      refreshTokenHash: refreshHash,
      expiresAt: expires,
    },
  });

  // set cookies
  res.cookie(ACCESS_COOKIE, accessToken, cookieOpts(this.accessTtlMs()));
  res.cookie(REFRESH_COOKIE, rawRefresh, cookieOpts(this.refreshTtlMs()));

  const { passwordHash, ...safe } = user;
  return { user: safe };
}

async logout(req: Request, res: Response) {
  const raw = req.cookies?.[REFRESH_COOKIE];
  if (raw) {
    const candidates = await this.prisma.session.findMany({
      where: { revokedAt: null, expiresAt: { gt: new Date() } },
    });
    for (const s of candidates) {
      if (await bcrypt.compare(raw, s.refreshTokenHash)) {
        await this.prisma.session.update({
          where: { id: s.id },
          data: { revokedAt: new Date() },
        });
        break;
      }
    }
  }
  res.clearCookie(ACCESS_COOKIE, { path: '/' });
  res.clearCookie(REFRESH_COOKIE, { path: '/' });
  return { ok: true };
}

async refresh(req: Request, res: Response) {
  const raw = req.cookies?.[REFRESH_COOKIE];
  if (!raw) throw new UnauthorizedException('No refresh token');

  const session = await this.prisma.session.findFirst({
    where: { revokedAt: null, expiresAt: { gt: new Date() } },
    orderBy: { createdAt: 'desc' }, // most recent first (optional)
  });

  // We must check against all active sessions to find a match
  // (Mongo doesn't support hashing compare; we pull candidates then compare)
  const candidates = await this.prisma.session.findMany({
    where: {
      revokedAt: null,
      expiresAt: { gt: new Date() },
    },
  });

  let matched: typeof candidates[number] | null = null;
  for (const s of candidates) {
    if (await bcrypt.compare(raw, s.refreshTokenHash)) { matched = s; break; }
  }
  if (!matched) throw new UnauthorizedException('Invalid refresh token');

  const user = await this.prisma.user.findUnique({
    where: { id: matched.userId },
    select: { id: true, email: true, displayName: true, verified: true },
  });
  if (!user) throw new UnauthorizedException('User not found');

  // rotate: revoke old, create new
  const newRaw = this.genRefreshToken();
  const newHash = await this.hash(newRaw);
  const now = new Date();
  const expires = new Date(now.getTime() + this.refreshTtlMs());

  const newSession = await this.prisma.session.create({
    data: {
      userId: user.id,
      refreshTokenHash: newHash,
      expiresAt: expires,
      userAgent: req.headers['user-agent'] || undefined,
      ip:
        (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
        req.socket?.remoteAddress ||
        undefined,
    },
  });

  await this.prisma.session.update({
    where: { id: matched.id },
    data: { revokedAt: new Date(), replacedByTokenId: newSession.id },
  });

  // new access
  const accessToken = await this.jwt.signAsync({ sub: user.id, email: user.email });

  // set cookies
  res.cookie(ACCESS_COOKIE, accessToken, cookieOpts(this.accessTtlMs()));
  res.cookie(REFRESH_COOKIE, newRaw, cookieOpts(this.refreshTtlMs()));

  return { user };
  }
  async me(user: JwtPayload) {
    const row = await this.prisma.user.findUnique({
      where: { id: user.sub },
      select: { id: true, email: true, displayName: true, verified: true, createdAt: true },
    });
    if (!row) throw new (require('@nestjs/common').UnauthorizedException)();
    return { user: row };
}
}
