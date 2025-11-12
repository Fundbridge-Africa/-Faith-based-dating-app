import { Injectable, UnauthorizedException, ConflictException } from '@nestjs/common';
import { PrismaService } from '../config/prisma.service';
import * as bcrypt from 'bcryptjs';
import { RegisterUserDto } from './dto/register-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { JwtService } from '@nestjs/jwt';
import { Response, Request } from 'express';
import * as crypto from 'crypto';
import { ACCESS_COOKIE, REFRESH_COOKIE, cookieOpts } from './cookie.util/cookie.util';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwt: JwtService) {}

  // --- helpers ---
  private genRawRefresh(): string {
    return crypto.randomBytes(48).toString('hex');
  }
  private weekMs()   { return 7 * 24 * 60 * 60 * 1000 }
  private monthMs()  { return 30 * 24 * 60 * 60 * 1000 }
  private async hash(value: string) { return bcrypt.hash(value, 12); }
  private accessTtlMs() { return 15 * 60 * 1000; }       
  private refreshTtlMs() { return 7 * 24 * 60 * 60 * 1000; }
  private parseRefreshCookie(raw: string | undefined) {
    if (!raw) throw new UnauthorizedException('No refresh token');
    const [sessionId, token] = raw.split('.', 2);
    if (!sessionId || !token) throw new UnauthorizedException('Invalid refresh token');
    return { sessionId, token };
  }

  // --- core ---
  async register(dto: RegisterUserDto) {
    const email = dto.email.toLowerCase();
    const exists = await this.prisma.user.findUnique({ where: { email }, select: { id: true } });
    if (exists) throw new ConflictException('Email already in use');

    const passwordHash = await bcrypt.hash(dto.password, 12);
    const user = await this.prisma.user.create({
      data: {
        email,
        passwordHash,
        displayName: dto.displayName?.trim() || email.split('@')[0],
      },
      select: { id: true, email: true, displayName: true, verified: true, createdAt: true },
    });
    return { user };
  }

  async login(dto: LoginUserDto, req: Request, res: Response) {
  const email = dto.email.toLowerCase();
  const user = await this.prisma.user.findUnique({
    where: { email },
    select: { id: true, email: true, displayName: true, passwordHash: true, verified: true },
  });
  if (!user) throw new UnauthorizedException('Invalid credentials');

  const ok = await bcrypt.compare(dto.password, user.passwordHash);
  if (!ok) throw new UnauthorizedException('Invalid credentials');

  // issue access
  const accessToken = await this.jwt.signAsync({ sub: user.id, email: user.email });

  // per-device lifespan
  const lifeMs = dto.rememberMe ? this.monthMs() : this.weekMs();

  // session + refresh
  const raw = this.genRawRefresh();
  const refreshHash = await this.hash(raw);
  const expires = new Date(Date.now() + lifeMs);

  const ua = req.headers['user-agent'] as string | undefined;
  const ip =
    (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
    req.socket?.remoteAddress ||
    undefined;

  const session = await this.prisma.session.create({
    data: {
      userId: user.id,
      userAgent: ua,
      ip,
      refreshTokenHash: refreshHash,
      expiresAt: expires,
    },
    select: { id: true },
  });

  // cookies
  res.cookie(ACCESS_COOKIE, accessToken, cookieOpts(this.accessTtlMs()));
  res.cookie(REFRESH_COOKIE, `${session.id}.${raw}`, cookieOpts(lifeMs));

  const { passwordHash, ...safe } = user as any;
  return { user: safe };
}

async refresh(req: Request, res: Response) {
  const rawCookie = req.cookies?.[REFRESH_COOKIE];
  const { sessionId, token } = this.parseRefreshCookie(rawCookie);

  const session = await this.prisma.session.findUnique({
    where: { id: sessionId },
    select: { id: true, userId: true, refreshTokenHash: true, revokedAt: true, expiresAt: true, createdAt: true },
  });
  if (!session || session.revokedAt || session.expiresAt <= new Date()) {
    throw new UnauthorizedException('Invalid refresh token');
  }
  const ok = await bcrypt.compare(token, session.refreshTokenHash);
  if (!ok) throw new UnauthorizedException('Invalid refresh token');

  const user = await this.prisma.user.findUnique({
    where: { id: session.userId },
    select: { id: true, email: true, displayName: true, verified: true },
  });
  if (!user) throw new UnauthorizedException('User not found');

  // preserve original lifespan
  const lifeMs = session.expiresAt.getTime() - session.createdAt.getTime();
  const newRaw = this.genRawRefresh();
  const newHash = await this.hash(newRaw);
  const newExpires = new Date(Date.now() + lifeMs);

  const newSession = await this.prisma.session.create({
    data: {
      userId: user.id,
      refreshTokenHash: newHash,
      expiresAt: newExpires,
      userAgent: req.headers['user-agent'] as string | undefined,
      ip:
        (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
        req.socket?.remoteAddress ||
        undefined,
    },
    select: { id: true },
  });

  await this.prisma.session.update({
    where: { id: session.id },
    data: { revokedAt: new Date(), replacedByTokenId: newSession.id },
  });

  const accessToken = await this.jwt.signAsync({ sub: user.id, email: user.email });
  res.cookie(ACCESS_COOKIE, accessToken, cookieOpts(this.accessTtlMs()));
  res.cookie(REFRESH_COOKIE, `${newSession.id}.${newRaw}`, cookieOpts(lifeMs));

  return { user };
}

  async logout(req: Request, res: Response) {
    const rawCookie = req.cookies?.[REFRESH_COOKIE];
    const opts = cookieOpts(0);
    try {
      const { sessionId } = this.parseRefreshCookie(rawCookie);
      await this.prisma.session.update({
        where: { id: sessionId },
        data: { revokedAt: new Date() },
      });
    } catch { /* idempotent: ignore */ }
    res.clearCookie(ACCESS_COOKIE, { path: '/', sameSite: opts.sameSite, secure: opts.secure });
    res.clearCookie(REFRESH_COOKIE, { path: '/', sameSite: opts.sameSite, secure: opts.secure });
    return { ok: true };
  }
  async logoutAll(userId: string, res: Response) {
  await this.prisma.session.updateMany({
    where: { userId, revokedAt: null },
    data: { revokedAt: new Date() },
  });
  // clear cookies on this device too
  const opts = cookieOpts(0);
  res.clearCookie(ACCESS_COOKIE, { path: '/', sameSite: opts.sameSite, secure: opts.secure });
  res.clearCookie(REFRESH_COOKIE, { path: '/', sameSite: opts.sameSite, secure: opts.secure });
  return { ok: true };
}
}
