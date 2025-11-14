import { Injectable, UnauthorizedException, ConflictException } from '@nestjs/common';
import { PrismaService } from '../../core/database/prisma.service';
import * as bcrypt from 'bcryptjs';
import { RegisterUserDto } from './dto/register-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { JwtService } from '@nestjs/jwt';
import { Response, Request } from 'express';
import * as crypto from 'crypto';
import { ACCESS_COOKIE, REFRESH_COOKIE, cookieOpts } from './cookie.util';

const MAX_SESSIONS = 5; // cap simultaneous devices (evict oldest when exceeded)

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwt: JwtService) {}

  // --- helpers ---
  private genRawRefresh(): string {
    return crypto.randomBytes(48).toString('hex'); // 96 hex chars
  }
  private weekMs() { return 7 * 24 * 60 * 60 * 1000; }
  private monthMs() { return 30 * 24 * 60 * 60 * 1000; }
  private async hash(value: string) { return bcrypt.hash(value, 12); }
  private accessTtlMs() { return 15 * 60 * 1000; } // 15m
  private parseRefreshCookie(raw: string | undefined) {
    if (!raw) throw new UnauthorizedException('No refresh token');
    const [sessionId, token] = raw.split('.', 2);
    if (!sessionId || !token) throw new UnauthorizedException('Invalid refresh token');
    return { sessionId, token };
  }
  private ipFrom(req: Request) {
    return (
      (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
      req.socket?.remoteAddress ||
      undefined
    );
  }
  private uaFrom(req: Request) {
    return req.headers['user-agent'] as string | undefined;
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
        // no restrictions on name as requested
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

    // issue access (bind to session later via sid)
    // we'll sign after we create the session to include sid
    const lifeMs = dto.rememberMe ? this.monthMs() : this.weekMs();
    const raw = this.genRawRefresh();
    const refreshHash = await this.hash(raw);
    const expiresAt = new Date(Date.now() + lifeMs);

    // limit concurrent sessions (evict oldest active if over cap)
    const active = await this.prisma.session.findMany({
      where: { userId: user.id, revokedAt: null, expiresAt: { gt: new Date() } },
      select: { id: true },
      orderBy: { createdAt: 'asc' }, // oldest first
    });
    if (active.length >= MAX_SESSIONS) {
      await this.prisma.session.update({
        where: { id: active[0].id },
        data: { revokedAt: new Date() },
      });
    }

    const session = await this.prisma.session.create({
      data: {
        userId: user.id,
        userAgent: this.uaFrom(req),
        ip: this.ipFrom(req),
        refreshTokenHash: refreshHash,
        expiresAt,
      },
      select: { id: true },
    });

    const accessToken = await this.jwt.signAsync({
      sub: user.id,
      email: user.email,
      sid: session.id, // bind access token to this session (optional check in guards)
    });

    // cookies (httpOnly)
    res.cookie(ACCESS_COOKIE, accessToken, cookieOpts(this.accessTtlMs()));
    res.cookie(REFRESH_COOKIE, `${session.id}.${raw}`, cookieOpts(lifeMs));

    const { passwordHash, ...safe } = user as any;
    return { user: safe };
  }

  async refresh(req: Request, res: Response) {
    const rawCookie = req.cookies?.[REFRESH_COOKIE];
    const { sessionId, token } = this.parseRefreshCookie(rawCookie);

    // find session by id (deterministic)
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

    // preserve original lifespan across rotations
    const lifeMs = session.expiresAt.getTime() - session.createdAt.getTime();
    const newRaw = this.genRawRefresh();
    const newHash = await this.hash(newRaw);
    const newExpiresAt = new Date(Date.now() + lifeMs);

    const newSession = await this.prisma.session.create({
      data: {
        userId: user.id,
        refreshTokenHash: newHash,
        expiresAt: newExpiresAt,
        userAgent: this.uaFrom(req),
        ip: this.ipFrom(req),
      },
      select: { id: true },
    });

    // revoke old session
    await this.prisma.session.update({
      where: { id: session.id },
      data: { revokedAt: new Date(), replacedByTokenId: newSession.id },
    });

    // new access (bound to new sid)
    const accessToken = await this.jwt.signAsync({
      sub: user.id,
      email: user.email,
      sid: newSession.id,
    });

    // set cookies again
    res.cookie(ACCESS_COOKIE, accessToken, cookieOpts(this.accessTtlMs()));
    res.cookie(REFRESH_COOKIE, `${newSession.id}.${newRaw}`, cookieOpts(lifeMs));

    return { user };
  }

  async logout(req: Request, res: Response) {
    const rawCookie = req.cookies?.[REFRESH_COOKIE];
    try {
      const { sessionId } = this.parseRefreshCookie(rawCookie);
      await this.prisma.session.update({
        where: { id: sessionId },
        data: { revokedAt: new Date() },
      });
    } catch {
      // idempotent: ignore parse errors or missing session
    }
    const opts = cookieOpts(0);
    res.clearCookie(ACCESS_COOKIE, { path: '/', sameSite: opts.sameSite, secure: opts.secure });
    res.clearCookie(REFRESH_COOKIE, { path: '/', sameSite: opts.sameSite, secure: opts.secure });
    return { ok: true };
  }

  async logoutAll(userId: string, res: Response) {
    await this.prisma.session.updateMany({
      where: { userId, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    const opts = cookieOpts(0);
    res.clearCookie(ACCESS_COOKIE, { path: '/', sameSite: opts.sameSite, secure: opts.secure });
    res.clearCookie(REFRESH_COOKIE, { path: '/', sameSite: opts.sameSite, secure: opts.secure });
    return { ok: true };
  }

  // optional; wire a controller route later if you want
  async me(payload: { sub: string }) {
    const row = await this.prisma.user.findUnique({
      where: { id: payload.sub },
      select: { id: true, email: true, displayName: true, verified: true, createdAt: true },
    });
    if (!row) throw new UnauthorizedException();
    return { user: row };
  }
}
