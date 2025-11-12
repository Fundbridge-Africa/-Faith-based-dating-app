export class CookieUtil {}
export const ACCESS_COOKIE = 'accessToken';
export const REFRESH_COOKIE = 'refreshToken';

export function cookieOpts(ttlMs: number) {
  const isProd = process.env.NODE_ENV === 'production';
  return { 
    httpOnly: true, 
    sameSite: 'lax' as const,
    secure: isProd, 
    path: '/', 
    maxAge: ttlMs };
}