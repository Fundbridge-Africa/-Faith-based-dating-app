# MatcherHub (Faith‑based Dating App) — Backend

Backend for the MatcherHub project built with **NestJS + Prisma + MongoDB**.  
Production‑ready **cookie‑based auth** with per‑device sessions, **rotating refresh tokens**, **Remember Me**, **logout per device** and **logout‑all**. Includes TTL auto‑cleanup for sessions and a clean, testable structure.

---

## ✨ Features

- **NestJS** application, structured modules
- **Prisma (MongoDB)** data access
- **Cookie‑based JWT**:
  - `accessToken` (15m) — httpOnly cookie
  - `refreshToken` (7d by default, 30d with Remember Me) — httpOnly cookie
  - Refresh cookie format: `sessionId.rawToken` (deterministic lookup)
- **Per‑device sessions** (each device has its own session row)
- **Rotating refresh** on every `POST /auth/refresh`
- **Remember Me** (30 days for that device)
- **Logout (this device)** and **Logout‑all** (revoke all sessions)
- **Max concurrent devices**: 5 (evict oldest active session on new login)
- **TTL index** on `Session.expiresAt` for auto cleanup
- Clean guard (`JwtAuthGuard`) for protected routes

---

## 🧱 Tech Stack

- Node 20+ / NestJS 10+
- Prisma 5+ (MongoDB)
- JWT (access), bcrypt (passwords), httpOnly cookies
- Class‑validator / Class‑transformer

---

## 🚀 Quick Start

### 1) Requirements
- Node.js 20+
- MongoDB Atlas (or local MongoDB) — create a DB named `matcherhub`

### 2) Clone & Install
```bash
npm install
```

### 3) Environment
Create `.env` in the **backend** folder:

```env
# Server
PORT=3000
API_PREFIX=/api/v1
NODE_ENV=development

# JWT
JWT_ACCESS_SECRET=replace_with_long_random_string

# MongoDB (note the database name at the end!)
DATABASE_URL="mongodb+srv://<user>:<pass>@<cluster>.mongodb.net/matcherhub?retryWrites=true&w=majority"
```

> If you see Prisma `P1013` invalid database string, ensure the **database name** is present (e.g., `/matcherhub`).

### 4) Prisma (Mongo)
```bash
npx prisma generate --schema=./prisma/schema.prisma
npx prisma db push --schema=./prisma/schema.prisma
```

### 5) Run dev
```bash
npm run start:dev
```

The API will be at: `http://localhost:${PORT}${API_PREFIX}` (e.g., `http://localhost:3000/api/v1`).

---

## 🔐 Auth Endpoints

Base: `${API_PREFIX}/auth`

| Method | Path         | Body / Notes                                                                                   | Auth |
|-------:|--------------|-------------------------------------------------------------------------------------------------|:----:|
| POST   | `/register`  | `{ email, password, displayName? }`                                                            |  –   |
| POST   | `/login`     | `{ email, password, rememberMe? }` → sets `accessToken` (15m) + `refreshToken` (7d/30d)        |  –   |
| POST   | `/refresh`   | – uses `refreshToken` cookie (`sessionId.rawToken`) → rotates cookies                          |  –   |
| POST   | `/logout`    | – revokes **only this device** session; clears cookies                                         |  –   |
| POST   | `/logout-all`| – revokes **all** active sessions for current user; clears cookies on this device              | JWT |
| GET    | `/me`        | – returns current user (optional endpoint; add when needed)                                    | JWT |

**Cookie names**: `accessToken`, `refreshToken`  
**Cookie options (dev)**: `httpOnly`, `sameSite:lax`, `secure:false`  
**Cookie options (prod)**: `httpOnly`, `sameSite:none`, `secure:true`, HTTPS only, CORS configured

**Session policy**:
- Max **5** concurrent devices (oldest evicted on new login beyond cap)
- `refreshToken` rotates each refresh
- `logout` affects only current device; `logout-all` kills every device

---

## 🧪 Testing Scenarios

Use **Thunder Client** profiles or **Newman** with per‑device cookie jars.

### Newman (Windows PowerShell one‑liners)
```powershell
# Device A
newman run .\FaithDating.postman_collection.json -e .\local.postman_environment.json --cookie-jar .\A.cookies

# Device B
newman run .\FaithDating.postman_collection.json -e .\local.postman_environment.json --cookie-jar .\B.cookies
```

**Happy path**:
1. Login A → Refresh A → OK  
2. Login B → Refresh B → OK  
3. Logout A → Refresh A = 401, Refresh B = OK (per‑device verified)

**Remember Me verification**:
- Login with `{ rememberMe: true }` → `refreshToken.Max-Age ≈ 2592000` (30d)
- Without rememberMe → `Max-Age ≈ 604800` (7d)  
- After `refresh`, `Max-Age` remains the same as original for that device

---

## ⚙️ Production Notes

- Set `sameSite: 'none'` and `secure: true` for cookies (HTTPS only)
- Configure **CORS** to allow your frontend origin and send cookies (`credentials: true`)
- Optionally verify `sid` (session id) from access token in guards for sensitive routes
- Add **rate limiting** on `/auth/login` to prevent brute‑force attempts
- Use a long, random `JWT_ACCESS_SECRET`

---

## 🗄️ Prisma Models (excerpt)

```prisma
model User {
  id           String   @id @default(auto()) @map("_id") @db.ObjectId
  email        String   @unique
  passwordHash String
  displayName  String
  verified     Boolean  @default(false)
  createdAt    DateTime @default(now())
  updatedAt    DateTime @updatedAt
}

model Session {
  id                String   @id @default(auto()) @map("_id") @db.ObjectId
  userId            String   @db.ObjectId
  userAgent         String?
  ip                String?
  refreshTokenHash  String
  expiresAt         DateTime
  createdAt         DateTime @default(now())
  revokedAt         DateTime?
  replacedByTokenId String?  @db.ObjectId

  @@index([userId])
  @@index([expiresAt])
}
```

> The app ensures a TTL index on `Session.expiresAt` (auto‑cleanup). If you ever see a Mongo index conflict during startup in dev, just drop the old index and restart.

---

## 🧰 Troubleshooting

- **P1013 Invalid Mongo URL** → include the **database name** at the end of `DATABASE_URL`.
- **IndexOptionsConflict (code 85)** on startup → an existing non‑TTL index on `expiresAt` conflicts with TTL creation. Drop it once:
  ```js
  use matcherhub
  db.Session.dropIndex("Session_expiresAt_idx")
  ```
  then restart.
- **PowerShell line continuation errors** → use one‑liners or PowerShell backticks `` ` `` for multi‑line commands.

---

## 📦 Scripts

```bash
npm run start         # dev (non-watch)
npm run start:dev     # dev watch mode
npm run build         # compile TS
npm run start:prod    # run compiled dist
npm run test          # unit tests (if any)
npm run test:e2e      # e2e tests (if any)
```

---

## 📄 License

MIT
