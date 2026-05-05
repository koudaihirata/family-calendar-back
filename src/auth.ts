/// <reference types="@cloudflare/workers-types" />
import { Hono } from 'hono'
import { sign, verify } from 'hono/jwt'
import { getCookie, setCookie, deleteCookie } from 'hono/cookie'
import type { Bindings } from './types'

const auth = new Hono<{ Bindings: Bindings }>()

const ACCESS_EXPIRY  = 7  * 24 * 60 * 60  // 7日
const REFRESH_EXPIRY = 30 * 24 * 60 * 60  // 30日

const cookieBase = {
  httpOnly: true,
  secure: true,
  sameSite: 'None' as const,
  path: '/',
}

async function hashPassword(password: string): Promise<string> {
  const enc  = new TextEncoder()
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const key  = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 100000 },
    key, 256
  )
  const toB64 = (u: Uint8Array) => btoa(String.fromCharCode(...u))
  return `pbkdf2:100000:${toB64(salt)}:${toB64(new Uint8Array(bits))}`
}

async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [, , saltB64, hashB64] = stored.split(':')
  const salt     = Uint8Array.from(atob(saltB64), (ch: string) => ch.charCodeAt(0))
  const expected = Uint8Array.from(atob(hashB64), (ch: string) => ch.charCodeAt(0))
  const enc  = new TextEncoder()
  const key  = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 100000 },
    key, 256
  )
  const actual = new Uint8Array(bits)
  if (actual.length !== expected.length) return false
  let diff = 0
  for (let i = 0; i < actual.length; i++) diff |= actual[i] ^ expected[i]
  return diff === 0
}

// ────────────────────────────────
// POST /register — 新規ユーザー登録
// ────────────────────────────────
auth.post('/register', async (c) => {
  const { email, password, name } = await c.req.json()

  if (!email || !password || !name) {
    return c.json({ error: 'email・password・name は必須です' }, 400)
  }

  const existing = await c.env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first()
  if (existing) return c.json({ error: 'このメールアドレスは既に使用されています' }, 409)

  const id            = crypto.randomUUID()
  const password_hash = await hashPassword(password)
  const now           = new Date().toISOString()

  await c.env.DB.prepare(`
    INSERT INTO users (id, name, email, password_hash, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).bind(id, name, email, password_hash, now).run()

  const user = await c.env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(id).first() as any

  const nowSec = Math.floor(Date.now() / 1000)
  const accessToken  = await sign({ sub: user.id, exp: nowSec + ACCESS_EXPIRY  }, c.env.JWT_SECRET, 'HS256')
  const refreshToken = await sign({ sub: user.id, type: 'refresh', exp: nowSec + REFRESH_EXPIRY }, c.env.JWT_SECRET, 'HS256')

  setCookie(c, 'access_token',  accessToken,  { ...cookieBase, maxAge: ACCESS_EXPIRY  })
  setCookie(c, 'refresh_token', refreshToken, { ...cookieBase, maxAge: REFRESH_EXPIRY })

  const { password_hash: _, ...safeUser } = user
  return c.json({ user: safeUser }, 201)
})

// ────────────────────────────────
// POST /login — ログイン
// ────────────────────────────────
auth.post('/login', async (c) => {
  const { email, password } = await c.req.json()

  if (!email || !password) {
    return c.json({ error: 'email・password は必須です' }, 400)
  }

  const user = await c.env.DB.prepare(
    'SELECT * FROM users WHERE email = ?'
  ).bind(email).first() as any

  if (!user || !user.password_hash || !(await verifyPassword(password, user.password_hash))) {
    return c.json({ error: 'メールアドレスまたはパスワードが違います' }, 401)
  }

  const nowSec = Math.floor(Date.now() / 1000)
  const accessToken  = await sign({ sub: user.id, exp: nowSec + ACCESS_EXPIRY  }, c.env.JWT_SECRET, 'HS256')
  const refreshToken = await sign({ sub: user.id, type: 'refresh', exp: nowSec + REFRESH_EXPIRY }, c.env.JWT_SECRET, 'HS256')

  setCookie(c, 'access_token',  accessToken,  { ...cookieBase, maxAge: ACCESS_EXPIRY  })
  setCookie(c, 'refresh_token', refreshToken, { ...cookieBase, maxAge: REFRESH_EXPIRY })

  const { password_hash, ...safeUser } = user
  return c.json({ user: safeUser }, 200)
})

// ────────────────────────────────
// GET /me — ユーザー情報取得（access_token 期限切れなら refresh_token で自動更新）
// ────────────────────────────────
auth.get('/me', async (c) => {
  const accessToken = getCookie(c, 'access_token')

  if (accessToken) {
    try {
      const payload = await verify(accessToken, c.env.JWT_SECRET, 'HS256')
      const user = await c.env.DB.prepare(
        'SELECT * FROM users WHERE id = ?'
      ).bind(payload.sub).first() as any

      if (user) {
        const { password_hash, ...safeUser } = user
        return c.json({ user: safeUser }, 200)
      }
    } catch { /* 期限切れ → refresh_token で試みる */ }
  }

  const refreshToken = getCookie(c, 'refresh_token')
  if (!refreshToken) return c.json({ error: 'Unauthorized' }, 401)

  try {
    const payload = await verify(refreshToken, c.env.JWT_SECRET, 'HS256')
    const user = await c.env.DB.prepare(
      'SELECT * FROM users WHERE id = ?'
    ).bind(payload.sub).first() as any

    if (!user) return c.json({ error: 'Unauthorized' }, 401)

    const nowSec = Math.floor(Date.now() / 1000)
    const newAccessToken = await sign({ sub: user.id, exp: nowSec + ACCESS_EXPIRY }, c.env.JWT_SECRET, 'HS256')
    setCookie(c, 'access_token', newAccessToken, { ...cookieBase, maxAge: ACCESS_EXPIRY })

    const { password_hash, ...safeUser } = user
    return c.json({ user: safeUser }, 200)
  } catch {
    return c.json({ error: 'Unauthorized' }, 401)
  }
})

// ────────────────────────────────
// POST /logout — Cookie を削除してログアウト
// ────────────────────────────────
auth.post('/logout', (c) => {
  deleteCookie(c, 'access_token',  { path: '/', secure: true, sameSite: 'None' })
  deleteCookie(c, 'refresh_token', { path: '/', secure: true, sameSite: 'None' })
  return c.json({ success: true }, 200)
})

// ────────────────────────────────
// GET /auth/google — Google OAuth 認証画面にリダイレクト
// ────────────────────────────────
auth.get('/auth/google', (c) => {
  const backendOrigin = new URL(c.req.url).origin
  const redirectUri   = `${backendOrigin}/auth/google/callback`

  const params = new URLSearchParams({
    client_id:     c.env.GOOGLE_CLIENT_ID,
    redirect_uri:  redirectUri,
    response_type: 'code',
    scope:         'openid email profile',
    access_type:   'offline',
  })

  return c.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`)
})

// ────────────────────────────────
// GET /auth/google/callback — コード受け取り → JWT 発行 → フロントへリダイレクト
// ────────────────────────────────
auth.get('/auth/google/callback', async (c) => {
  const code = c.req.query('code')
  if (!code) return c.redirect(`${c.env.ALLOWED_ORIGIN}/login?error=oauth_failed`)

  const backendOrigin = new URL(c.req.url).origin
  const redirectUri   = `${backendOrigin}/auth/google/callback`

  const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id:     c.env.GOOGLE_CLIENT_ID,
      client_secret: c.env.GOOGLE_CLIENT_SECRET,
      redirect_uri:  redirectUri,
      grant_type:    'authorization_code',
    }),
  })

  const tokenData = await tokenRes.json() as any
  if (!tokenRes.ok) return c.redirect(`${c.env.ALLOWED_ORIGIN}/login?error=oauth_failed`)

  const userRes   = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
    headers: { Authorization: `Bearer ${tokenData.access_token}` },
  })
  const googleUser = await userRes.json() as any
  if (!userRes.ok || !googleUser.email) {
    return c.redirect(`${c.env.ALLOWED_ORIGIN}/login?error=oauth_failed`)
  }

  const now = new Date().toISOString()
  let user  = await c.env.DB.prepare(
    'SELECT * FROM users WHERE email = ?'
  ).bind(googleUser.email).first() as any

  if (!user) {
    const id = crypto.randomUUID()
    await c.env.DB.prepare(`
      INSERT INTO users (id, name, email, avatar_url, created_at)
      VALUES (?, ?, ?, ?, ?)
    `).bind(id, googleUser.name ?? googleUser.email, googleUser.email, googleUser.picture ?? null, now).run()

    user = await c.env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(id).first() as any
  }

  const nowSec = Math.floor(Date.now() / 1000)
  const accessToken  = await sign({ sub: user.id, exp: nowSec + ACCESS_EXPIRY  }, c.env.JWT_SECRET, 'HS256')
  const refreshToken = await sign({ sub: user.id, type: 'refresh', exp: nowSec + REFRESH_EXPIRY }, c.env.JWT_SECRET, 'HS256')

  setCookie(c, 'access_token',  accessToken,  { ...cookieBase, maxAge: ACCESS_EXPIRY  })
  setCookie(c, 'refresh_token', refreshToken, { ...cookieBase, maxAge: REFRESH_EXPIRY })

  return c.redirect(c.env.ALLOWED_ORIGIN)
})

export default auth
