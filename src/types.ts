import type { D1Database } from '@cloudflare/workers-types'

export type Bindings = {
  DB: D1Database
  JWT_SECRET: string
  ALLOWED_ORIGIN: string
  GOOGLE_CLIENT_ID: string
  GOOGLE_CLIENT_SECRET: string
}

export type Variables = {
  userId: string
}
