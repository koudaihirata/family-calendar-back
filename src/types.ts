import type { D1Database } from '@cloudflare/workers-types'

export type Bindings = {
    DB: D1Database
    JWT_SECRET: string          // wrangler secret put JWT_SECRET で登録
    ALLOWED_ORIGIN: string      // wrangler.jsonc の vars に登録
    GOOGLE_CLIENT_ID: string
    GOOGLE_CLIENT_SECRET: string // wrangler secret put GOOGLE_CLIENT_SECRET で登録
}
