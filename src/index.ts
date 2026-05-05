import { Hono } from 'hono'
import { cors } from 'hono/cors'
import type { Bindings } from './types'
import auth from './auth'
import calendar from './calendar'

const app = new Hono<{ Bindings: Bindings }>()

// CORS: Cookie を使うためにオリジンを固定・credentials を許可
app.use('*', async (c, next) => {
  return cors({
    origin: c.env.ALLOWED_ORIGIN || '*',
    credentials: true,
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowHeaders: ['Content-Type'],
  })(c, next)
})

app.get('/', (c) => c.text('Hello Hono!'))

app.route('/', auth)
app.route('/', calendar)

export default app
