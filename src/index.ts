import { Hono } from 'hono'
import { cors } from 'hono/cors'
import type { Bindings, Variables } from './types'
import auth from './auth'
import calendar from './calendar'
import families from './families'

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>()

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
app.route('/families', families)
app.route('/', calendar)

export default app
