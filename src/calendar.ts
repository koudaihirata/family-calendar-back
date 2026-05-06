/// <reference types="@cloudflare/workers-types" />
import { Hono } from 'hono'
import type { Bindings, Variables } from './types'
import { requireAuth } from './middleware'

const calendar = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// ────────────────────────────────
// GET /events?year=2026&month=5
// ────────────────────────────────
calendar.get('/events', requireAuth, async (c) => {
  const userId = c.get('userId')
  const now = new Date()
  const year   = parseInt(c.req.query('year') ?? '') || now.getFullYear()
  const month  = parseInt(c.req.query('month') ?? '') || (now.getMonth() + 1)

  const member = await c.env.DB.prepare(
    'SELECT family_id FROM family_members WHERE user_id = ? LIMIT 1'
  ).bind(userId).first() as any

  if (!member) return c.json({ events: [] })

  const startDate = new Date(year, month - 1, 1).toISOString()
  const endDate   = new Date(year, month, 1).toISOString()

  const result = await c.env.DB.prepare(`
    SELECT
      e.*,
      l.id    AS label_id_join,
      l.name  AS label_name,
      l.color AS label_color
    FROM events e
    LEFT JOIN labels l ON e.label_id = l.id
    WHERE e.family_id = ? AND e.start_at >= ? AND e.start_at < ?
    ORDER BY e.start_at ASC
  `).bind(member.family_id, startDate, endDate).all() as any

  const events = result.results || []
  return c.json({ events })
})

// ────────────────────────────────
// POST /events
// ────────────────────────────────
calendar.post('/events', requireAuth, async (c) => {
  const userId = c.get('userId')
  const { title, start_at, end_at, label_id, location_name } = await c.req.json()

  if (!title || !start_at || !end_at) {
    return c.json({ error: 'title・start_at・end_at は必須です' }, 400)
  }

  const member = await c.env.DB.prepare(
    'SELECT family_id FROM family_members WHERE user_id = ? LIMIT 1'
  ).bind(userId).first() as any

  if (!member) return c.json({ error: '家族グループに参加していません' }, 404)

  const id  = crypto.randomUUID()
  const now = new Date().toISOString()

  await c.env.DB.prepare(`
    INSERT INTO events
      (id, family_id, created_by, label_id, title, start_at, end_at, location_name, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(id, member.family_id, userId, label_id ?? null, title, start_at, end_at, location_name ?? null, now, now).run()

  const event = await c.env.DB.prepare('SELECT * FROM events WHERE id = ?').bind(id).first()
  return c.json({ event }, 201)
})

// ────────────────────────────────
// GET /labels
// ────────────────────────────────
calendar.get('/labels', requireAuth, async (c) => {
  const userId = c.get('userId')

  const member = await c.env.DB.prepare(
    'SELECT family_id FROM family_members WHERE user_id = ? LIMIT 1'
  ).bind(userId).first() as any

  if (!member) return c.json({ labels: [] })

  const { results } = await c.env.DB.prepare(
    'SELECT * FROM labels WHERE family_id = ? ORDER BY created_at ASC'
  ).bind(member.family_id).all()

  return c.json({ labels: results })
})

export default calendar
