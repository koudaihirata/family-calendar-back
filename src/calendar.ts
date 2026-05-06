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

// ────────────────────────────────
// GET /events/:id — 単一イベント取得
// ────────────────────────────────
calendar.get('/events/:id', requireAuth, async (c) => {
  const userId  = c.get('userId')
  const eventId = c.req.param('id')

  const member = await c.env.DB.prepare(
    'SELECT family_id FROM family_members WHERE user_id = ? LIMIT 1'
  ).bind(userId).first() as any

  if (!member) return c.json({ error: 'Unauthorized' }, 401)

  const event = await c.env.DB.prepare(`
    SELECT e.*, l.name AS label_name, l.color AS label_color
    FROM events e
    LEFT JOIN labels l ON e.label_id = l.id
    WHERE e.id = ? AND e.family_id = ?
  `).bind(eventId, member.family_id).first()

  if (!event) return c.json({ error: 'イベントが見つかりません' }, 404)
  return c.json({ event })
})

// ────────────────────────────────
// PUT /events/:id — イベント更新
// ────────────────────────────────
calendar.put('/events/:id', requireAuth, async (c) => {
  const userId  = c.get('userId')
  const eventId = c.req.param('id')
  const { title, start_at, end_at, label_id, location_name } = await c.req.json()

  const member = await c.env.DB.prepare(
    'SELECT family_id FROM family_members WHERE user_id = ? LIMIT 1'
  ).bind(userId).first() as any

  if (!member) return c.json({ error: 'Unauthorized' }, 401)

  const existing = await c.env.DB.prepare(
    'SELECT id FROM events WHERE id = ? AND family_id = ?'
  ).bind(eventId, member.family_id).first()

  if (!existing) return c.json({ error: 'イベントが見つかりません' }, 404)

  const now = new Date().toISOString()
  await c.env.DB.prepare(`
    UPDATE events
    SET title = ?, start_at = ?, end_at = ?, label_id = ?, location_name = ?, updated_at = ?
    WHERE id = ?
  `).bind(title, start_at, end_at, label_id ?? null, location_name ?? null, now, eventId).run()

  const event = await c.env.DB.prepare(`
    SELECT e.*, l.name AS label_name, l.color AS label_color
    FROM events e LEFT JOIN labels l ON e.label_id = l.id
    WHERE e.id = ?
  `).bind(eventId).first()

  return c.json({ event })
})

// ────────────────────────────────
// POST /labels — ラベルを新規作成
// ────────────────────────────────
calendar.post('/labels', requireAuth, async (c) => {
  const userId = c.get('userId')
  const { name, color } = await c.req.json()

  if (!name || !color) return c.json({ error: 'name・color は必須です' }, 400)

  const member = await c.env.DB.prepare(
    'SELECT family_id FROM family_members WHERE user_id = ? LIMIT 1'
  ).bind(userId).first() as any

  if (!member) return c.json({ error: '家族グループに参加していません' }, 404)

  const id  = crypto.randomUUID()
  const now = new Date().toISOString()

  await c.env.DB.prepare(
    'INSERT INTO labels (id, family_id, name, color, created_at) VALUES (?, ?, ?, ?, ?)'
  ).bind(id, member.family_id, name, color, now).run()

  const label = await c.env.DB.prepare('SELECT * FROM labels WHERE id = ?').bind(id).first()
  return c.json({ label }, 201)
})

// ────────────────────────────────
// DELETE /labels/:id — ラベルを削除
// ────────────────────────────────
calendar.delete('/labels/:id', requireAuth, async (c) => {
  const userId  = c.get('userId')
  const labelId = c.req.param('id')

  const member = await c.env.DB.prepare(
    'SELECT family_id FROM family_members WHERE user_id = ? LIMIT 1'
  ).bind(userId).first() as any

  if (!member) return c.json({ error: 'Unauthorized' }, 401)

  const label = await c.env.DB.prepare(
    'SELECT * FROM labels WHERE id = ? AND family_id = ?'
  ).bind(labelId, member.family_id).first()

  if (!label) return c.json({ error: 'ラベルが見つかりません' }, 404)

  await c.env.DB.prepare('DELETE FROM labels WHERE id = ?').bind(labelId).run()
  return c.json({ success: true })
})

export default calendar
