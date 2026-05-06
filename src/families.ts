/// <reference types="@cloudflare/workers-types" />
import { Hono } from 'hono'
import type { Bindings, Variables } from './types'
import { requireAuth } from './middleware'

const families = new Hono<{ Bindings: Bindings; Variables: Variables }>()

function generateInviteCode(): string {
  // 読み間違えやすい 0,O,1,I を除いた文字セット
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
  const values = crypto.getRandomValues(new Uint8Array(6))
  return Array.from(values, v => chars[v % chars.length]).join('')
}

// ────────────────────────────────
// GET /families/me — 自分の所属家族を取得
// ────────────────────────────────
families.get('/me', requireAuth, async (c) => {
  const userId = c.get('userId')

  const family = await c.env.DB.prepare(`
    SELECT f.* FROM families f
    JOIN family_members fm ON f.id = fm.family_id
    WHERE fm.user_id = ?
    LIMIT 1
  `).bind(userId).first()

  return c.json({ family: family ?? null }, 200)
})

// ────────────────────────────────
// POST /families — 家族グループを新規作成
// ────────────────────────────────
families.post('/', requireAuth, async (c) => {
  const { name } = await c.req.json()
  if (!name) return c.json({ error: 'name は必須です' }, 400)

  const userId     = c.get('userId')
  const familyId   = crypto.randomUUID()
  const memberId   = crypto.randomUUID()
  const inviteCode = generateInviteCode()
  const now        = new Date().toISOString()

  await c.env.DB.prepare(`
    INSERT INTO families (id, name, invite_code, created_at)
    VALUES (?, ?, ?, ?)
  `).bind(familyId, name, inviteCode, now).run()

  await c.env.DB.prepare(`
    INSERT INTO family_members (id, family_id, user_id, role, joined_at)
    VALUES (?, ?, ?, 'owner', ?)
  `).bind(memberId, familyId, userId, now).run()

  // デフォルトラベルを挿入
  const defaultLabels = [
    { name: '家族', color: '#4CAF50' },       // green
    { name: '買い物', color: '#2196F3' },     // blue
    { name: 'お出かけ', color: '#FF5722' },   // orange
    { name: '仕事', color: '#9C27B0' },       // purple
    { name: 'その他', color: '#FF9800' },     // yellow
  ]

  for (const label of defaultLabels) {
    const labelId = crypto.randomUUID()
    await c.env.DB.prepare(`
      INSERT INTO labels (id, family_id, name, color, created_at)
      VALUES (?, ?, ?, ?, ?)
    `).bind(labelId, familyId, label.name, label.color, now).run()
  }

  const family = await c.env.DB.prepare('SELECT * FROM families WHERE id = ?')
    .bind(familyId).first()

  return c.json({ family }, 201)
})

// ────────────────────────────────
// POST /families/join — 招待コードで家族に参加
// ────────────────────────────────
families.post('/join', requireAuth, async (c) => {
  const { invite_code } = await c.req.json()
  if (!invite_code) return c.json({ error: 'invite_code は必須です' }, 400)

  const userId = c.get('userId')

  const family = await c.env.DB.prepare(
    'SELECT * FROM families WHERE invite_code = ?'
  ).bind(invite_code.toUpperCase()).first() as any

  if (!family) return c.json({ error: '招待コードが正しくありません' }, 404)

  const existing = await c.env.DB.prepare(
    'SELECT id FROM family_members WHERE family_id = ? AND user_id = ?'
  ).bind(family.id, userId).first()

  if (existing) return c.json({ error: 'すでにこの家族に参加しています' }, 409)

  const memberId = crypto.randomUUID()
  const now      = new Date().toISOString()

  await c.env.DB.prepare(`
    INSERT INTO family_members (id, family_id, user_id, role, joined_at)
    VALUES (?, ?, ?, 'member', ?)
  `).bind(memberId, family.id, userId, now).run()

  return c.json({ family }, 200)
})

// ────────────────────────────────
// PUT /families/me — 自宅住所を更新
// ────────────────────────────────
families.put('/me', requireAuth, async (c) => {
  const userId = c.get('userId')
  const { home_address } = await c.req.json()

  const member = await c.env.DB.prepare(
    'SELECT family_id FROM family_members WHERE user_id = ? LIMIT 1'
  ).bind(userId).first() as any

  if (!member) return c.json({ error: '家族グループに参加していません' }, 404)

  await c.env.DB.prepare(
    'UPDATE families SET home_address = ? WHERE id = ?'
  ).bind(home_address ?? null, member.family_id).run()

  const family = await c.env.DB.prepare('SELECT * FROM families WHERE id = ?')
    .bind(member.family_id).first()

  return c.json({ family }, 200)
})

export default families
