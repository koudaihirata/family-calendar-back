import { Hono } from "hono";
import { Bindings } from "./types";

const calendar = new Hono<{Bindings: Bindings}>()

calendar.get('/calendar', async (c) => {
    const userId = c.req.query('user_id')
    if (!userId) return c.json({ todoList: [], genreList: [], total: 0 })
})

export default calendar