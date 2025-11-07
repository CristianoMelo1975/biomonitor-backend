import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import pg from 'pg'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'

const { Pool } = pg

// Pool compatível com Neon (SSL). Se a URL já tem ?sslmode=require, ok.
// Caso contrário, força SSL seguro.
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('sslmode=require')
    ? undefined
    : { rejectUnauthorized: false }
})

const app = express()
app.use(express.json())
app.use(cors({ origin: process.env.CORS_ORIGIN?.split(',') || '*' }))

app.get('/', (_req, res) => res.json({ ok: true, service: 'biomonitor-backend' }))

// ---------- AUTH ----------
app.post('/auth/register', async (req, res) => {
  const { name, email, password, role } = req.body
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Missing fields' })
  }
  try {
    const hash = await bcrypt.hash(password, 10)
    const r = await pool.query(
      'INSERT INTO users(name,email,password_hash,role) VALUES($1,$2,$3,$4) RETURNING id,name,email,role',
      [name, email, hash, role === 'ADMIN' ? 'ADMIN' : 'BASIC']
    )
    res.json(r.rows[0])
  } catch (e) {
    console.error('REGISTER ERROR:', e)
    res.status(400).json({ error: 'User exists?' })
  }
})

app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body
    const r = await pool.query('SELECT * FROM users WHERE email=$1', [email])
    const u = r.rows[0]
    if (!u) return res.status(401).json({ error: 'Invalid credentials' })
    const ok = await bcrypt.compare(password, u.password_hash)
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' })
    if (!process.env.JWT_SECRET) {
      console.error('JWT_SECRET is missing!')
      return res.status(500).json({ error: 'Server misconfigured (JWT_SECRET)' })
    }
    const token = jwt.sign(
      { id: u.id, role: u.role, name: u.name },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    )
    res.json({ token, user: { id: u.id, name: u.name, email: u.email, role: u.role } })
  } catch (e) {
    console.error('LOGIN ERROR:', e)
    res.status(500).json({ error: 'Internal error' })
  }
})

function requireAuth(req, res, next) {
  const header = req.headers.authorization || ''
  const token = header.startsWith('Bearer ') ? header.slice(7) : null
  if (!token) return res.status(401).json({ error: 'No token' })
  try { req.user = jwt.verify(token, process.env.JWT_SECRET); next() }
  catch { return res.status(401).json({ error: 'Invalid token' }) }
}
function requireAdmin(req, res, next) {
  if (req.user?.role !== 'ADMIN') return res.status(403).json({ error: 'Admin only' })
  next()
}

// ---------- EQUIPMENT ----------
app.post('/equipment', requireAuth, async (req, res) => {
  const { tag, name, local, estado, descricao } = req.body;

  if (!tag || !name) {
    return res.status(400).json({ error: 'TAG e Nome são obrigatórios' });
  }

  try {
    const r = await pool.query(
      `INSERT INTO equipment (tag, name, local, estado, descricao)
       VALUES ($1,$2,$3,$4,$5)
       RETURNING *`,
      [tag, name, local || null, estado || null, descricao || null]
    );
    res.json(r.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Falha ao criar equipamento' });
  }
});


// ---------- DIAGNÓSTICO ----------
app.get('/diag', async (_req, res) => {
  try {
    const db = await pool.query('SELECT 1')
    const users = await pool.query('SELECT COUNT(*) FROM users')
    res.json({
      ok: true,
      db: db?.rows?.length === 1,
      users: Number(users.rows[0].count || 0),
      jwtSecretPresent: !!process.env.JWT_SECRET
    })
  } catch (e) {
    console.error('DIAG ERROR:', e)
    res.status(500).json({ ok: false, error: String(e) })
  }
})

const port = process.env.PORT || 4000
const host = process.env.HOST || '0.0.0.0'
app.listen(port, host, () => console.log(`Backend running on http://${host}:${port}`))
