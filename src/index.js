import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import pg from 'pg';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });

const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.sendStatus(401);
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.sendStatus(403);
  }
};

app.post('/auth/register', async (req, res) => {
  const { email, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  await pool.query('INSERT INTO users (email, password) VALUES ($1, $2)', [email, hash]);
  res.sendStatus(201);
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  const user = result.rows[0];
  if (!user || !(await bcrypt.compare(password, user.password))) return res.sendStatus(401);
  const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET);
  res.json({ token });
});

app.post('/flows/save', authMiddleware, async (req, res) => {
  const { name, data } = req.body;
  await pool.query('INSERT INTO flows (user_id, name, data) VALUES ($1, $2, $3)', [req.user.id, name, data]);
  res.sendStatus(201);
});

app.put('/flows/:id', authMiddleware, async (req, res) => {
  const { name, data } = req.body;
  await pool.query('UPDATE flows SET name=$1, data=$2 WHERE id=$3 AND user_id=$4', [name, data, req.params.id, req.user.id]);
  res.sendStatus(200);
});

app.get('/flows/:id', authMiddleware, async (req, res) => {
  const result = await pool.query('SELECT * FROM flows WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
  res.json(result.rows[0]);
});

app.get('/flows/list', authMiddleware, async (req, res) => {
  const result = await pool.query('SELECT * FROM flows WHERE user_id=$1 ORDER BY created_at DESC', [req.user.id]);
  res.json(result.rows);
});

app.delete('/flows/:id', authMiddleware, async (req, res) => {
  await pool.query('DELETE FROM flows WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
  res.sendStatus(204);
});

app.listen(process.env.PORT, () => console.log(`Server running on port ${process.env.PORT}`));
