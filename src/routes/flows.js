const express = require('express');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const router = express.Router();
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

router.post('/save', authenticateToken, async (req, res) => {
  const { name, data } = req.body;
  try {
    await pool.query(
      'INSERT INTO flows (user_id, name, data) VALUES ($1, $2, $3)',
      [req.user.userId, name, JSON.stringify(data)]
    );
    res.status(201).send('Flow saved');
  } catch (err) {
    res.status(400).send('Save error');
  }
});

router.get('/list', authenticateToken, async (req, res) => {
  const result = await pool.query('SELECT id, name, created_at FROM flows WHERE user_id = $1 ORDER BY id DESC', [req.user.userId]);
  res.json(result.rows);
});

router.get('/:id', authenticateToken, async (req, res) => {
  const result = await pool.query('SELECT * FROM flows WHERE id = $1 AND user_id = $2', [req.params.id, req.user.userId]);
  res.json(result.rows[0]);
});

router.put('/:id', authenticateToken, async (req, res) => {
  const { data } = req.body;
  await pool.query('UPDATE flows SET data = $1 WHERE id = $2 AND user_id = $3', [JSON.stringify(data), req.params.id, req.user.userId]);
  res.send('Flow updated');
});

router.delete('/:id', authenticateToken, async (req, res) => {
  await pool.query('DELETE FROM flows WHERE id = $1 AND user_id = $2', [req.params.id, req.user.userId]);
  res.send('Flow deleted');
});

module.exports = router;