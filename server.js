const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const db = require('./db');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 5000;

// POST /login - Authenticate user
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  console.log('\n========== LOGIN ATTEMPT ==========');
  console.log('📧 Email received    :', email);
  console.log('🔑 Password received :', password);

  if (!email || !password) {
    console.log('❌ Missing email or password');
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);

    console.log('📦 DB rows found     :', result.rows.length);

    if (result.rows.length === 0) {
      console.log('❌ No user found with that email in DB');
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];
    console.log('👤 User from DB      :', JSON.stringify(user, null, 2));
    console.log('🔐 Password in DB    :', user.password);

    // Verify password: Check plain text first (if inserted manually), then try bcrypt
    let validPassword = false;
    if (password === user.password) {
      validPassword = true;
      console.log('✅ Password matched (plain text)');
    } else {
      try {
        validPassword = await bcrypt.compare(password, user.password);
        console.log('✅ bcrypt compare result:', validPassword);
      } catch (e) {
        console.log('⚠️  bcrypt compare error:', e.message);
        validPassword = false;
      }
    }

    if (!validPassword) {
      console.log('❌ Password mismatch — login denied');
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    console.log('🎉 Login successful for:', user.email);
    console.log('====================================\n');

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        email: user.email
      }
    });

  } catch (err) {
    console.error('🔥 Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /logout - Handle logout
// For JWT, logout is primarily handled client-side by discarding the token.
// A backend endpoint provides a clean confirmation and a place to add token blacklisting if needed.
app.post('/logout', (req, res) => {
  res.json({ message: 'Logout successful. Please discard your token.' });
});

// Basic test route
app.get('/', (req, res) => {
  res.send('Backend API is running...');
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
