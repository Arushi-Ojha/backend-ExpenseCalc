const mysql = require('mysql2');
const express = require('express');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
const PORT = 3000;
const otpStorage = {};
const { OAuth2Client } = require('google-auth-library');
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

app.use(express.json());
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'arushiojha100@gmail.com',
    pass: 'opmv xlzv iuzi aipy',
  },
});
const db = mysql.createConnection({
  host: 'shinkansen.proxy.rlwy.net',
  port: 27131,
  user: 'root',
  password: 'JvgyawowgQmbjujYWuAWyCoyEhlNqvoQ',
  database: 'railway',
});

db.connect((err) => {
  if (err) {
    console.error('MySQL connection failed:', err.message);
    return;
  }
  console.log('Connected to MySQL Database');
});

app.get('/api/users/:username', (req, res) => {
  const { username } = req.params;

  const query = 'SELECT email ,budget, password FROM users WHERE username = ?';
  db.query(query, [username], (err, results) => {
    if (err) {
      console.error('Error fetching user details:', err.message);
      return res.status(500).json({ error: 'Database error' });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const { email, budget, password } = results[0];
    res.json({ username, email, budget, password });
  });
});

//=========================REGISTER========================
app.post('/api/users/request-otp', (req, res) => {
  const { username, email, password, budget } = req.body;

  if (!username || !email || !password || budget == null) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  otpStorage[username] = { otp, userData: { username, email, password, budget }, createdAt: Date.now() };

  const mailOptions = {
    from: 'arushiojha100@gmail.com',
    to: email,
    subject: 'Your OTP for Expense Calculator',
    text: `Your OTP is: ${otp}`,
  };

  transporter.sendMail(mailOptions, (err, info) => {
    if (err) {
      console.error('Error sending email:', err.message);
      return res.status(500).json({ error: 'Failed to send OTP' });
    }
    res.json({ message: 'OTP sent successfully to email' });
  });
});
app.post('/api/users/verify-otp', async (req, res) => {
  const { username, otp } = req.body;

  const record = otpStorage[username];
  if (!record) return res.status(400).json({ error: 'No OTP requested for this user' });

  const { userData } = record;

  if (record.otp !== otp) {
    return res.status(400).json({ error: 'Invalid OTP' });
  }

  try {
    const hashedPassword = await bcrypt.hash(userData.password, 10);
    const query = 'INSERT INTO users (username, email, password, budget) VALUES (?, ?, ?, ?)';

    db.query(query, [userData.username, userData.email, hashedPassword, userData.budget], (err, result) => {
      if (err) {
        console.error('DB Error:', err.message);
        return res.status(500).json({ error: 'Database error' });
      }

      delete otpStorage[username];
      res.status(201).json({ message: 'User registered successfully', userId: result.insertId });
    });
  } catch (error) {
    console.error('Hashing error:', error.message);
    res.status(500).json({ error: 'Server error during registration' });
  }
});


//========================EDIT PROFILE====================
app.put('/api/users/:username', (req, res) => {
  const { username } = req.params;
  const { email, password, budget } = req.body;

  if (!email || !password || budget == null) {
    return res.status(400).json({ error: 'All fields (email, password, budget) are required for update' });
  }

  const query = 'UPDATE users SET email = ?, password = ?, budget = ? WHERE username = ?';
  db.query(query, [email, password, budget, username], (err, result) => {
    if (err) {
      console.error('Error updating user:', err.message);
      return res.status(500).json({ error: 'Database error' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ message: 'User updated successfully' });
  });
});

//========================LOG IN==========================
app.post('/api/users/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const query = 'SELECT password FROM users WHERE username = ?';
  db.query(query, [username], async (err, results) => {
    if (err) {
      console.error('DB error:', err.message);
      return res.status(500).json({ error: 'Database error' });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const isMatch = await bcrypt.compare(password, results[0].password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Incorrect password' });
    }

    res.json({ message: 'Login successful', username });
  });
});

app.post('/api/google-login', async (req, res) => {
  const { credential } = req.body; 

  if (!credential) {
    return res.status(400).json({ error: 'No token provided' });
  }

  try {
    const ticket = await client.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    const email = payload.email;

    const query = 'SELECT username FROM users WHERE email = ?';
    db.query(query, [email], (err, results) => {
      if (err) {
        console.error('DB error:', err.message);
        return res.status(500).json({ error: 'Database error' });
      }

      if (results.length === 0) {
        return res.status(404).json({ error: 'No user found for this email' });
      }

      res.json({ email, username: results[0].username });
    });
  } catch (err) {
    console.error('Google token verification error:', err.message);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
});


//=======================ADD EXPENSE========================
app.post('/api/expenses', (req, res) => {
  const { username, amount, category, description, date } = req.body;

  if (!username || !amount || !category || !description || !date) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  const getUserIdQuery = 'SELECT id FROM users WHERE username = ?';
  db.query(getUserIdQuery, [username], (err, results) => {
    if (err) {
      console.error('Error fetching user ID:', err.message);
      return res.status(500).json({ error: 'Database error while fetching user ID' });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user_id = results[0].id;
    const insertExpenseQuery = `
      INSERT INTO expense (user_id, amount, category, description, date)
      VALUES (?, ?, ?, ?, ?)
    `;

    db.query(
      insertExpenseQuery,
      [user_id, amount, category, description, date],
      (err, result) => {
        if (err) {
          console.error('Error inserting expense:', err.message);
          return res.status(500).json({ error: 'Database error while inserting expense' });
        }

        res.status(201).json({
          message: 'Expense added successfully',
          expenseId: result.insertId,
        });
      }
    );
  });
});

//=======================FETCH ALL EXPENSE==================
app.get('/api/expenses/:username', (req, res) => {
  const { username } = req.params;

  const getUserIdQuery = 'SELECT id,budget FROM users WHERE username = ?';
  db.query(getUserIdQuery, [username], (err, results) => {
    if (err) {
      console.error('Error fetching user ID:', err.message);
      return res.status(500).json({ error: 'Database error while fetching user ID' });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user_id = results[0].id;
    const budget = parseFloat(results[0].budget);

    const getExpensesQuery = 'SELECT * FROM expense WHERE user_id = ? ORDER BY date DESC';
    db.query(getExpensesQuery, [user_id], (err, expenses) => {
      if (err) {
        console.error('Error fetching expenses:', err.message);
        return res.status(500).json({ error: 'Database error while fetching expenses' });
      }
      const totalSpent = expenses.reduce((sum, expense) => {
        return sum + parseFloat(expense.amount);
      }, 0);

      const remaining = (budget - totalSpent).toFixed(2);

      res.json({ username, expenses,total_spent: totalSpent, remaining_balance: remaining});
    });
  });
});

//====================FILTER EXPENSE========================
app.get('/api/expenses/:username/sort', (req, res) => {
  const { username } = req.params;
  const { order } = req.query;

  const sortOrder = order === 'desc' ? 'DESC' : 'ASC';

  const getUserQuery = 'SELECT id FROM users WHERE username = ?';
  db.query(getUserQuery, [username], (err, userResult) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (userResult.length === 0) return res.status(404).json({ error: 'User not found' });

    const user_id = userResult[0].id;

    const sortQuery = `SELECT * FROM expense WHERE user_id = ? ORDER BY date ${sortOrder}`;
    db.query(sortQuery, [user_id], (err, expenses) => {
      if (err) return res.status(500).json({ error: 'Error fetching expenses' });

      res.json({ username, sorted_by: sortOrder, expenses });
    });
  });
});

app.get('/api/expenses/:username/filter', (req, res) => {
  const { username } = req.params;
  const { from, to } = req.query;

  if (!from || !to) {
    return res.status(400).json({ error: 'Both from and to dates are required (YYYY-MM-DD)' });
  }

  const getUserQuery = 'SELECT id FROM users WHERE username = ?';
  db.query(getUserQuery, [username], (err, userResult) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (userResult.length === 0) return res.status(404).json({ error: 'User not found' });

    const user_id = userResult[0].id;

    const filterQuery = `SELECT * FROM expense WHERE user_id = ? AND date BETWEEN ? AND ? ORDER BY date ASC`;
    db.query(filterQuery, [user_id, from, to], (err, expenses) => {
      if (err) return res.status(500).json({ error: 'Error filtering expenses' });

      res.json({ username, from, to, filtered_expenses: expenses });
    });
  });
});

//==============delete expense===============================
app.delete('/api/expenses/:username/:expenseId', (req, res) => {
  const { username, expenseId } = req.params;

  const getUserQuery = 'SELECT id FROM users WHERE username = ?';
  db.query(getUserQuery, [username], (err, userResults) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (userResults.length === 0) return res.status(404).json({ error: 'User not found' });

    const user_id = userResults[0].id;

    const deleteQuery = 'DELETE FROM expense WHERE id = ? AND user_id = ?';
    db.query(deleteQuery, [expenseId, user_id], (err, result) => {
      if (err) return res.status(500).json({ error: 'Database error during deletion' });

      if (result.affectedRows === 0) {
        return res.status(404).json({ error: 'Expense not found or does not belong to user' });
      }

      res.json({ message: 'Expense deleted successfully' });
    });
  });
});

//==================EDIT EXPENSE=============================
app.put('/api/expenses/:username/:expenseId', (req, res) => {
  const { username, expenseId } = req.params;
  const { amount, category, description, date } = req.body;

  if (!amount || !category || !description || !date) {
    return res.status(400).json({ error: 'All fields are required to update expense' });
  }

  const getUserQuery = 'SELECT id FROM users WHERE username = ?';
  db.query(getUserQuery, [username], (err, userResults) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (userResults.length === 0) return res.status(404).json({ error: 'User not found' });

    const user_id = userResults[0].id;

    const updateQuery = `
      UPDATE expense
      SET amount = ?, category = ?, description = ?, date = ?
      WHERE id = ? AND user_id = ?
    `;

    db.query(updateQuery, [amount, category, description, date, expenseId, user_id], (err, result) => {
      if (err) return res.status(500).json({ error: 'Database error during update' });

      if (result.affectedRows === 0) {
        return res.status(404).json({ error: 'Expense not found or does not belong to user' });
      }

      res.json({ message: 'Expense updated successfully' });
    });
  });
});

//======================SERVER=================
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
