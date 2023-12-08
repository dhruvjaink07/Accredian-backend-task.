const express = require('express');
const mysql = require('mysql');
const cors = require('cors');
const bcrypt = require('bcrypt');
// const bodyParser = require('body-parser');

const app = express();
app.use(cors({
  origin: 'http://localhost:3000', // Update this to your React app's address
  credentials: true,
}));

app.use(express.json());

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'tonystark',
  database: 'accredian',
  authSwitchHandler: (data, cb) => {
    if (data.pluginName === 'caching_sha2_password') {
      cb(null, Buffer.from([0x01]));
    }
  },
});

db.connect((err) => {
  if (err) {
    console.error('Database connection failed:', err);
  } else {
    console.log('Connected to MySQL database');
  }
});

const tableName = 'USER';
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const query = `SELECT username, password FROM ${tableName} WHERE username = ?`;

  db.query(query, [username], async (err, result) => {
    if (err) {
      console.error('Login Failed - Database Query Error:', err);
      return res.status(500).send('Internal Server Error');
    }

    if (result.length > 0) {
      const hashedPassword = result[0].password;

      if (!hashedPassword) {
        console.error('Login Failed - Empty Password Hash');
        return res.status(400).send('Invalid Credentials');
      }

      // Output hashed password for debugging
      // console.log('Hashed Password:', hashedPassword);

      // Compare the provided password with the hashed password
      const passwordMatch = await bcrypt.compare(password, hashedPassword);

      if (passwordMatch) {
        res.status(200).json({ message: 'Login Successful' });
      } else {
        console.error('Login Failed - Invalid Credential');
        res.status(400).send('Invalid Credential');
      }
    } else {
      console.error('Login Failed - User Not Found');
      res.status(400).send('Invalid Credentials');
    }
  });
});



app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;

  // Hash the password before storing it in the database
  const hashedPassword = await bcrypt.hash(password, 10);

  const checkUsernameQuery = `SELECT * FROM ${tableName} WHERE username = ?`;

  db.query(checkUsernameQuery, [username], async (checkUsernameError, existingUser) => {
    if (checkUsernameError) {
      console.error('Error checking username:', checkUsernameError);
      return res.status(500).send('Internal Server Error');
    }

    if (existingUser.length > 0) {
      return res.status(409).send('Username already taken');
    }

    const insertUserQuery = `INSERT INTO ${tableName} (username, email, password) VALUES (?, ?, ?)`;

    db.query(insertUserQuery, [username, email, hashedPassword], (signupError, result) => {
      if (signupError) {
        console.error('Signup error:', signupError);
        return res.status(500).send('Internal Server Error');
      }

      res.status(201).json({ message: 'Sign-up successful' });
    });
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
