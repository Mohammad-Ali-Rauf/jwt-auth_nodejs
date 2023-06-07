import mongoose from 'mongoose';
import express from 'express';
import 'dotenv/config';
import bodyParser from 'body-parser';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

// import models
import User from './models/User.js';

const app = express();

app.use(bodyParser.json());

// Connect to Database
try {
  mongoose
    .connect(process.env.DATABASE_URI)
    .then(() => console.log('MongoDB Connected Successfully!!!'));
} catch (err) {
  console.error('MongoDB Connecting Error:', err);
}

app.get('/', (req, res) => {
  res.send({ msg: 'This is JWT Auth Project created by Mohammad Ali' });
});

// Routes
app.get('/users', async (req, res) => {
  try {
    const users = await User.find();
    res.json(users);
  } catch (err) {}
});

app.post('/register', async (req, res) => {
  try {
    const name = req.body.name;
    const password = req.body.password;

    const existingUser = await User.findOne({ name });
    if (existingUser) {
      return res.status(400).json({ msg: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({ name, password: hashedPassword });
    await newUser.save();

    const token = jwt.sign({ userId: newUser._id }, process.env.JWT_SECRET);

    res.json({ msg: 'User registered successfully', token });
  } catch (err) {
    console.error('Error registering user:', err);
    res.status(500).json({ msg: 'Registration failed' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { name, password } = req.body;

    const user = await User.findOne({ name });

    if (!user) {
      return res.status(401).json({ msg: 'User not found!!' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ msg: 'Password is incorrect!!' });
    }

    const token = req.header('token');

    try {
      jwt.verify(token, process.env.JWT_SECRET)
      return res.json({ msg: 'Login successful' });
    } catch (err) {
      return res.status(401).json({ msg: 'Invalid Token!' });
    }
  } catch (err) {
    console.error('Error during login:', err);
    return res.status(500).json({ msg: 'Login failed' });
  }
});

const PORT = 5000 || process.env.PORT;

app.listen(PORT, () => console.log(`Server is running on ${PORT}`));
