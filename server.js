// server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cron = require('node-cron');
const bcrypt = require('bcryptjs');
const User = require('./models/User');
const authRoutes = require('./routes/auth');

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors({
  origin: 'http://localhost:3000'
}));
app.use(express.json());
app.use('/api/auth', authRoutes);

// MongoDB Connection
const clientOptions = { serverApi: { version: '1', strict: true, deprecationErrors: true } };

mongoose.connect(process.env.MONGO_URI, clientOptions)
  .then(() => {
    console.log("MongoDB connected");
    // Ping the database to ensure connection is established
    return mongoose.connection.db.admin().command({ ping: 1 });
  })
  .then(() => {
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  })
  .catch(err => console.log(err));

// Server
app.listen(port, () => console.log(`Server running on port ${port}`));

// Schedule task to run at midnight every day
cron.schedule('0 0 * * *', async () => {
  try {
    const users = await User.find();
    users.forEach(async (user) => {
      const dynamicPassword = generateDynamicPassword(user.basePassword);
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(dynamicPassword, salt);
      user.password = hashedPassword;
      await user.save();
    });
    console.log('Passwords updated for all users');
  } catch (err) {
    console.error('Error updating passwords:', err);
  }
});

function generateDynamicPassword(basePassword) {
  const currentDate = new Date().toISOString().slice(0, 10).replace(/-/g, ''); // YYYYMMDD
  return `${basePassword}${currentDate}`;
}
