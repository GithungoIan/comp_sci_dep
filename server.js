const mongoose = require('mongoose');
const dotenv = require('dotenv');

process.on('uncaughtException', (err) => {
  console.log('UNCAUGHT EXCEPTION! 🔥 Shutting down...');
  console.log(err.name, err.messsage);
  process.exit(1);
});

dotenv.config({path: './config.env'});
const app = require('./index');

const DB = process.env.DATABASE_LOCAL;

mongoose.connect(DB, {
  useCreateIndex: true,
  useFindAndModify: false,
  useUnifiedTopology: true,
  useNewUrlParser: true,
}).then(() => console.log('DB, Connection successful'));

const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
  console.log(`App running on port ${PORT}`);
});

process.on(`unhandledRejection`, (err) => {
  console.log('Unhandled Rejection! 🔥 Shutting down...');
  console.log(err.name, err.message);
  server.close(() => {
    process.exit(1);
  });
});
