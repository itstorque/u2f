'use strict';
const mongoose = require('mongoose');
const dbConnection = process.env.DB_CONNECTION;
console.log(dbConnection);

mongoose.connect(dbConnection, {
	useCreateIndex: true,
	useNewUrlParser: true,
	useUnifiedTopology: true,
});
const db = mongoose.connection;

db.on('error', () => {
	console.log('> error occurred from the database');
});
db.once('open', () => {
	console.log('> successfully opened the database');
});
module.exports = mongoose;
