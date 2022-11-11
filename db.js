const mongoose = require('mongoose');
require('dotenv').config();

// connect to mongodb
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });
mongoose.Promise = global.Promise;