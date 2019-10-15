const mongoose = require('mongoose');

const tokenSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    required: [true, 'Token must belong to an user'],
    ref: 'User'
  },
  token: {
    type: String,
    required: [true, 'Token must exist']
  },
  createdAt: {
    type: Date,
    required: [true, 'Token must have the time of creation'],
    default: Date.now,
    expires: 86400
  }
});

const Token = mongoose.model('Token', tokenSchema);

module.exports = Token;
