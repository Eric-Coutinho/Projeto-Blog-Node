const mongoose = require('mongoose');

const authorSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        minlength: 3
    },
    birth: {
        type: Date,
        required: true
    },
    email: {
        type: String,
        required: true,
        minlength: 3
    },
    createdAt: {
        type: Date,
        required: true
    },
    updatedAt: {
        type: Date,
        required: false
    },
    removedAt: {
        type: Date,
        required: false
    }
});

const Author = mongoose.model('Author', authorSchema);

exports.Author = Author;
exports.authorSchema = authorSchema;