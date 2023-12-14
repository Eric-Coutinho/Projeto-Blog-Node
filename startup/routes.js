const express = require('express');
const article = require('../src/routes/article');
const author = require('../src/routes/author');
const user = require('../src/routes/user');

module.exports = function(app) {
    app
        .use(express.json())
        .use('/api/article', article)
        .use('/api/author', author)
        .use('/api/user', user)
}

