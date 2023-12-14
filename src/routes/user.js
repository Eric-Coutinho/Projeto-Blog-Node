const express = require('express');
const AuthController = require('../controller/UserController');
const route = express.Router();

route
    .post('/register', AuthController.register)
    .post('/login', AuthController.login)
    
module.exports = route;