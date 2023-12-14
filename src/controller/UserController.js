const User = require('../model/user');
const jwt = require('jsonwebtoken');
const { Author } = require('../model/author');
require('dotenv').config();
const Cryptojs = require('crypto-js');

const { decrypt } = require('dotenv')

class AuthController{
    static async register(req, res){
        const { name, birth, email, password, confirmPassword } = req.body;

        if(!name)
            return res.send(400).json({ message: "O nome é obrigatório" });
        if(!email)
            return res.send(400).json({ message: "O email é obrigatório" });
        if(!birth)
            return res.send(400).json({ message: "É obrigatório fornecer a data de nascimento" });
        if(!password)
            return res.send(400).json({ message: "A senha é obrigatória" });
        if(password != confirmPassword)
            return res.send(400).json({ message: "As senhas não conferem" });

        const userExist = await User.findOne({ email: email });

        if(userExist)
            return res.status(422).json({ message: "Esse email já está em uso" });

        const passwordCrypt = Cryptojs.AES.encrypt(password, process.env.SECRET).toString();

        const author = new Author({
            name,
            email,
            birth,
            createdAt: Date.now(),
            updatedAt: Date.now(),
            removedAt: null
        })
        const user = new User({
            login: email,
            author,
            email,
            password: passwordCrypt,
            createdAt: Date.now(),
            updatedAt: Date.now(),
            removedAt: null
        });

        try {
            await User.create(user);
            res.status(201).send({ message: "Usuário cadastrado com sucesso" });
        } catch (error) {
            res.status(500).send({ message: "Something failed", data: error.message });
        }
    }

    static async login(req, res){
        const { email, password } = req.body;

        const user = await User.findOne({ email });
        const passwordDecrypt = Cryptojs.AES.decrypt(user.password, process.env.SECRET).toString(Cryptojs.enc.Utf8);

        if(!user)
            res.status(400).send({ message: "Invalid Login" });

        if(passwordDecrypt != password)
            res.status(400).send({ message: "Invalid Password" });

        const secret = process.env.SECRET;

        const token = jwt.sign(
            {
                id: user._id
            },
            secret,
            {
                expiresIn: '2 days'
            }
        );
        return res.status(200).send({ token: token });
    }
}

module.exports = AuthController