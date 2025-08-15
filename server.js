const express = require('express');

const jwt = require('jsonwebtoken');

const bcrypt = require('bcryptjs');

require('dotenv').config();

const app = express();

app.use(express.json());

const users = []; // Store users (In real applications, use a database)

let refreshTokens = []; // Store refresh tokens (In a database)

app.post('/msbase-login/v1/register', async (req, res) => {

    const { username, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = { username, password: hashedPassword };

    users.push(user);

    res.status(201).send("User Registered!");

});

app.post('/msbase-login/v1/login', async (req, res) => {

    const { username, password } = req.body;

    let user = users.find(u => u.username === username);



    if (!user || !(await bcrypt.compare(password, user.password))) {

        return res.status(403).send('Invalid credentials');

    }

    user = {
        "iss": "Online JWT Builder",
        "aud": "www.example.com",
        "sub": "jrocket@example.com",
        "username": username,
        "role": {
            "id": 1,
            "name": "admin",
            "permissions": [
                "view",
                "edit",
                "delete"
            ]
        },
        "id": "2311432"
    }


    const accessToken = generateAccessToken(user);

    const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });

    refreshTokens.push(refreshToken);



    res.json({ accessToken, refreshToken });

});

app.post('/msbase-login/v1/refreshToken', (req, res) => {

    const { refreshToken } = req.body;

    if (!refreshToken) return res.sendStatus(401);

    if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);

    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {

        if (err) return res.sendStatus(403);

        newUser = {
        "iss": "Online JWT Builder",
        "aud": "www.example.com",
        "sub": "jrocket@example.com",
        "username": user.username,
        "role": {
            "id": 1,
            "name": "admin",
            "permissions": [
                "view",
                "edit",
                "delete"
            ]
        },
        "id": "2311432"
    }


        let NewAccessToken = generateAccessToken(newUser);

        console.log("Access Token Generated: ", NewAccessToken);

        res.json({ accessToken:NewAccessToken });

    });

});

app.post('/msbase-login/v1/logout', (req, res) => {

    const { token } = req.body;

    refreshTokens = refreshTokens.filter(t => t !== token);

    res.sendStatus(204);

});

function generateAccessToken(user) {

    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '5m' });

}

app.listen(4000, () => console.log('Server running on port 4000'));   