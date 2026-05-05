require('dotenv').config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo").default;
const bcrypt = require("bcrypt");
const saltRounds = 12;

const app = express();

const Joi = require("joi");

const PORT = process.env.PORT || 3000;
const expireTime = 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

const { MongoClient } = require('mongodb');

const atlasURI = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/`;
const database = new MongoClient(atlasURI, {});
const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(__dirname + '/public'));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}`,
    crypto: {
        secret: mongodb_session_secret
    }
});

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true,
    cookie: {maxAge: expireTime}
}));

// Routes
app.get("/", (req, res) =>{
    if (!req.session.authenticated) {
        res.send(`
        <body>
            <form action = "/signup" method="get">
                <button>Sign Up</button>
            </form>
            <form action = "/login" method="get">
                <button>Log In</button>
            </form>
        </body>
        `);
    }
    else {
    res.send(`
        <body>
            <p>Hello, ${req.session.name}!
            </p>
            <form action = "/members" method="get">
                <button>Go to Member's Area</button>
            </form>
            <form action = "/logout" method="get">
                <button>Logout</button>
            </form>
        </body>
        `);
    }
});

app.get("/signup", (req,res) => {
    res.send(`
    <body>
        <p>
        create user
        </p>
        <form action = "/signupSubmit" method="post">
            <input type="text" name="name" placeholder="name"><br>
            <input type="text" name="email" placeholder="email"><br>
            <input type="password" name="password" placeholder="password"><br>
            <button>Submit</button>
        </form>
    </body>
    `);
});

app.post("/signupSubmit", async(req,res) => {
    const {name, email, password } = req.body;

    const schema = Joi.object({
        name: Joi.string().max(50).required(),
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required() 
    })

    const validationResult = schema.validate({name, email, password});
    if (validationResult.error != null) {
        const message = validationResult.error.details[0].message;
        res.send(`
            <p>${message}</p>
            <a href="/signup">Try again</a>
        `);
        return;
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);
    await userCollection.insertOne({ name, email, password: hashedPassword});

    req.session.authenticated = true;
    req.session.name = name;
    req.session.cookie.maxAge = expireTime;

    res.redirect('/members');
});

app.get("/login", (req,res) => {
    res.send(`
    <body>
        log in
        <form action = "/loginSubmit" method="post">
            <input type="text" name="email" placeholder="username"><br>
            <input type="password" name="password" placeholder="password"><br>
            <button>Submit</button>
        </form>
    </body>
    `);
});

app.post("/loginSubmit", async (req, res) => {
    const {email, password} = req.body;

    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required()
    })

    const validationResult = schema.validate({ email, password});
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/login");
        return;
    }

    const result = await userCollection
        .find({email})
        .project({ name: 1, email: 1, password: 1, _id:1})
        .toArray();
       
    if (result.length !==1) {
        res.send(`
            <p>Invalid email/password combination.</p>
            <a href="/login">Try again</a>
        `);
        return;
    } 

    if (await bcrypt.compare(password, result[0].password)) {
        req.session.authenticated = true;
        req.session.name = result[0].name;
        req.session.cookie.maxAge = expireTime;
        res.redirect('/members');
    } else {
        res.send(`
            <p>Invalid email/password combination.</p>
            <a href="/login">Try again</a>
        `);
    }

});

app.get("/members", (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
        return;
    }

    const images = ['image.png', 'image2.png', 'image3.png'];
    const randomImage = images[Math.floor(Math.random() * images.length)];

    res.send(`
        <body>
            <h1>Hello, ${req.session.name}.</h1>
            <img src="/${randomImage}" style ="width:300px;"><br>
            <form action="/logout" method="get">
                <button>Sign out</button>
            </form>
        </body>
    `)
});

app.get("/logout", (req,res) => {
    req.session.destroy();
    res.redirect('/');
});

// 404 handler
app.use((req, res) => {
    res.status(404);
    res.send("Page not found - 404");
});

// Error handler
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: "Internal server error"});
});

app.listen(PORT, () => {
    console.log(`Server listening on http://localhost:${PORT}`);
});