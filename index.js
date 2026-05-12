require('dotenv').config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo").default;
const bcrypt = require("bcrypt");
const { ObjectId } = require('mongodb');
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

app.set('view engine', 'ejs');

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
    cookie: { maxAge: expireTime }
}));

const navLinks = [
    { name: "Home", link: "/" },
    { name: "Cats", link: "/cats" },
    { name: "Login", link: "/login" },
    { name: "Admin", link: "/admin" },
    { name: "404", link: "/dne" },
];

// Middleware to set nav locals on every request
app.use((req, res, next) => {
    app.locals.navLinks = navLinks;
    app.locals.currentURL = req.path;
    next();
});

// Middleware: require valid session
function sessionValidation(req, res, next) {
    if (req.session.authenticated) {
        next();
    } else {
        res.redirect('/login');
    }
}

// Middleware: require admin role
function adminAuthorization(req, res, next) {
    if (req.session.user_type === 'admin') {
        next();
    } else {
        res.status(403).render('403', { message: 'You are not authorized to view this page.' });
    }
}

// Routes
app.get('/', (req, res) => {
    res.render("index", {
        authenticated: req.session.authenticated || false,
        name: req.session.name || ''
    });
});

app.get("/signup", (req, res) => {
    res.render("signup");
});

app.post("/signupSubmit", async (req, res) => {
    const { name, email, password } = req.body;

    const schema = Joi.object({
        name: Joi.string().max(50).required(),
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({ name, email, password });
    if (validationResult.error != null) {
        const message = validationResult.error.details[0].message;
        res.render("signupSubmit", { message });
        return;
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);
    await userCollection.insertOne({ name, email, password: hashedPassword, user_type: 'user' });

    req.session.authenticated = true;
    req.session.name = name;
    req.session.user_type = 'user';
    req.session.cookie.maxAge = expireTime;

    res.redirect('/members');
});

app.get("/login", (req, res) => {
    res.render("login");
});

app.post("/loginSubmit", async (req, res) => {
    const { email, password } = req.body;

    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({ email, password });
    if (validationResult.error != null) {
        res.redirect("/login");
        return;
    }

    const result = await userCollection
        .find({ email })
        .project({ name: 1, email: 1, password: 1, user_type: 1, _id: 1 })
        .toArray();

    if (result.length !== 1) {
        res.render("loginSubmit");
        return;
    }

    if (await bcrypt.compare(password, result[0].password)) {
        req.session.authenticated = true;
        req.session.name = result[0].name;
        req.session.user_type = result[0].user_type || 'user';
        req.session.cookie.maxAge = expireTime;
        res.redirect('/members');
    } else {
        res.render("loginSubmit");
    }
});

app.get("/members", sessionValidation, (req, res) => {
    res.render("members", { name: req.session.name });
});

app.get("/cats", sessionValidation, (req, res) => {
    res.render("cats");
});

app.get("/logout", (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.get("/admin", sessionValidation, adminAuthorization, async (req, res) => {
    const result = await userCollection.find().project({ name: 1, email: 1, user_type: 1, _id: 1 }).toArray();
    res.render("admin", { users: result });
});

app.get("/admin/promote", sessionValidation, adminAuthorization, async (req, res) => {
    const id = req.query.id;
    await userCollection.updateOne({ _id: new ObjectId(id) }, { $set: { user_type: 'admin' } });
    res.redirect('/admin');
});

app.get("/admin/demote", sessionValidation, adminAuthorization, async (req, res) => {
    const id = req.query.id;
    await userCollection.updateOne({ _id: new ObjectId(id) }, { $set: { user_type: 'user' } });
    res.redirect('/admin');
});

// 403 page
app.get("/403", (req, res) => {
    res.status(403).render("403", { message: "You are not authorized to view this page." });
});

// 404 handler
app.use((req, res) => {
    res.status(404).render("404");
});

// Error handler
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: "Internal server error" });
});

app.listen(PORT, () => {
    console.log(`Server listening on http://localhost:${PORT}`);
});