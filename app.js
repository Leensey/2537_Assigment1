require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const Joi = require("joi");
const User = require("./models/user.model");

const app = express();
const PORT = process.env.PORT || 3000;

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

// Construct MongoDB URI from individual parts
const dbURI = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}`;

// Connect to MongoDB using Mongoose
mongoose.connect(dbURI)
    .then(() => console.log("MongoDB connected via Mongoose"))
    .catch(err => console.error("MongoDB connection error:", err));


// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.set("view engine", "ejs");

// Session Configuration
app.use(session({
    secret: node_session_secret,
    store: MongoStore.create({
        mongoUrl: dbURI,
        crypto: {
            secret: mongodb_session_secret
        }
    }),
    saveUninitialized: false,
    resave: true,
    cookie: {
        maxAge: 1000 * 60 * 60 // 1 hour
    }
}));

// Home Page
app.get("/", (req, res) => {
    res.render("index", { name: req.session.name });
});

// Sign Up Page
app.get("/signup", (req, res) => {
    res.render("signup");
});

// Handle Sign Up
app.post("/signup", async (req, res) => {
    const schema = Joi.object({
        name: Joi.string().required(),
        email: Joi.string().email().required(),
        password: Joi.string().required()
    });

    const validation = schema.validate(req.body);
    if (validation.error) {
        return res.send(`Error: ${validation.error.message}<br><a href="/signup">Try Again</a>`);
    }

    const hashedPassword = await bcrypt.hash(req.body.password, 12);

    try {
        const newUser = new User({
            name: req.body.name,
            email: req.body.email,
            password: hashedPassword
        });

        await newUser.save();

        req.session.authenticated = true;
        req.session.name = newUser.name;
        req.session.email = newUser.email;

        res.redirect("/members");
    } catch (err) {
        res.send("Error creating user. Try again.");
    }
});

// Login Page
app.get("/login", (req, res) => {
    res.render("login");
});

// Handle Login
app.post("/login", async (req, res) => {
    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().required()
    });

    const validation = schema.validate(req.body);
    if (validation.error) {
        return res.send("Invalid input.<br><a href='/login'>Try Again</a>");
    }

    const user = await User.findOne({ email: req.body.email });

    if (!user) {
        return res.send("Email not found.<br><a href='/login'>Try Again</a>");
    }

    const passwordMatch = await bcrypt.compare(req.body.password, user.password);
    if (!passwordMatch) {
        return res.send("Invalid password.<br><a href='/login'>Try Again</a>");
    }

    req.session.authenticated = true;
    req.session.name = user.name;
    req.session.email = user.email;

    res.redirect("/members");
});

// Members Area
app.get("/members", (req, res) => {
    if (!req.session.authenticated) return res.redirect("/");

    const images = ["1.jpg", "2.jpg", "3.jpg"];
    const randomImage = images[Math.floor(Math.random() * images.length)];

    res.render("members", { name: req.session.name, image: randomImage });
});

// Logout
app.get("/logout", (req, res) => {
    req.session.destroy(err => {
        if (err) console.log("Logout error:", err);
        res.redirect("/");
    });
});

// 404 Handler
app.use((req, res) => {
    res.status(404).render("404");
});


// Start Server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
