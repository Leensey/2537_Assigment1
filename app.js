require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const Joi = require("joi");
const User = require("./models/user.model");
const requireAuth = require("./middleware/requireAuth");
const requireAdmin = require("./middleware/requireAdmin");

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

app.use((req, res, next) => {
    res.locals.name = req.session.name;
    res.locals.user_type = req.session.user_type;
    next();
});

// Home Page
app.get("/", (req, res) => {
    res.render("index", { name: req.session.name });
});

// Sign Up Page
app.get("/signup", (req, res) => {
    res.render("signup", {
        missingName: req.query.name === "true",
        missingEmail: req.query.email === "true",
        missingPassword: req.query.password === "true",
        errorMessage: null
    });
});

// Handle Sign Up
app.post("/signup", async (req, res) => {
    const { name, email, password } = req.body;

    const schema = Joi.object({
        name: Joi.string().required(),
        email: Joi.string().email().required(),
        password: Joi.string().required()
    });

    const validation = schema.validate(req.body, { abortEarly: false });
    // Handle missing or invalid fields
    if (validation.error) {
        // Prepare query flags: ?name=true&email=true&password=true
        const flags = [];
        validation.error.details.forEach(err => {
            if (err.path.includes("name")) flags.push("name=true");
            if (err.path.includes("email")) flags.push("email=true");
            if (err.path.includes("password")) flags.push("password=true");
        });
        return res.redirect("/signup?" + flags.join("&"));
    }

    const hashedPassword = await bcrypt.hash(req.body.password, 12);

    try {
        const newUser = new User({
            name: req.body.name,
            email: req.body.email,
            password: hashedPassword,
            user_type: "user"
        });

        await newUser.save();

        req.session.authenticated = true;
        req.session.name = newUser.name;
        req.session.email = newUser.email;
        req.session.user_type = "user";

        res.redirect("/members");
    } catch (err) {
        res.render("signup", {
            missingName: false,
            missingEmail: false,
            missingPassword: false,
            errorMessage: "Something went wrong. Please try again."
        });
    }
});

// Login Page
app.get("/login", (req, res) => {
    res.render("login", {
        errorMessage: null,
        showSignupLink: false
    });
});

// Handle Login
app.post("/login", async (req, res) => {
    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().required()
    });

    const validation = schema.validate(req.body);

    if (validation.error) {
        return res.render("login", {
            errorMessage: "Invalid email or password. Please try again.",
            showSignupLink: true
        });
    }

    const user = await User.findOne({ email: req.body.email });

    if (!user) {
        return res.render("login", {
            errorMessage: "User and password not found.",
            showSignupLink: true
        });
    }

    const passwordMatch = await bcrypt.compare(req.body.password, user.password);

    if (!passwordMatch) {
        return res.render("login", {
            errorMessage: "Invalid password.",
            showSignupLink: false
        });
    }

    req.session.authenticated = true;
    req.session.name = user.name;
    req.session.email = user.email;
    req.session.user_type = user.user_type;

    res.redirect("/members");
});

// Members Area
app.get("/members", requireAuth, (req, res) => {
    const images = ["1.jpg", "2.jpg", "3.jpg"];
    res.render("members", { images });
});

// Admin Area
app.get("/admin", requireAuth, requireAdmin, async (req, res) => {
    const users = await User.find();
    res.render("admin", {
        users,
        currentEmail: req.session.email
    });
});

// Promote User
app.get("/promote/:id", requireAuth, requireAdmin, async (req, res) => {
    try {
        await User.updateOne({ _id: req.params.id }, { $set: { user_type: "admin" } });
        res.redirect("/admin");
    } catch (err) {
        console.error("Promotion error:", err);
        res.status(500).send("Failed to promote user.");
    }
});

// Demote User
app.get("/demote/:id", requireAuth, requireAdmin, async (req, res) => {
    try {
        await User.updateOne({ _id: req.params.id }, { $set: { user_type: "user" } });
        res.redirect("/admin");
    } catch (err) {
        console.error("Demotion error:", err);
        res.status(500).send("Failed to demote user.");
    }
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
