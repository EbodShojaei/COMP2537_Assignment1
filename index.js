// Load modules below.
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoDBSession = require('connect-mongodb-session')(session);
const bcrypt = require('bcrypt');
const saltRounds = 12;
const Joi = require("joi");
const expireTime = 60 * 60 * 1000; //expires after 1 hour (minutes * seconds * millis)

const app = express();

// Port declaration below. Defaults to 3020 if system variable PORT not set.
const port = process.env.PORT || 3020;

// secret information section
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_secret = process.env.MONGODB_SECRET;
const mongodb_session_database = process.env.MONGODB_SESSION_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

// Encrypt the session ID via GUID.
const node_session_secret = process.env.NODE_SESSION_SECRET;
// END secret section


// Configure users db
const mongodbStore = new MongoDBSession({
    uri: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}?retryWrites=true&w=majority`,
    collection: 'users',
    crypto: {
        secret: mongodb_secret
    }
});

// Configure sessions db
const sessionStore = new MongoDBSession({
    uri: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_session_database}?retryWrites=true&w=majority`,
    collection: 'sessions',
    crypto: {
        secret: mongodb_session_secret
    }
});

let userCollection;
let sessionCollection;

sessionStore.on('connected', function () {
    console.log('MongoDB session store connected');

    // Enable access to the LoginInfo collection
    userCollection = mongodbStore.client.db().collection('users');
    sessionCollection = sessionStore.client.db().collection('sessions');
});

app.use(session({
    secret: node_session_secret,
    store: sessionStore,
    saveUninitialized: false,
    resave: true
}
));

// Homepage is a login/signup page if not logged in but is members page if logged in
app.get('/', (req, res) => {
    if (!req.session.authenticated) {
        var html = `
        <button onclick="location.href = window.location.origin + '/login'">Login</button>
        <button onclick="location.href = window.location.origin + '/createUser'">Sign Up</button>
        `;
    } else {
        var name = req.session.name;
        var html = `
        <h1>Hello, ${name}!</h1>
        <button onclick="location.href = window.location.origin + '/members'">Go to Members Area</button>
        <button onclick="location.href = window.location.origin + '/logout'">Logout</button>
        `;
    }

    res.send(html);
});


// @author greencodecomments
// @see https://github.com/greencodecomments/COMP2537_Demo_Code_1/blob/main/index.js
app.get('/nosql-injection', async (req, res) => {
    var username = req.query.user;

    if (!username) {
        res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
        return;
    }
    console.log("user: " + username);

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(username);

    //If we didn't use Joi to validate and check for a valid URL parameter below
    // we could run our userCollection.find and it would be possible to attack.
    // A URL parameter of user[$ne]=name would get executed as a MongoDB command
    // and may result in revealing information about all users or a successful
    // login without knowing the correct password.
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
        return;
    }

    const result = await userCollection.find({ username: username }).project({ name: 1, username: 1, password: 1, _id: 1 }).toArray();

    console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

// @author greencodecomments
// @see https://github.com/greencodecomments/COMP2537_Demo_Code_1/blob/main/index.js
app.get('/createUser', (req, res) => {
    var html = `
    create user
    <form action='/submitUser' method='post'>
    <input name='name' type='text' placeholder='name'>
    <input name='username' type='email' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

// @author greencodecomments
// @see https://github.com/greencodecomments/COMP2537_Demo_Code_1/blob/main/index.js
app.get('/login', (req, res) => {
    var html = `
    log in
    <form action='/loggingin' method='post'>
    <input name='username' type='email' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});


app.use(express.urlencoded({ extended: true }));

// @author greencodecomments
// @see https://github.com/greencodecomments/COMP2537_Demo_Code_1/blob/main/index.js
app.post('/submitUser', async (req, res) => {
    var name = req.body.name;
    var username = req.body.username;
    var password = req.body.password;

    const schema = Joi.object(
        {
            // Let's use a regular expression to ensure first name (e.g., Fernandez) is only alphabetical. 
            name: Joi.string().pattern(/^[a-zA-Z]+$/).max(20).required(),
            username: Joi.string().email().max(20).required(),
            password: Joi.string().max(20).required()
        });

    const validationResult = schema.validate({ name, username, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/createUser");
        return;
    }

    // Encrypt the password of the new account to store.
    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({ name: name, username: username, password: hashedPassword });
    console.log("Inserted user");

    var html = "successfully created user";
    res.send(html);
});

// @author greencodecomments
// @see https://github.com/greencodecomments/COMP2537_Demo_Code_1/blob/main/index.js
app.post('/loggingin', async (req, res) => {
    var username = req.body.username;
    var password = req.body.password;

    // Define the schema (validation criteria) of the user info.
    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(username);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/login");
        return;
    } else {
        // Search the collection for a matching user.
        const result = await userCollection.find({ username: username }).project({ name: 1, username: 1, password: 1, _id: 1 }).toArray();

        // Check the collection for a matching user. If none, redirect.
        console.log(result);
        if (result.length != 1) {
            console.log("user not found");
            res.redirect("/login");
            return;
        }
        if (await bcrypt.compare(password, result[0].password)) {
            console.log("correct password");

            req.session.authenticated = true;
            req.session.name = result[0].name;
            req.session.cookie.maxAge = expireTime;


            res.redirect('/loggedIn');
            return;
        }
        else {
            console.log("incorrect password");
            res.redirect("/login");
            return;
        }
    }
}
);

// @author greencodecomments
// @see https://github.com/greencodecomments/COMP2537_Demo_Code_1/blob/main/index.js
app.get('/loggedin', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }
    var html = `
    You are logged in!
    `;
    res.send(html);
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});


app.get("*", (req, res) => {
    res.status(404);
    res.send("Error 404: Page not found!");
})


app.listen(port, () => {
    console.log("Node application listening on port " + port);
});
