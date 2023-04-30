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

// Defining directory to serve image files.
app.use(express.static(__dirname + "/public"));

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
    secret: mongodb_secret
});

// Configure sessions db
const sessionStore = new MongoDBSession({
    uri: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_session_database}?retryWrites=true&w=majority`,
    collection: 'sessions',
    secret: mongodb_session_secret
});

let userCollection;
let sessionCollection;

mongodbStore.on('connected', function () {
    console.log('MongoDB user store connected');

    // Enable access to the users collection
    userCollection = mongodbStore.client.db().collection('users');
});

sessionStore.on('connected', function () {
    console.log('MongoDB session store connected');

    // Enable access to the sessions collection
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
        <button onclick="location.href = window.location.origin + '/signup'">Sign Up</button>
        `;
    } else {
        var name = req.session.name;
        var html = `
        <p>Hello, ${name}!</p>
        <button onclick="location.href = window.location.origin + '/members'">Go to Members Area</button>
        <button onclick="location.href = window.location.origin + '/logout'">Logout</button>
        `;
    }

    res.send(html);
});


// @author greencodecomments
// @see https://github.com/greencodecomments/COMP2537_Demo_Code_1/blob/main/index.js
app.get('/signup', (req, res) => {
    var html = `
    create user
    <form action='/signupSubmit' method='post'>
        <input name='name' type='text' placeholder='name'>
        <input name='email' type='email' placeholder='email'>
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
    <form action='/loginSubmit' method='post'>
        <input name='email' type='email' placeholder='email'>
        <input name='password' type='password' placeholder='password'>
        <button>Submit</button>
    </form>
    `;
    res.send(html);
});


app.use(express.urlencoded({ extended: true }));

// @author greencodecomments
// @see https://github.com/greencodecomments/COMP2537_Demo_Code_1/blob/main/index.js
app.post('/signupSubmit', async (req, res) => {
    var name = req.body.name;

    // Store the email in lowercase to avoid duplicate emails capitalized differently.
    var email = req.body.email.toLowerCase();
    var password = req.body.password;

    const schema = Joi.object(
        {
            // Name represents 'username' so it will be alphanumerical (letters/numbers) 
            name: Joi.string().alphanum().max(20).required(),
            email: Joi.string().email().max(20).required(),
            password: Joi.string().max(20).required()
        });

    const validationResult = schema.validate({ name, email, password });

    if (validationResult.error != null) {
        console.log(validationResult.error);

        // Loop through the validation errors and check the context property
        validationResult.error.details.forEach((error) => {

            switch (error.context.key) {
                case "name":
                    if (name.trim() == "") {
                        var html = `
                        <p>Name required.</p>
                        <a href="/signup">Try again</a>
                        `;
                    } else {
                        var html = `
                        <p>Invalid name.</p>
                        <a href="/signup">Try again</a>
                        `;
                    }
                    break;
                case "email":
                    if (email.trim() == "") {
                        var html = `
                        <p>Email required.</p>
                        <a href="/signup">Try again</a>
                        `;
                    } else {
                        var html = `
                        <p>Email must be 20 characters or less and not contain any illegal characters.</p>
                        <a href="/signup">Try again</a>
                        `;
                    }
                    break;
                case "password":
                    if (password.trim() == "") {
                        var html = `
                        <p>Password required.</p>
                        <a href="/signup">Try again</a>
                        `;
                    } else {
                        var html = `
                        <p>Password must be 20 characters or less and not contain any illegal characters.</p>
                        <a href="/signup">Try again</a>
                        `;
                    }
                    break;
                default:
                    // Error 400 for bad request if the validation error is other than 'name', 'email', and 'password'.
                    var html = "Error 400: Invalid request!"
                    res.status(400);
            }

            res.send(html);
        })

        return;
    }

    // Parametrized query treats user input as plain data and not code, so as to defend against injection attacks.
    // $eq looks for an exact match and requires collation for case-insensitive query. Name must be unique.
    const nameResult = await userCollection.find({ name: { $eq: name } }, { collation: { locale: 'en_US', strength: 2 } }).project({ name: 1, email: 1, password: 1, _id: 1 }).toArray();

    const emailResult = await userCollection.find({ email: { $eq: email } }).project({ name: 1, email: 1, password: 1, _id: 1 }).toArray();

    if (nameResult.length == 1) {
        console.log("Name already in use.");

        var html = `
        <p>Name already in use.</p>
        <a href="/signup">Try again</a>
        `;

        res.send(html);
        return;
    } else if (emailResult.length == 1) {
        console.log("Email already in use.");

        var html = `
        <p>Email already in use.</p>
        <a href="/signup">Try again</a>
        `;

        res.send(html);
        return;
    } else {
        // Encrypt the password of the new account to store.
        var hashedPassword = await bcrypt.hash(password, saltRounds);

        var html = `
                <!DOCTYPE html>
                <html>
                  <head>
                    <meta http-equiv="refresh" content="3;url=/members">
                  </head>
                  <body>
                    <p>User created successfully. Redirecting to members page...</p>
                  </body>
                </html>
              `;

        // Create a unique index with a case-insensitive collation on the name field
        await userCollection.createIndex(
            { name: 1 },
            { unique: true, collation: { locale: "en_US", strength: 2 } }
        );

        await userCollection.insertOne({ name: name, email: email, password: hashedPassword });

        console.log("Inserted user");

        req.session.authenticated = true;
        req.session.name = name;
        req.session.cookie.maxAge = expireTime;

        res.send(html);
    }
});


// @author greencodecomments
// @see https://github.com/greencodecomments/COMP2537_Demo_Code_1/blob/main/index.js
app.post('/loginSubmit', async (req, res) => {
    var email = req.body.email.toLowerCase();
    var password = req.body.password;

    // Define the schema (validation criteria) of the user info.
    const schema = Joi.object(
        {
            email: Joi.string().email().max(20).required(),
            password: Joi.string().max(20).required()
        });

    const validationResult = schema.validate({ email, password });

    if (validationResult.error != null) {
        console.log(validationResult.error);

        // Loop through the validation errors and check the context property
        validationResult.error.details.forEach((error) => {

            switch (error.context.key) {
                case "email":
                    if (email.trim() == "") {
                        var html = `
                        <p>Email required.</p>
                        <a href="/login">Try again</a>
                        `;
                    } else {
                        var html = `
                        <p>Email must be 20 characters or less and not contain any illegal characters.</p>
                        <a href="/login">Try again</a>
                        `;
                    }
                    break;
                case "password":
                    if (password.trim() == "") {
                        var html = `
                        <p>Password required.</p>
                        <a href="/login">Try again</a>
                        `;
                    } else {
                        var html = `
                        <p>Password must be 20 characters or less and not contain any illegal characters.</p>
                        <a href="/login">Try again</a>
                        `;
                    }
                    break;
                default:
                    // Error 400 for bad request if the validation error is other than 'name', 'email', and 'password'.
                    var html = "Error 400: Invalid request!"
                    res.status(400);
            }

            res.send(html);
        })

        return;
    } else {
        // Search the collection for a matching user.
        const result = await userCollection.find({ email: { $eq: email } }).project({ name: 1, email: 1, password: 1, _id: 1 }).toArray();

        // Check the collection for a matching user. If none, redirect.
        console.log(result);

        if (result.length != 1) {
            console.log("user not found");
            var html = `
            <p>User not found.</p>
            <a href="/login">Try again</a>
            `;

            res.send(html);
            return;
        }

        if (await bcrypt.compare(password, result[0].password)) {
            console.log("correct password");

            req.session.authenticated = true;
            req.session.name = result[0].name;
            req.session.cookie.maxAge = expireTime;

            var html = `
            <!DOCTYPE html>
            <html>
              <head>
                <meta http-equiv="refresh" content="3;url=/members">
              </head>
              <body>
                <p>Logged in successfully. Redirecting to members page...</p>
              </body>
            </html>
          `;

            res.send(html);
            return;
        } else {
            console.log("incorrect password");
            var html = `
            <p>Invalid email/password combination.</p>
            <a href="/login">Try again</a>
            `;

            res.send(html);
            return;
        }
    }
});


app.get('/logout', (req, res) => {
    req.session.destroy();

    var html = `
    <!DOCTYPE html>
    <html>
      <head>
        <meta http-equiv="refresh" content="3;url=/">
      </head>
      <body>
        <p>Logged out successfully. Redirecting to homepage...</p>
      </body>
    </html>
  `;

  res.send(html);
});


app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect("/");
    } else {
        var name = req.session.name;

        // Generate a random number from 0 to 2
        var randomIndex = Math.floor(Math.random() * 3);
        var hero;

        switch (randomIndex) {
            case 0:
                hero = "/flamingPie.jpg";
                break;
            case 1:
                hero = "/mindGames.jpg";
                break;
            case 2:
                hero = "/plasticBeach.jpg";
                break;
        }

        var html = `
        <h1>Hello, ${name}!</h1>
        <img src='${hero}' style='width:320px;'>
        <br>
        <button onclick="location.href = window.location.origin">Home</button>
        <button onclick="location.href = window.location.origin + '/logout'">Logout</button>
        `;

        res.send(html);
    }
});


app.get("*", (req, res) => {
    res.status(404);
    res.send("Error 404: Page not found!");
});


app.listen(port, () => {
    console.log("Node application listening on port " + port);
});
