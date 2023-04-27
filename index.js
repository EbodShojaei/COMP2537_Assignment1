// Load modules below.
const express = require('express');

const session = require('express-session');


const app = express();

// Port declaration below. Defaults to 3020 if system variable PORT not set.
const port = process.env.PORT || 3020;

// Encrypt the session ID via GUID.
const secret = process.env.NODE_SESSION_SECRET;

app.use(session({
    secret: secret,
    //store: mongoStore, //default is memory store
    saveUninitialized: false,
    resave: true
}
));


app.get('/', (req, res) => {
    req.session.username = 'Dobe';
    res.send('Hello World! :D');
});

app.listen(port, () => {
    console.log("Node application listening on port " + port);
});


