require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;



const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");
let ejs = require('ejs');
app.set('view engine', 'ejs');

const expireTime = 1 * 60 * 60 * 1000;

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
  crypto: {
    secret: mongodb_session_secret
  }
})

app.use(session({
  secret: node_session_secret,
  store: mongoStore, //default is memory store 
  saveUninitialized: false,
  resave: false

}

));
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

  const result = await userCollection.find({ username: username }).project({ username: 1, password: 1, _id: 1 }).toArray();

  console.log(result);

  res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/', (req, res) => {

  // res.send(`
  //   <h1>Welcome!</h1>
  //   <a href="/createUser">Sign Up</a>
  //   <br>
  //   <br>
  //   <a href="/login">Log In</a>
  // `);
  
res.render('index');
});


app.get('/createUser', (req, res) => {
  // var html = `
  //   <h2>Sign Up</h2>
  //   <form action='/submitUser' method='post'>
  //   <input name='username' type='text' placeholder='name'>
  //     <br>
  //     <br>
  //   <input name='email' type='text' placeholder='email'>
  //   <br>
  //   <br>
  //   <input name='password' type='password' placeholder='password'>
  //   <br>
  //   <br>
  //   <button>Submit</button>
  //   </form>
  //   <br>
  //   <br>

  //   `;
  // res.send(html);
  res.render('createUser');
});



app.get('/login', (req, res) => {
  // var html = `
  
  //   <h2>log In </h2>
  //   <form action='/loggingin' method='post'>
  //   <input name='email' type='email' placeholder='email'>
  //   <br>
    

  //   <input name='password' type='password' placeholder='password'>
  //   <br>
  //   <br>

  //   <button>Submit</button>
  //   </form>
  //   <br>
  //   <br>
  //   ${req.session.loginError ? '<p style="color:red;">Invalid email/password combination</p>' : ''}
  //   `;
  
  // res.send(html);
  req.session.loginError = false;
  res.render('login', {loginError: req.session.loginError});
});

app.post('/submitUser', async (req, res) => {
  var username = req.body.username;
  var password = req.body.password;
  var email = req.body.email;

  const schema = Joi.object(
    {
      username: Joi.string().alphanum().max(20).required(),
      password: Joi.string().max(20).required(),
      email: Joi.string().email().required()
    });

  const validationResult = schema.validate({ username, password, email });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/createUser");
    return;
  }

  var hashedPassword = await bcrypt.hash(password, saltRounds);
  await userCollection.insertOne({ username: username, password: hashedPassword , email: email, type: "user"});
  console.log("Inserted user");
  req.session.authenticated = true;
  req.session.username = username;
  res.redirect("/members");
});


app.post('/loggingin', async (req, res) => {
 
  var password = req.body.password;
  var email = req.body.email;
 
  const schema = Joi.string().email().required();
  const validationResult = schema.validate(email);
  if (validationResult.error != null) {
    console.log(validationResult.error);
  
    res.redirect("/login");
    
    return;
  }

  const result = await userCollection.find({ email: email }).project({ username: 1, password: 1, email:1, _id: 1, type:1 }).toArray();

  console.log(result);
  if (result.length != 1) {
    req.session.loginError = true;
    console.log("user not found");
    res.redirect("/login");
    return;
  }
  if (await bcrypt.compare(password, result[0].password)) {
    console.log("correct password");
    req.session.authenticated = true;
    req.session.username = result[0].username;
    req.session.cookie.maxAge = expireTime;

    if (result[0].type === "admin") {
      res.redirect("/admin");
    } else {
      res.redirect("/members");
    }
  }
  else {
    console.log("incorrect password");
    res.redirect("/login");
    return;
  }
});

app.get("/members", (req, res) => {
  if (!req.session.authenticated) {
    res.redirect('/login');
  }

  // var html = `
  //   <h1>Hello ${req.session.username}!</h1>

    
  //   <img src = "/images/1.gif" style = 'width:250px;'>
  //   <br>
  //   <br>
  //   <form action="public/logout" method="POST">
  //     <button type="submit">Sign Out</button>
  //   </form>

  //   `;
  // res.send(html);
  res.render('members', {username: req.session.username});
});


// app.get('/admin', (req, res) => {
  
//   res.render('admin');
// });

// make a list of users from data base
app.get('/admin', async (req, res) => {
  const result = await userCollection.find({}).project({ username: 1, type:1 }).toArray();
  res.render('admin', { users: result });
});

app.post('/promote', async (req, res) => {
  const result = await userCollection.updateOne({ email: req.body.email }, { $set: { type: 'admin' } });
  const updatedUser = await userCollection.findOne({ email: req.body.email });
  res.render('admin', { users: updatedUser });
});
   










app.post('/logout', (req, res) => {
  req.session.destroy();
  // 
  res.redirect('/login');
  // res.send(html);
});


// app.get('/cat/:id', (req, res) => {

//   var cat = req.params.id;

//   if (cat == 1) {
//     res.send("Fluffy: <img src='/images/fluffy.gif' style='width:250px;'>");
//   }
//   else if (cat == 2) {
//     res.send("Socks: <img src='/images/socks.gif' style='width:250px;'>");
//   }
//   else if (cat == 3) {
//     res.send("giphy.gif: <img src='/images/giphy.gif' style='width:250px;'>");
//   }else {
//     res.send("Invalid cat id: " + cat);
//   }
// });


app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
  res.status(404);
  res.send("Page not found - 404");
})

app.listen(port, () => {
  console.log("Node application listening on port " + port);
});