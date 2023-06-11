require("dotenv").config();
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const express = require("express");
const ejs = require("ejs");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended:true}));

app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://127.0.0.1:27017/userDB");

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) { 
    console.log("user.id in serializeUser: " + user.id);
    done(null, user.id);
}); 

passport.deserializeUser(function (id, done) {
    console.log("id in deserializeUser: " + id);
    User.findById(id);
    done(null,id);
});   

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
 },
  function(accessToken, refreshToken, profile, cb) {
    console.log("profile.id: " + profile.id);
    
    User.findOrCreate({googleId: profile.id}, function (err, user) {
      return cb(err, user);
     }); 
  })); 
 
app.get("/auth/google", passport.authenticate("google", {scope: ["profile"]}));

app.get("/auth/google/secrets", passport.authenticate("google", 
    {failureRedirect: "/login"}),function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/secrets");
});

app.get("/", function(req, res){ 
    res.render("home");
});

app.get("/login", function(req, res){
    res.render("login");
}); 

app.get("/register", function(req, res){
    res.render("register");
});

app.get("/secrets", function(req, res){
    User.find({"secret": {$ne: null}}).then(function(foundUsers){
        res.render("secrets", {usersWithSecret: foundUsers});
    });
}); 

app.get("/submit", function(req, res){
    if (req.isAuthenticated ()){
        res.render("submit")
    }else{
        res.redirect("/login");
    }
});

app.post("/submit", function(req, res) {
    const submittedSecret = req.body.secret;
    User.findByIdAndUpdate(req.user, 
          {secret: submittedSecret}).then(function (doc) {
          console.log("Updated doc : ", doc);
          res.redirect("/secrets");
    });
});

app.get("/logout", function(req, res){
    req.logOut(function(err) {if (err) {return next(err)}});
    res.redirect("/");
}); 

//REGISTERING NEW USER
app.post("/register", function(req, res){
    User.register({username: req.body.username}, req.body.password, 
        function(err, user){
        if(err){
            console.log(err);
            res.redirect("/register");
        }else{
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }
    });   
}); 

//LOGIN EXISTING USER
app.post("/login", function(req, res){
    const user = new User ({
        username: req.body.username,
        password: req.body.password
    });
    req.login(user, function(err){
        if(err){
            console.log(err);
        }else{
            passport.authenticate("local")(req, res, function(){
            res.redirect("/secrets");
            });
        };
    });
}); 
   
app.listen(3000, function(){
    console.log("Server started on port 3000");
}); 