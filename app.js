//jshint esversion:6
//Require dotenv as early as possible in application
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
//const encrypt = require("mongoose-encryption"); //Level 2 Security
//const md5 = require("md5"); //Level 3 Security
//const bcrypt = require("bcrypt"); //Level 4 Security
//const saltRounds = 10; //Level 4 Security
const session = require("express-session"); //Level 5 Security
const passport = require("passport"); //Level 5 Security
const passportLocalMongoose = require("passport-local-mongoose"); //Level 5 Security
const findOrCreate = require('mongoose-findorcreate'); //Level 6 Security | OAuth | Refer to Line 85
const GoogleStrategy = require('passport-google-oauth20').Strategy; //Level 6 Security | OAuth
const FacebookStrategy = require('passport-facebook').Strategy; //Level 6 Security | OAuth

const app = express();

app.set('view engine', 'ejs');

app.use(express.static("public"));
app.use(bodyParser.urlencoded({extended: true}));

//Level 5 | Place these before connecting to database
app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

main().catch(err => console.log(err));

async function main(){
    await mongoose.connect("mongodb://127.0.0.1:27017/userDB", {useNewUrlParser: true});
};

//Schema
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String, //Add for Level 6
    facebookId: String, //Add for Level 6
    secret: String
});

//Level 5 | Place this after creating a Schema
userSchema.plugin(passportLocalMongoose); // Level 5
userSchema.plugin(findOrCreate);

//Mongoose Encryption | Level 2 Security
//Refer to dotenv environment variable file
//Add the plugin first before creating a Mongoose Model or before passing the Schema as a parameter to create a Model
//Add 'encryptedFields' to specify which data to encrypt, don't use if you want to encypt the whole database

//userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ["password"]});

//Model
const User = mongoose.model("User", userSchema);

//Level 5 | Place these after creating a Model
passport.use(User.createStrategy());
// passport.serializeUser(User.serializeUser()); //Serialize creates Cookie | Level 5 only
// passport.deserializeUser(User.deserializeUser()); //Deserialize crumbles the Cookie } Level 5 only

//for all types including Level 6
passport.serializeUser(function(user, done){
    done(null, user.id);
});

passport.deserializeUser(function(id, done){
    User.findById(id, function(err, user){
        done(err, user);
    });
});

//Level 6 | Google OAuth
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

//Level 6 | Facebook OAuth
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res){
    res.render("home");
});

//Level 6 | Google OAuth
app.get("/auth/google",
    passport.authenticate('google', { scope: ["profile"] })
);

app.get("/auth/google/secrets", 
    passport.authenticate('google', { failureRedirect: "/login" }),
    function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
    }
);

//Level 6 | Facebook OAuth
app.get("/auth/facebook",
  passport.authenticate('facebook', { scope: ["public_profile"] })
);

app.get("/auth/facebook/secrets",
  passport.authenticate('facebook', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
);

app.get("/login", function(req, res){
    res.render("login");
});

app.get("/register", function(req, res){
    res.render("register");
});

app.get("/secrets", function(req, res){
    if(req.isAuthenticated()){
        User.find({"secret": {$ne: null}}, function(err, foundUsers){
            if(err){
                console.log(err);
            }else{
                if(foundUsers){
                    res.render("secrets", {usersWithSecrets: foundUsers})
                }
            }
        });
    }else{
        res.redirect("/login");
    }
});

app.get("/submit", function(req, res){
    if(req.isAuthenticated()){
        res.render("submit");
    }else{
        res.redirect("/login");
    }
});

app.get("/logout", function(req, res){
    //passport package
    req.logout(function(err){
        if(err){
            console.log(err);
        }else{
            res.redirect("/");
        }
    });
});

app.post("/submit", function(req, res){
    const submittedSecret = req.body.secret;
    console.log(req.user.id);

    User.findById(req.user.id, function(err, foundUser){
        if(err){
            console.log(err);
        }else{
            if(foundUser){
                foundUser.secret = submittedSecret;
                foundUser.save(function(){
                    res.redirect("/secrets");
                });
            }
        }
    });
});

// --------- Use login below for Security 5 --------- //

app.post("/login", function(req, res){
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    //passport package
    req.login(user, function(err){
        if(err){
            console.log(err);
        }else{
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }
    })
});

// --------- Use register below for Security 5 --------- //

app.post("/register", function(req, res){
    //passport-local-mongoose package
    User.register({username: req.body.username}, req.body.password, function(err, user){
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

// --------- Use login below for Securities 1-4 --------- //

// app.post("/login", function(req, res){
//     const username = req.body.username;
//     const password = req.body.password; //md5(req.body.password) | Level 3

//     //By using any SQL commands, the decryption will automatically be triggered //Level 2
//     User.findOne({email: username}, function(err, foundUser){
//         if(err){
//             console.log(err);
//         }else{
//             //Check if user registered
//             if(foundUser){
//                 //Check registered user's password

//                 /*
//                 if(foundUser.password === password){
//                     res.render("secrets");
//                 }
//                 */

//                 //Level 4
//                 bcrypt.compare(password, foundUser.password, function(err, result){
//                     if(result === true){
//                         res.render("secrets");
//                     }
//                 });
//             }
//         }
//     });
// });

// --------- Use register below for Securities 1-4 --------- //

// app.post("/register", function(req, res){

//     //Level 4
//     bcrypt.hash(req.body.password, saltRounds, function(err, hash){
//         //Document
//         const newUser = new User({
//             email: req.body.username,
//             password: hash
//         });

//         newUser.save(function(err){
//             if(err){
//                 console.log(err);
//             }else{
//                 res.render("secrets");
//             }
//         });
//     });
    
//     /*
//     //Document
//     const newUser = new User({
//         email: req.body.username,
//         password: req.body.password //md5(req.body.password) | Level 3
//     });

//     //By using save(), the encryption will automatically be triggered //Level 2
//     newUser.save(function(err){
//         if(err){
//             console.log(err);
//         }else{
//             res.render("secrets");
//         }
//     });
//     */
// });

app.listen(3000, function(){
    console.log("Server started on port 3000.");
});