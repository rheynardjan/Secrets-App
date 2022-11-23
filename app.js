//jshint esversion:6
//Require dotenv as early as possible in application
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");

const app = express();

app.set('view engine', 'ejs');

app.use(express.static("public"));
app.use(bodyParser.urlencoded({extended: true}));

main().catch(err => console.log(err));

async function main(){
    await mongoose.connect("mongodb://127.0.0.1:27017/userDB", {useNewUrlParser: true});
};

//Schema
const userSchema = new mongoose.Schema({
    email: String,
    password: String
});

//Mongoose Encryption
//Refer to dotenv environment variable file
//Add the plugin first before creating a Mongoose Model or before passing the Schema as a parameter to create a Model
//Add 'encryptedFields' to specify which data to encrypt, don't use if you want to encypt the whole database
userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ["password"]});

//Model
const User = mongoose.model("User", userSchema);

app.get("/", function(req, res){
    res.render("home");
});

app.get("/login", function(req, res){
    res.render("login");
});

app.get("/register", function(req, res){
    res.render("register");
});

app.post("/login", function(req, res){
    const username = req.body.username;
    const password = req.body.password;

    //By using any SQL commands, the decryption will automatically be triggered
    User.findOne({email: username}, function(err, foundUser){
        if(err){
            console.log(err);
        }else{
            //Check if user registered
            if(foundUser){
                //Check registered user's password
                if(foundUser.password === password){
                    res.render("secrets");
                }
            }
        }
    });
});

app.post("/register", function(req, res){
    //Document
    const newUser = new User({
        email: req.body.username,
        password: req.body.password
    });

    //By using save(), the encryption will automatically be triggered
    newUser.save(function(err){
        if(err){
            console.log(err);
        }else{
            res.render("secrets");
        }
    });
});

app.listen(3000, function(){
    console.log("Server started on port 3000.");
});