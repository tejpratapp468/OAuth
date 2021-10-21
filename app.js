//jshint esversion:6
require('dotenv').config() //Put this on top.This will be active and running so we are not setting a constant for it.
const express=require("express");
const bodyParser=require("body-parser");
const ejs=require("ejs");
const mongoose=require("mongoose");
const session = require('express-session');
const MongoStore = require('connect-mongo')
const passport=require("passport");
const passportLocalMongoose=require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app=express();

app.use(express.static("public"));
app.set('view engine','ejs');
app.use(bodyParser.urlencoded({extended:true}));

//to connect to our mongoDB
mongoose.connect(process.env.MONGO_URI,
  {useNewUrlParser: true,useUnifiedTopology: true,useFindAndModify: false ,useCreateIndex: true})
  .then(() => console.log("DB connected Successfully")) 
  .catch((error) => console.log(error.message));




//Its really important to place your code in the same order
//we have initialized session telling our app to use session package
app.use(session({
  //setting up initial configuration
  secret:process.env.SECRET,
  resave:false,
  saveUninitialized:false,
  store: MongoStore.create({ mongoUrl: process.env.MONGO_URI, useUnifiedTopology:true}),
}));

// to initialize passport
app.use(passport.initialize());

//telling our app to use passport to set up our session
app.use(passport.session());


//this schema is no longer simple a JS object but it is an object created from mongoose schema class.
const userSchema=new mongoose.Schema({
  email:String,
  password:String,
  googleId:String,
  secret:String
});

//set up for passportLocalMongoose & findOrCreate to plugin userSchema with passportLocalMongoose & findOrCreate it has to be a mongoose schema
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User=mongoose.model("User",userSchema);

//default code for using passportLocalMongoose from its documentation
passport.use(User.createStrategy()); //creating local login strategy

// In order to support login sessions, Passport will serialize and deserialize user instances to and from the session.
//creates cookie with user info
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

//allows passport to discover user info for identification
passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

//setting up google strategy
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo" //we are retriving user profile info from userinfo which is an endpoint on google not from google+  
  },
  /*google strategy for login and register if successful then we have callback function where
   google sends back accessToken,we got user's profile(profile contains user's email,google id etc that we have
 access to) */
  function(accessToken, refreshToken, profile, cb) {
    //console.log(profile);
    /*finally we use the data that we get back from google to find or create user in our database */
    User.findOrCreate({ googleId: profile.id,username:profile.emails[0].value }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/",function(req,res){
  res.render("home");
});

//registration request with google goes to this route
app.get("/auth/google",
  passport.authenticate('google', { scope: ["profile","email"] })
  //authenticating with google strategy and getting profile of user
);

//once login is successful google will redirect user back to our website by making get request to auth/google/secret
app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: "/login" }), //failure redirects to login page
  function(req, res) {
    // Successful authentication, redirects to secrets page.
    res.redirect('/secrets');
  });

app.get("/login",function(req,res){
  res.render("login");
});

app.get("/register",function(req,res){
  res.render("register");
});

app.get("/secrets",function(req,res){
  //find only secret field of only those users where their secret fiels is not equal to null
  User.find({"secret":{$ne: null}}, function(err,foundUsers){
    if(err){
      console.log(err);
    } else{
      if(foundUsers){
        res.render("secrets",{usersWithSecrets: foundUsers});
      }
    }
  });

});

app.get("/submit",function(req,res){
  if(req.isAuthenticated()){
    res.render("submit");
  } else{
    res.redirect("/login");
  }
})

app.post("/submit",function(req,res){
const submittedSecret=req.body.secret;
console.log(req.user.id);

User.findById(req.user.id,function(err,foundUser){
  if(err){
    console.log(err);
  } else {
    if(foundUser){
      foundUser.secret=submittedSecret;
      foundUser.save(function(){
        res.redirect("/secrets");/*Once foundUserget saved redirects hom to secrets page
        where they can see their own secrets alongside everybody else's.*/
      });
    }
  }
});

});

app.get("/logout",function(req,res){
  //Here we deauthenticate user and end that user session
  req.logout();
  res.redirect("/");
});

app.post("/register",function(req,res){
//this register method come from passport local mongoose
User.register({username:req.body.username},req.body.password,function(err,user){
  if(err){
    console.log(err);
    res.redirect("/register");
  } else{
    //if no err then we will try to authenticate user by local strategy
    passport.authenticate("local")(req,res,function(){
      /*this callback function only triggered if authentication was successful and
      we manage setup cookie that saves user current login session*/

      res.redirect("/secrets"); //Now no need to render secrets page user can directly go to secrets page
                                //by /secrets.Thanks to cookies!!
    })
  }
})

});

app.post("/login",function(req,res){

const user=new User({
  username:req.body.username,
  password:req.body.password
});

//this login method come from passport
req.login(user,function(err){  //user came from login credentials
  if(err){
    console.log(err);
  } else{
    passport.authenticate("local") (req,res,function(){
      /*this callback function only triggered if authentication was successful and
      we manage setup cookie that saves user current login session*/

      res.redirect("/secrets"); //Now no need to render secrets page user can directly go to secrets page//by /secrets.Thanks to cookies!!
    });
  }
});

});

app.listen(3000,function(){
  console.log("Server started on port 3000");
});

/*
Passport uses serializeUser function to persist user data (after successful authentication) into session. Function deserializeUser is used to retrieve user data from session.
*/

/*The Refresh Token grant type is used by clients to exchange a refresh token for an access token when the access token has expired.  */