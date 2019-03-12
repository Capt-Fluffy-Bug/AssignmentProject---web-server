var express = require('express');
var router = express.Router();
var User = require('../models/user')
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;

router.get('/register', function(req, res){
	res.render('register');
});

router.get('/login', function(req, res){
	res.render('login');
});

router.get('/about', function(req, res){
	res.render('about');
});

router.get('/home', function(req, res){
	res.render('home');
});

router.post('/register', function(req, res){
	var name = req.body.name;
	var email = req.body.email;
	var roll = req.body.roll;
	var username = req.body.username;
	var password = req.body.password;
	var password2 = req.body.password2;

	//validation
	req.checkBody('name', 'Name is required').notEmpty();
	req.checkBody('email', 'Email is required').notEmpty();
	req.checkBody('email', 'Email is not valid').isEmail();
	req.checkBody('roll', 'Roll number is required').notEmpty();
	req.checkBody('username', 'Username is required').notEmpty();
	req.checkBody('password', 'Password is required').notEmpty();
	req.checkBody('password2', 'Passwords must match').equals(req.body.password);


	var errors = req.validationErrors();

	if(errors){
		res.render('register',{
			errors: errors
		})
	} else{
		var newUser = new User({
			name: name,
			email: email,
			roll_number: roll,
			password: password,
			username: username
		});

		User.createUser(newUser, function(err, user){
			if(err) throw err;
			console.log('User created');
		});

		req.flash('success_msg', 'Registered Successfully');
		res.redirect('/users/login');
	}

});

passport.use(new LocalStrategy(function(username, password, done) {
    User.getUserByUsername(username, function(err, user){
    	if(err) throw err;
    	if(!user){
    		return done(null, false, {message: 'Unknown User'});
    	}

    	User.comparePassword(password, user.password, function(err, isMatch){
    		if(err) throw err;
    		if(isMatch){
    			return done(null, user);
    		} else{
    			return done(null, false, {message: 'Invalid password'})
    		}
    	});
    });
  }));

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.getUserById(id, function(err, user) {
    done(err, user);
  });
});

router.post('/login',
  passport.authenticate('local', {successRedirect:'/users/home', failureRedirect:'/users/login', failureFlash: true}),
  function(req, res) {
   
    res.redirect('/home' + req.user.username);
  });

router.get('/logout', function(req, res){
	req.logout();
	req.flash('success_msg', 'Logged out successfully');
	res.redirect('/users/login');
});

module.exports = router;