var mongoose = require('mongoose');
var bcrypt = require('bcryptjs');

//Schema
var UserSchema = new mongoose.Schema({
  name: {type:String},
  roll_number: {type:Number},
  email: {type:String},
  password: {type:String},
  username: {type:String}
});

var User = module.exports = mongoose.model('User', UserSchema);

module.exports.createUser = function(newUser, callback){
	bcrypt.genSalt(10, function(err, salt) {
	    bcrypt.hash(newUser.password, salt, function(err, hash) {
	       newUser.password = hash;
	       newUser.save(callback);
		});
	});
}

module.exports.getUserByUsername = function(username, callback){
	var query = {username: username}
	User.findOne(query, callback);
}

module.exports.comparePassword = function(candidatePassword, hash, callback){
	bcrypt.compare(candidatePassword, hash, function(err, isMatch) {
    	if(err) throw err;
    	callback(null, isMatch);
	});
}

module.exports.getUserById = function(id, callback){
	User.findById(id, callback);
}