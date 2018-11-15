var mongoose = require('mongoose');
var bcrypt = require('bcryptjs');

var UserSchema = mongoose.Schema({
	username: {
		type: String,
		index: true
	},
	password: {
		type: String
	}
});

var User = module.exports = mongoose.model('User', UserSchema);

module.exports.getUserByUsername = function (username, callback) {
	var query = {
		username: username
	};
	User.findOne(query, callback);
}

module.exports.getUserById = function (id, callback) {
	User.findById(id, callback);
}

module.exports.comparePassword = function (candidatePassword, hash, callback) {
	bcrypt.compare(candidatePassword, hash, function (err, isMatch) {
		if (err) throw err;
		callback(null, isMatch);
	});
}

module.exports.updateUserPassword = function (candidatePassword, callback) {
	bcrypt.hash(candidatePassword, 10, function (err, hash) {
		if (!err) {
			User.updateOne({
				"username": "admin"
			}, {
				"password": hash
			}, function (error, affected) {
				if (!error) {
					callback(error, true);
				} else {
					callback(err, false);
				}
			});
		} else {
			callback(err, false);
		}
	});
}