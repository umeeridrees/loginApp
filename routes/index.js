var express = require('express');
var router = express.Router();
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;

var User = require('../models/user');

/* GET home page. */
router.get('/', ensureAuthenticated, function (req, res, next) {
  res.render('index', {
    title: 'Main Page'
  });
});

router.get('/users', ensureAuthenticated, function (req, res, next) {
  res.render('users', {
    title: 'Users'
  });
});

router.get('/changePassword', ensureAuthenticated, function (req, res, next) {
  res.render('changePassword', {
    title: 'Login'
  });
});

router.post('/changePassword', ensureAuthenticated, function (req, res, next) {
  console.log(req.body);
  if (req.body.NewPassword.length < 8) {
    req.flash('error_msg', 'Password should be minimum 8 characters long');
    res.redirect('/changePassword');
  } else if (req.body.NewPassword != req.body.cNewPassword) {
    req.flash('error_msg', 'Passwords do not match');
    res.redirect('/changePassword');
  } else {
    User.updateUserPassword(req.body.NewPassword, function (err, result) {
      if (result) {
        req.flash('success_msg', 'Password is changed');
        res.redirect('/login');
      } else if (!err) {
        req.flash('error_msg', 'Could not change password');
        res.redirect('/changePassword');
      } else {
        req.flash('error', err.message);
        res.redirect('/changePassword');
      }
    });
  }

});

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  } else {
    req.flash('error_msg', 'You are not logged in');
    res.redirect('/login');
  }
}

router.get('/login', function (req, res, next) {
  res.render('login', {
    title: 'Login'
  });
});

/* router.post('/logout', function (req, res, next) {
  res.sendStatus(401);
}); */

passport.use(new LocalStrategy(
  function (username, password, done) {
    User.getUserByUsername(username, function (err, user) {
      if (err) throw err;
      if (!user) {
        return done(null, false, {
          message: 'Incorrect username or password'
        });
      }

      User.comparePassword(password, user.password, function (err, isMatch) {
        if (err) throw err;
        if (isMatch) {
          return done(null, user);
        } else {
          return done(null, false, {
            message: 'Invalid password'
          });
        }
      });
    });
  }
));

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.getUserById(id, function (err, user) {
    done(err, user);
  });
});

router.post('/login',
  passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
  }),
  function (req, res) {
    res.redirect('/');
  });

router.get('/logout', function (req, res) {
  req.logout();
  req.flash('success_msg', 'you are out');
  res.redirect('/login');
});

module.exports = router;