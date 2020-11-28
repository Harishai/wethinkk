const LocalStrategy = require('passport-local').Strategy
const bcrypt = require('bcrypt')
const mongoose = require('mongoose')

// Load User model
const Parents = require('../models/parentsModel')
const Teachers = require('../models/teacherModel')
const Students = require('../models/studentsModel')
const Admin = require('../models/adminsModel')

function SessionConstructor(userId, userGroup, details) {
  this.userId = userId;
  this.userGroup = userGroup;
  this.details = details;
}

module.exports = function(passport) {
  passport.use('local_parents',
    new LocalStrategy({ usernameField: 'email' }, (email, password, done) => {
      // Match user
      Parents.findOne({
        email: email
      }).then(user => {
        if (!user) {
          return done(null, false, { message: 'That email is not registered' });
        }

        // Match password
        bcrypt.compare(password, user.password, (err, isMatch) => {
          if (err) throw err;
          if (isMatch) {
            return done(null, user);
          } else {
            return done(null, false, { message: 'Password incorrect' });
          }
        });
      });
    })
  );

  passport.use('local_teacher',
    new LocalStrategy({ usernameField: 'email' }, (email, password, done) => {
      // Match user
      Teachers.findOne({
        email: email
      }).then(user => {
        if (!user) {
          return done(null, false, { message: 'That email is not registered' });
        }

        // Match password
        bcrypt.compare(password, user.password, (err, isMatch) => {
          if (err) throw err;
          if (isMatch) {
            return done(null, user);
          } else {
            return done(null, false, { message: 'Password incorrect' });
          }
        });
      });
    })
  );

  passport.use('local_student',
    new LocalStrategy({ usernameField: 'username' }, (username, password, done) => {
      // Match user
      Students.findOne({
        username: username
      }).then(user => {
        if (!user) {
          return done(null, false, { message: 'That username is not registered' });
        }

        // Match password
        bcrypt.compare(password, user.password, (err, isMatch) => {
          if (err) throw err;
          if (isMatch) {
            return done(null, user);
          } else {
            return done(null, false, { message: 'Password incorrect' });
          }
        });
      });
    })
  );

  passport.use('local_admin',
    new LocalStrategy({ usernameField: 'email' }, (email, password, done) => {
      // Match user
      Admin.findOne({
        email: email
      }).then(user => {
        if (!user) {
          return done(null, false, { message: 'That email is not registered' });
        }
        // Match password
        bcrypt.compare(password, user.password, (err, isMatch) => {
          if (err) throw err;
          if (isMatch) {
            return done(null, user);
          } else {
            return done(null, false, { message: 'Password incorrect' });
          }
        });
      });
    })
  );

  passport.serializeUser(function (userObject, done) {
    // userObject could be a Model1 or a Model2... or Model3, Model4, etc.
    let userGroup = "model1";
    let userPrototype =  Object.getPrototypeOf(userObject);
    if (userPrototype === Parents.prototype) {
      userGroup = "model1";
    } else if (userPrototype === Teachers.prototype) {
      userGroup = "model2";
    } else if (userPrototype === Students.prototype) {
      userGroup = "model3";
    } else if (userPrototype === Admin.prototype) {
      userGroup = "model4";
    }
    let sessionConstructor = new SessionConstructor(userObject.id, userGroup, '');
    done(null,sessionConstructor);
  });

  passport.deserializeUser(function (sessionConstructor, done) {
    if (sessionConstructor.userGroup == 'model1') {
        Parents.findOne({_id: sessionConstructor.userId
      }, (err, user) => { // When using string syntax, prefixing a path with - will flag that path as excluded.
          done(err, user);
      });
    } else if (sessionConstructor.userGroup == 'model2') {
      Teachers.findOne({_id: sessionConstructor.userId
        }, (err, user) => { // When using string syntax, prefixing a path with - will flag that path as excluded.
            done(err, user);
        });
    } else if (sessionConstructor.userGroup == 'model3') {
      Students.findOne({_id: sessionConstructor.userId
        }, (err, user) => { // When using string syntax, prefixing a path with - will flag that path as excluded.
            done(err, user);
        });
    } else if (sessionConstructor.userGroup == 'model4') {
      Admin.findOne({_id: sessionConstructor.userId
        }, (err, user) => { // When using string syntax, prefixing a path with - will flag that path as excluded.
            done(err, user);
        });
    }
  });
}