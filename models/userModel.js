const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Please tell us your name']
  },
  regNumber: {
    type: String,
    required: [true, 'Please tell us your registration number']
  },
  email: {
    type: String,
    required: [true, 'Please provide your email'],
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'Please provide a valid email']
  },
  photo: {
    type: String,
    default: 'default.jpg'
  },
  role: {
    type: String,
    default: 'student',
    enum: ['student', 'staff', 'admin'],
  },
  bio: {
    type: String,
    trim: true
  },
  clubs: [String],
  password: {
    type: String,
    required: [true, 'Please provide a password'],
    minlength: 8,
    select: false,
  },
  passwordConfirm: {
    type: String,
    required: [true, 'Please confirm your password'],
    validate: {
      //This only works on create and save!!
      validator: function (el) {
        return el === this.password;
      },
      message: 'Passwords are not the same!',
    },
  },
  passwordChangeAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  active: {
    type: Boolean,
    default: true,
    select: false,
  },
});

// Socument Middleware

userSchema.pre('save', async function(next) {
  // only run this function if password is modified
  if(!this.isModified('password')) return next();

  // Encrtypt or hash the password
  // Either use a cost parameter or you cabn salt the hash
  this.password = await bcrypt.hash(this.password, 12);
  // delete the passwordConfirm
  this.passwordConfirm = undefined;
  next();
});


// student changed their password
userSchema.pre('save', function(next){
  if(!this.isModified('password') || this.isNew) return next();
  // takes some time to save to db so minus 1 second
  this.passwordChangeAt = Date.now() -1000;
});

// find students
userSchema.pre(/^find/, function(next){
  // this points to the current user
  this.find({active: {$ne: false}});
  next();
});

// **** instance method ****
// 1) Check if the passwords are correct
userSchema.methods.correctPassword = async function (
  candidatePassword,
  studentPassword
){
  return await bcrypt.compare(candidatePassword, studentPassword);
}

// 2) cheking if the user changed the password
userSchema.methods.changedPasswordsAfter = function (JWTTimestamp) {
  if (this.passwordChangeAt) {
    const changedTimeStamp = parseInt(
      this.passwordChangeAt.getTime() / 1000,
      10
    );
    return JWTTimestamp < changedTimeStamp;
  }

  //False means NOT changed
  return false;
};

// 3) sending password reset token
userSchema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString('hex');
  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');
  // console.log({ resetToken }, this.passwordResetToken);
  // passwod reset token expires after 10min
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000;

  return resetToken;
};

const User = mongoose.model('User', userSchema);
module.exports = User;
