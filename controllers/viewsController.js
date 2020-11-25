const User = require('../models/userModel');
const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/appError');

exports.landing =  (req, res) => {
  res.status(200).render('landingPage');
}

exports.getOverview = (req, res) => {
  res.status(200).render('overview', {
    title: 'Computer Science Department'
  });
}

exports.getLoginForm = (req, res) => {
  res.status(200).render('login', {
    title: 'login'
  });
}

exports.getSignupForm = (req, res) => {
  res.status(200).render('signup', {
    title: 'Signup'
  });
}

exports.getForgotPasswordForm = (req, res) => {
  res.status(200).render('forgotPassword');
}

exports.getAccountPage = (req, res) => {
  res.status(200).render('account');
}

exports.getResetPaswordForm = (req, res) => {
  res.status(200).render('resetPassword');
}


exports.updateUserData = catchAsync(async(req, res, next) => {
  const updatedUser = await User.findByIdAndUpdate(req.user.id, {
    name: req.body.name,
    email: req.body.email
  },{
    new: true,
    runValidators: true
  }
  );
  res.status(200).render('account', {
    title: 'Your account',
    user: updatedUser
  });

})
