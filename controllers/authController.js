const crypto = require('crypto');
const {promisify} = require('util');
const jwt = require('jsonwebtoken');
const User = require('../models/userModel');
const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/appError');
const Email = require('../utils/email');


const signToken = (id) => {
  return jwt.sign({id}, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN
  });
};

const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id);

  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 *1000
    ),
    httpOnly: true, // prevents it by being modified by the browser
  };

  if(process.env.NODE_ENV === 'production'){
    cookieOptions.secure = true;
  }

  res.cookie('jwt', token, cookieOptions);

  user.password = undefined;

  res.status(statusCode).json({
    status: 'success',
    token,
    data: {
      user
    }
  });
};

// signup
exports.signup = catchAsync(async (req, res, next) => {
  const newUser = await User.create({
    name: req.body.name,
    regNumber: req.body.regNumber,
    email: req.body.email,
    password: req.body.password,
    passwordConfirm: req.body.passwordConfirm
  });

  // const url = `${req.protocol}://${req.get('host')}/account`;
  // await new Email(newUser, url).sendWelcome();

  // send user response
  return res.status(201).json({
    status: 'success',
    data: {
      newUser
    }
  });
});


// login
exports.login = catchAsync(async(req, res, next) => {
  // destructuring
  const {email, password} = req.body;
  // 1) check if the email and password exists
  if(!email || !password){
    return next(new AppError('Please provide email and password', 404));
  }
  // 2) check if user exist and password is correct
  const user = await User.findOne({email}).select('+password');

  if(!user || !(await user.correctPassword(password, user.password))){
    return next(new AppError('Incorrect email or password', 401));
  }

  // 3) if ok send token to user
  createSendToken(user, 200, res);
});

// logout
exports.logout = (req, res) => {
  res.cookie('jwt', 'logged out', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true,
  });

  res.status(200).json({
    status: 'success',
  });
}

exports.protect = catchAsync(async (req, res, next) => {
  // 1) Getting the token and check if it exists
  let token;
  if(
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ){
    token = req.headers.authorization.split(' ')[1];
  } else if(req.cookies.jwt){
    token = req.cookies.jwt;
  }

  if (!token) {
    return next(
      new AppError('You are not loged in please login to gain access', 401)
    );
  }

  // 2) token verification
  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  // 3) check if the user stil exists
  const freshUser = await User.findById(decoded.id);
  if (!freshUser) {
    return next(
      new AppError('The user belonging to the token no longer exists.', 401)
    );
  }

  // 4) Chek if user changed password after the token was issued

  if(freshUser.changedPasswordsAfter(decoded.iat)){
    return next(
      new AppError('The user recently changed the password! Please login again')
    );
  }

  // 5) grant acces to the protected route
  req.user = freshUser;
  req.locals.user = freshUser;
  return next();
});

// only for rendered pages and there will be no errors
exports.isLoggedIn = async(req, res, next) => {
  if(req.cookies.jwt){
    try{
      // 1) TOKEN verification
      const decoded = await promisify(jwt.verify)(
        req.cookies.jwt,
        process.env.JWT_SECRET
      );

      // 2) Check if user still exists
      const freshUser = await User.findById(decoded.id);

      if(!freshUser){
        return next();
      }

      //  3) check if use changed password after the oken was issued
      if(freshUser.changedPasswordsAfter(decoded.iat)){
        return next();
      }

      // 4) there is LOGGED IN User
      res.locals.user = freshUser;
      return next();

    } catch (err){
      return next();
    }
  }
  next();
};

exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    if(!roles.includes(req.user.role)){
      return next(
        new AppError('You do not have permission to perform this action.', 401)
      );
    }
    next();
  }
}

exports.forgotPassword = catchAsync(async (req, res, next) => {
  // Get the user based on the email
  const user = await User.findOne({email: req.body.email});
  if(!user){
    return next(new AppError('There is no user with that email address', 404));
  }

  // Generate the random reset token
  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });

  // 3) Send it to the user's email
  try{
    // const resetURL = `${req.protocol}://${req.get(
    // 'host'
    // )}/api/v1/users/resetPassword/${resetToken}`;
    // await new Email(user, resetURL).sendResetPassword();

    res.status(200).json({
      status: 'success',
      message: 'Token sent to email',
    });

  } catch (err) {
    user.passwordResetToken = undefined;
    user.PasswordResetExpires = undefined;

    await user.save({ validateBeforeSave: false });

    return next(
      new AppError(
        `There was an error sending your email, please try again`,
        500
      )
    );
  }
});

exports.resetPassword = catchAsync(async (req, res, next) => {
  // 1) Get the stuent based on the token
  const hashedToken = crypto
    .createHash('sha256')
    .update(req.params.token)
    .digest('hex');
  const user = await User.findOne({
    passwordResetToken: hashedToken,
    PasswordResetExpires: {$gt: Date.now()}
  });

  // 2) If token has not expired and there is a user, set password
  if(!user) {
    return next(new AppError('Token is invalid or has Expired', 400));
  }
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  await user.save();
  // 3) Update changedPasswordsAt property for the user

  // 4) log he user in send jwt
  createSendToken(user, 200, res);
});


exports.updatePassword = catchAsync(async(req, res, next) => {
  // 1) Get user from collection
  const user = await User.findById(req.user.id).select('+passwod');

  // 2) Check if posted passwod if correct
  if (!(await user.correctPassword(req.body.passwordCurent, user.password))) {
    return next(new AppError('Your current password is wrong.', 401));
  }

  // 3) If so update password
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  await user.save();

  // 4) Log user in, send jwt
  createSendToken(user, 200, res);
});
