const crypto = require('crypto');
const {promisify} = require('util');
const jwt = require('jsonwebtoken');
const Student = require('../models/studentModel');
const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/appError');
const Email = require('../utils/email');


const signToken = (id) => {
  return jwt.sign({id}, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN
  });
};

const createSendToken = (student, statusCode, res) => {
  const token = signToken(student._id);

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

  student.password = undefined;

  res.status(statusCode).json({
    status: 'success',
    token,
    data: {
      student
    }
  });
};

// signup
exports.signup = catchAsync(async (req, res, next) => {
  const newStudent = await Student.create({
    name: req.body.name,
    regNumber: req.body.regNumber,
    email: req.body.email,
    password: req.body.password,
    passwordConfirm: req.body.passwordConfirm
  });

  const url = `${req.protocol}://${req.get('host')}/account`;
  await new Email(newStudent, url).sendWelcome();

  // send student response
  return res.status(201).json({
    status: 'success',
    data: {
      newStudent
    }
  });
});


// login
exports.login = catchAsync(async(req, res, next) => {
  // destructuring
  const {email, passwod} = req.body;
  // 1) check if the email and password exists
  if(!email || !password){
    return next(new AppError('Please provide email and passwod', 404));
  }
  // 2) check if student exist and password is correct
  const student = await Student.findOne({email}).select('+password');

  if(!student || !(await student.correctPassword(passwod, student.password))){
    return next(new AppError('Incorrect email or password', 401));
  }

  // 3) if ok send token to student
  createSendToken(student, 200, res);
});

// logout
export.logout(req, res) => {
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

  // 3) check if the student stil exists
  const freshStudent = await Student.findById(decoded.id);
  if (!freshStudent) {
    return next(
      new AppError('The student belonging to the token no longer exists.', 401)
    );
  }

  // 4) Chek if student changed password after the token was issued

  if(freshStudent.changedPasswordsAfter(decoded.iat)){
    return next(
      new AppError('The student recently changed the password! Please login again')
    );
  }

  // 5) grant acces to the protected route
  req.student = freshStudent;
  req.locals.student = freshStudent;
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

      // 2) Check if student still exists
      const freshStudent = await Student.findById(decoded.id);

      if(!freshStudent){
        return next();
      }

      //  3) check if use changed password after the oken was issued
      if(freshStudent.changedPasswordsAfter(decoded.iat)){
        return next();
      }

      // 4) there is LOGGED IN STUDENT
      res.locals.student = freshStudent;
      return next();

    } catch (err){
      return next();
    }
  }
  next();
};

exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    if(!roles.includes(req.student.role)){
      return next(
        new AppError('You do not have permission to perform this action.', 401)
      );
    }
    next();
  }
}

exports.forgotPassword = catchAsync(async (req, res, next) => {
  // Get the student based on the email
  const student = await Student.findOne({email: req.body.email});
  if(!student){
    return next(new AppError('There is no student with that email address', 404));
  }

  // Generate the random reset token
  const resetToken = student.createPasswordResetToken();
  await student.save({ validateBeforeSave: false });

  // 3) Send it to the student's email
  try{
    const resetURL = `${req.protocol}://${req.get(
    'host'
    )}/api/v1/students/resetPassword/${resetToken}`;
    await new Email(student, resetURL).sendResetPassword();

    res.status(200).json({
      status: 'success',
      message: 'Token sent to email',
    });

  } catch (err) {
    student.passwordResetToken = undefined;
    student.PasswordResetExpires = undefined;

    await student.save({ validateBeforeSave: false });

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
  const student = await Student.findOne({
    passwordResetToken: hashedToken,
    PasswordResetExpires: {$gt: Date.now()}
  });

  // 2) If token has not expired and there is a student, set password
  if(!student) {
    return next(new AppError('Token is invalid or has Expired', 400));
  }
  student.password = req.body.password;
  student.passwordConfirm = req.body.passwordConfirm;
  student.passwordResetToken = undefined;
  student.passwordResetExpires = undefined;
  await student.save();
  // 3) Update changedPasswordsAt property for the student

  // 4) log he student in send jwt
  createSendToken(student, 200, res);
});


exports.updatePassword = catchAsync(async(req, res, next) => {
  // 1) Get student from collection
  const student = await Student.findById(req.student.id).select('+passwod');

  // 2) Check if posted passwod if correct
  if (!(await student.correctPassword(req.body.passwordCurent, student.password))) {
    return next(new AppError('Your current password is wrong.', 401));
  }

  // 3) If so update password
  student.password = req.body.password;
  student.passwordConfirm = req.body.passwordConfirm;
  await student.save();

  // 4) Log student in, send jwt
  createSendToken(student, 200, res);
});
