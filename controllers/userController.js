const User = require('../models/userModel');
const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/appError');
const factory = require('./handlerFactroy');

exports.getAllUsers = factory.getAll(User);
exports.getUser = factory.getOne(User);


const filterObj = (obj, ...allowedFields) => {
  const newObj = {};
  Object.keys(obj).forEach((el) => {
    if (allowedFields.includes(el)) {
      newObj[el] = obj[el];
    }
  });
  return newObj;
};

exports.updateMe = catchAsync(async (req, res, next) => {
  // 1) Create an error  if user tries to update password
  if (req.body.password || req.body.confirmPassword) {
    return next(
      new AppError(
        'This route is not for password update please use /updateMyPassword'
      )
    );
  }

  // 2) Filter out unwanted data
  const filteredBody = filterObj(req.body, 'name', 'email');
  if(req.file) filteredBody.photo = req.file.filename;

  // 3) Update THE USER Document
  const updatedUser = await User.findByIdAndUpdate(req.user.id, filteredBody, {
    new: true,
    runValidators: true,
  });

  res.status(200).json({
    status: 'success',
    data: {
      updatedUser,
    },
  });
});

exports.deleteMe = catchAsync(async (req, res, next) => {
  await User.findByIdAndUpdate(req.user.id, { active: false });

  res.status(204).json({
    status: 'success',
    data: null,
  });
  next();
});
