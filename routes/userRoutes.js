const express = require('express');
const userController = require('../controllers/userController');
const authController = require('../controllers/authController');

const router = express.router();

// authentication
router.post('/signup', authContoller.signup);
router.post('/login', authContoller.login);
router.get('/logout', authContoller.logout);
router.post('/forgotPassword', authContoller.forgotPassword);
router.patch('/resetPassword/:token', authContoller.resetPassword);


// protect all the routes
router.use(authController.protect);
router.patch('/updateMyPassword', authController.updatePassword);
router.get('/me', userController.getUser);
router.patch(
  '/updateMe',
  authController.uploadUserPhoto,
  authController.resizeUserPhoto,
  userController.updateMe
);

router.delete('/deleteMe', userController.deleteMe);
router.use(authController.restrictTo('admin'));
router.route('/').get(userController.getAllUsers);
router.route(
  '/:id')
  .get(userController.getUser)
  .patch(userController.updatedUser)
  .delete(userController.deleteUser);
  
module.exports = router;
