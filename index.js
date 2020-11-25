const express = require('express');
const morgan = require('morgan');
const path = require('path');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const compression = require('compression');

const AppError = require('./utils/appError');
const globalErrorHandler = require('./controllers/errorController');
const userRouter = require('./routes/userRoutes');
const viewRouter = require('./routes/viewRoutes');

const app = express();


app.set('view engine', 'pug');
app.set('views', path.join(__dirname, 'views'));;

// GLOBAL Middlewares
// 1) Server static files
app.use(express.static(path.join(__dirname, 'public')));

// 2) Set Security HTTP headers
app.use(helmet());

// 3) Development loggind
if(process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

// 4) Body parser, reading data from body into req.Body
app.use(express.json({limit: '20kb'}));
app.use(express.urlencoded({extended: true, limit: '20kb'}));
app.use(cookieParser());

// 5) Data Sanitization
// 5a) Sanitization aganist NOSQL query injection
app.use(mongoSanitize());

// 5b) Sanitization aganist xss
app.use(xss());

// 6) request compression
app.use(compression());


// ROUTES
app.use('/', viewRouter);
app.use('/api/v1/users', userRouter);


// TEST Middleware
app.all('*', (req, res, next) => {
  next(new AppError(`Can't find ${req.originalUrl} on this server`, 400));
});

// Error handling
app.use(globalErrorHandler);
// Export app
module.exports = app;
