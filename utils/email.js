const nodemailer = require('nodemailer');
const pug = require('pug');


module.exports = class Email{
  constructor(user, url) {
    this.to = user.email;
    this.firstName = user.name.split(' ')[0];
    this.url = url;
    this.from = `Customer support <${process.env.EMAIL_FROM}>`;
  }

  newTransport(){
    return nodemailer.createTransport({
      service: 'SendGrid',
      auth: {
        user: process.env.SENDGRID_USERNAME,
        pass: process.env.SENDGRID_PASSWORD
      }
    });
  }

  // send the actual email
  async send(template, subject){
    // 1) Rendered HTML based on the pug template
    const html = pug.renderFile(
      `${__dirname}/../views/emails/${template}.pug`,
      {
        firstName: this.firstName,
        url: this.url,
        subject,
      }
    );

    // 2)  Define email options
    const mailOptions = {
      from: this.from,
      to: this.to,
      subject,
      html,
    };

    // 3) Create a transport and send the email
    await this.newTransport().sendMail(mailOptions);
  }

  async sendWelcome() {
    await this.send('welcome', 'Welcome to Computer science  Department family');
  }


  async sendResetPassword() {
    await this.send(
      'passwordReset',
      'Your password reset token valid for only 10 min'
    );
  }
};
