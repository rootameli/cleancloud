'use strict';

// Before running, you need to yarn add yargs nodemailer

// And also replace this with your email:
const DEFAULT_TO_EMAIL = 'benz69003@hotmail.com';

// Username password correct? Make sure your smtp provider doesn't 
// have a from/to email address whitelist, or if it does, both emails 
// are on it.

const yargs       = require('yargs');
const nodemailer  = require('nodemailer');

const argv = yargs.argv;

const host      = argv.host || argv.h;
const user      = argv.user || argv.u;
const pass      = argv.pw || argv.pass || argv.password || argv.p;
const port      = argv.port || 25;
const secure    = argv.secure || [ 465 ].indexOf(port) > -1;
const from      = argv.from;
const to        = argv.to || DEFAULT_TO_EMAIL;
const enableWeakSecurity = argv['weak-security'];

if (!from) throw new Error('--from [email] required');
if (!to) throw new Error('--to [email] required');

const config = {
  host,
  port,
  secure,
  tls: {
  },
  auth: {
    user,
    pass,
  }
};

if (enableWeakSecurity) {
  config.tls.rejectUnauthorized = false;
}

//console.log('config', JSON.stringify(config, null, 2));

const transporter = nodemailer.createTransport(config);

// setup email data with unicode symbols
const mailOptions = {
  from, // sender address
  to, // list of receivers
  subject: `Hello ✔ - ${new Date().toGMTString()}`, // Subject line
  text: 'Hello world?', // plain text body
  html: '<b>Hello world?</b>' // html body
};

//console.log('mailOptions', JSON.stringify(mailOptions, null, 2));

// send mail with defined transport object
transporter.sendMail(mailOptions, (err, info) => {
  if (err) {
      return console.log('error', err.response);
  }
  console.log('Message sent:', JSON.stringify(info, null, 2));
});
