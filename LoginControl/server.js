var app = require('express')()
  , express = require('express')
  , cookieParser = require('cookie-parser')
  , session      = require('express-session')
  , server = require('http').createServer(app)
  , passport = require('passport')
  , bodyParser = require('body-parser')
  , SamlStrategy = require('passport-saml-too').Strategy
  , crypto = require('crypto')
  , config = require('./config');


var keys = config.crypto.keys;

var net = require('net');
var fs = require('fs');
passport.use('saml', new SamlStrategy(
  {
    path: config.pathprefix+'/callback',
    entryPoint: config.saml.idp,
    issuer: config.saml.issuer,
    privateCert: fs.readFileSync(config.saml.privatekey, 'utf-8').toString(),
    protocol: config.saml.protocol,
    identifierFormat: config.saml.identifierFormat,
    cert: fs.readFileSync(config.saml.cert, 'utf-8').toString()
  },
  function(profile, done) {
      return done(null, profile);
  })
);

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(id, done) {
  done(null, id);
});

if (config.useproxy)
  app.enable('trust proxy');
app.use(bodyParser());
app.use(cookieParser());
app.use(session({secret: config.sessionsecret, proxy: config.useproxy, cookie: { secure: config.securecookie }}));
app.use(function (req, res, next) {
    passport._strategy('saml')._saml.options.issuer = req.host.replace(/\./g, "_");
    next();
});
app.use(passport.initialize());
app.use(passport.session());

app.post(config.pathprefix+'/callback',
  passport.authenticate('saml', { failureRedirect: '/', failureFlash: true }),
  function(req, res) {
      //console.log(req.user);
    res.redirect('/');
  }
);
app.get(config.pathprefix+'/state', function(req, res) {
    res.json({state: req.isAuthenticated()});
});
app.get(config.pathprefix, passport.authenticate('saml', {samlFallback: 'login-request'}), function(req, res) {
    res.redirect('/');
});

app.get(config.pathprefix+'/info', function (req, res) {
    if (keys[req.host] == null) {
        return res.json({error: "No key specified in the config for host "+req.host+". Will not send"});
    }
    var cipher = crypto.createCipher(config.crypto.algo, new Buffer(keys[req.host]));
    var valid = new Date();
    valid.setSeconds(valid.getSeconds()+60);
    var data = JSON.stringify({user: req.user, valid: valid.toISOString()});
    //Mininum length of 50kb
    if (data.length < config.minlength)
        data = ((new Array(config.minlength)).join("|")+data).slice(-config.minlength);

    var buff = cipher.update(data, 'utf8', 'base64');
    buff = buff+cipher.final('base64');
    res.json({data: buff});
});

server.listen(config.port);
