1 /*
  * This code has been cloned from 
  * https://github.com/oauthinaction/oauth-in-action-code.git
  * I will mark the sections that needed to be modified with a comment above
  * Modified by Emily Gentry 
 */
var express = require("express");
var bodyParser = require('body-parser');
var cons = require('consolidate');
var nosql = require('nosql').load('database.nosql');
var __ = require('underscore');
var cors = require('cors');

var app = express();

app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for bearer tokens)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/protectedResource');
app.set('json spaces', 4);

app.use('/', express.static('files/protectedResource'));
app.use(cors());

var resource = {
	"name": "Protected Resource",
	"description": "This data has been protected by OAuth 2.0"
};
/*
 * Scan for an access token on the incoming request. This will accept
 * bearer tokens passed in HTTP Authorization headers, inside a form 
 * encoded POST body and as a query parameter. 
 * MODIFIED
 */
var getAccessToken = function(req, res, next) {
	var inToken = null;
	/*
	 * OAuth does not specify whether or not Authorization or Bearer
	 * need to be uppercase or lower case. Both varients are valid.
	 * Express.js automatically lower cases all incoming HTTP headers
	 * and that is why it is safe to only check against lower case 
	 * authorization 
	 */
	var auth = req.headers['authorization'];
	if(auth && auth.toLowerCase().indexOf('bearer') == 0){
		inToken = auth.slice('bearer '.length); //the token IS case
												// sensitive
	} else if (req.body && req.body.access_token) 
	{
		inToken = req.body.access_token; 
	} else if(req.query && req.query.access_token) 
	{
		inToken = req.query.access_token;
	}
	/* 
	 * Database look up for the token 
	 */
	nosql.one(function(token)) {
		if(token.access_token == inToken){
			return token;
		}
	}, function (err, token) {
			if(token) {
				console.log("We found a matching token: %s", inToken);
			} else {
				console.log('No matching token was found.')
			}
			req.access_token = token;
			next();
			return;
	});
	
};

app.options('/resource', cors());


/*
 * Add the getAccessToken function to this handler
 * MODIFIED
 */
app.post("/resource", cors(), function(req, res){

	if(req.access_token){
		res.json(resource);
	} else {
		res.status(401).end();
	}

	
});

var server = app.listen(9002, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log('OAuth Resource Server is listening at http://%s:%s', host, port);
});
 
