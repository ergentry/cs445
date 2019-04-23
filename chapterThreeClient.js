/*
 * This code has been cloned from 
 * https://github.com/oauthinaction/oauth-in-action-code.git
 * I will mark the sections that needed to be modified with a comment above
 * Modified by Emily Gentry 
 */

var express = require("express");
var request = require("sync-request");
var url = require("url");
var qs = require("qs");
var querystring = require('querystring');
var cons = require('consolidate');
var randomstring = require("randomstring");
var __ = require('underscore');
__.string = require('underscore.string');

var app = express();

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/client');
/*
 * The information about the client itself and the auhtorization server
 * is all of the information the client will need to connect to the
 * authorization server
 */
// authorization server information
var authServer = {
	authorizationEndpoint: 'http://localhost:9001/authorize',
	tokenEndpoint: 'http://localhost:9001/token'
};

// client information


/*
 * Add the client information in here
 * MODIFIED
 */
var client = {
	"client_id": "oauth-client-1",
	"client_secret": "oauth-client-secret-1",
	"redirect_uris": ["http://localhost:9000/callback"]
};

var protectedResource = 'http://localhost:9002/resource';

var state = null;

var access_token = null;
var scope = null;

app.get('/', function (req, res) {
	res.render('index', {access_token: access_token, scope: scope});
});
/*
 * Sending the user to the authorization server
 * MODIFIED
 * An important part of any OAuth implementation is properly building
 * URLs and adding query parameters to use front-channel communication
 */
app.get('/authorize', function(req, res){

	access_token = null; //removing the old access token 

	state = randomstring.generate(); //randomly generating a state to
									//check against later
	var authorizeUrl = buildUrl(authServer.authorizationEndpoint, {
		response_type: 'code',
		client_id: client.client_id,
		redirect_uri: client.redirect_uris[0],
		state: state
	});

	res.redirect(authorizeUrl);
});						 

/*
 * Parse the response from the authorization server and get a token
 * MODIFIED
 */
app.get('/callback', function(req, res){

	//checking to ensure the state is still the same randomly generated
	//string 
	if(req.query.state != state)
	{
		res.render('error', {error: 'State value did not match'});
		return;
	}
	//the authorization code from the authorization server
	var code = req.query.code;

	//send the code directly to the token endpoint 
	var form_data = qs.stringify({
		grant_type: 'authorization_code',
		code: code,
		redirect_uri: client.redirect_uris[0]
	});
	/*
	 * Even though we are not redirecting anything the redirect uri has
	 * to be included in the token request because it was included in 
	 * the authorization request. This is per OAuth specification. This
	 * prevents an attacker from using a compromised redirect token 
	 * request
	 */

	 //Header to tell the server this is an HTTP form encoded request
	var headers = {
	 	'Content-Type': 'application/x-www-form-urlencoded',
		'Authorization': 'Basic' + encodeClientCredentials(
									client.client_id, client.client_secret)
	 };

	var tokRes = request('POST', authServer.tokenEndpoint,
	 	{
			body: form_data,
			headers: headers
		}
	 );
	
	var body = JSON.parse(tokRes.getBody());

	access_token = body.access_token;
});
/*
 * Use the access token to call the resource server
 * MODIFIED
 */
app.get('/fetch_resource', function(req, res) {
	
	//ensuring we have an access token 
	if(!access_token){
		res.render('error', {error: 'Missing Access Token'});
		return;
	}
	
	//OAuth defined header for Bearer tokens 
	var headers = {
		'Authorization': 'Bearer ' + access_token
	};

	//sending a request to the protected resource
	var resource = request('POST', protectedResource,
		{headers: headers}
	);

	//if the request is successful parse the body otherwise return 
	//an error 
	if(resource.statusCode >= 200 && resource.statusCode <  300){
		var body = JSON.pasre(resource.getBody());

		res.render('data', {resource: body});
		return;
	}
	else 
	{
		access_token = null;
		res.render('error', {error: resource.statusCode});
		return;
	}
	
});

var buildUrl = function(base, options, hash) {
	var newUrl = url.parse(base, true);
	delete newUrl.search;
	if (!newUrl.query) {
		newUrl.query = {};
	}
	__.each(options, function(value, key, list) {
		newUrl.query[key] = value;
	});
	if (hash) {
		newUrl.hash = hash;
	}
	
	return url.format(newUrl);
};

var encodeClientCredentials = function(clientId, clientSecret) {
	return new Buffer(querystring.escape(clientId) + ':' + querystring.escape(clientSecret)).toString('base64');
};

app.use('/', express.static('files/client'));

var server = app.listen(9000, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;
  console.log('OAuth Client is listening at http://%s:%s', host, port);
});
 
