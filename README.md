# pusudb-use-auth-jwt

> Middleware to authenticate the pusudb.

This middleware implements authentication with jsonwebtoken.

Framework: [https://www.npmjs.com/package/pusudb](https://www.npmjs.com/package/pusudb)

<a name="installing"></a>
## Installing

```sh
npm install pusudb-use-auth-jwt --save
```

## Use
Create the auth-instance and define the options. The user can be accessed with req.user in other middlewares.

```js
var Pusudb = require('pusudb')
var pusudb = new Pusudb(3000, 'localhost', { log : true })

var AuthJwt = require('pusudb-use-auth-jwt')

/**
 * Default options {
     *  login: '/login',
     *  logout: '/logout',
     *  signin: '/signin',
     *  signinActive: true,
     *  redirect: '/index',
     *  redirectActive: false,
     *  cookie : 'bearer',
     *  db: 'users',
     *  form: { password : 'password', name : 'email' },
     *  secret : 'my-super-secret',
     *  expire: '1y',
     *  assignUser: false // assign key and userName to req.docs to handle it in the response
 * }
 */

var authjwt = new AuthJwt(/* options */) 

// Add some routes which needs authentication ( string || array )
auth.setRoutes('/admin', '/mypanel')
auth.setRoutes('/private', ['/privateOne', '/privateTwo'])

auth.setRoutesWebSocket('/api')

//add the middleware to the pusudb
pusudb.useBefore('http', authjwt.serve)

//add the middleware to the pusudb for websocket-authentication
pusudb.useBefore('ws', authjwt.serveWebSocket)

pusudb.listen(function(port, host){
    console.log('pusudb listening:', port, host)
})
```

## HTML

POST the userdata to the pusudb. The names of the form-input-fields are defined in option form. The action are defined in options login, logout and signin.

## WebSocket

Emit a login, logout, signin or token package to the pusudb.

```js
// Login
ws.send(JSON.stringify({meta : 'login', data: { email : 'pusu@pusu.com', password: '1234'}}));
// Logout
ws.send(JSON.stringify({ meta : 'logout', data: { email : 'pusu@pusu.com', password: '1234'}}));
// Signin
ws.send(JSON.stringify({meta : 'signin', data: { email : 'pusu@pusu.com', password: '1234'}}));
// Token
ws.send(JSON.stringify({meta : 'token', data: /* jsonwebtoken from http-cookie, check options */));
``` 


<a name="authors"></a>

## Authors

* **Yannick Grund** - *Initial work* - [yamigr](https://github.com/yamigr)

<a name="license"></a>

## License

This project is licensed under the MIT License

