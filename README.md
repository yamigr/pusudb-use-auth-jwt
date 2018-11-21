# pusudb-use-auth-jwt

> Middleware to authenticate the pusudb.

This middleware implements authentication with jsonwebtoken to the http-protocol.

Framework: [https://www.npmjs.com/package/pusudb](https://www.npmjs.com/package/pusudb)

<a name="installing"></a>
## Installing

```sh
npm install pusudb-use-auth-jwt --save
```

## Use
Create the auth-instance and define the options.

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
     *  expire: '1y'
 * }
 */

var authjwt = new AuthJwt(/* options */) 

// Add some routes which needs authentication ( string || array )
auth.setRoutes('/admin', '/mypanel')
auth.setRoutes('/private', ['/privateOne', '/privateTwo'])

//add the middleware to the pusudb
pusudb.use('http', authjwt.serve)

pusudb.listen(function(port, host){
    console.log('pusudb listening:', port, host)
})
```

<a name="authors"></a>

## Authors

* **Yannick Grund** - *Initial work* - [yamigr](https://github.com/yamigr)

<a name="license"></a>

## License

This project is licensed under the MIT License

