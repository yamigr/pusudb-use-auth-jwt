const path = require('path')
const Cookies = require('cookies')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')

/**
 * autor: yannick grund, 2018
 * This class implements the authentication in the pusudb. It uses the jsonwebtoken-standard. The token is asigned to the cookie of the client.
 * It's possible to set routes which should be authenticatied
 * 
 * Defined options:
 * - path to login, logout, signin pages
 * - redirect path when successful login or logout, this can be activated
 * - cookie name
 * - database name
 * - the body keys for the name and the password 
 * - a secret to create the token
 * - a expire time formate by zeit/ms documentation https://github.com/zeit/ms
    *   ms('2 days')  // 172800000
        ms('1d')      // 86400000
        ms('10h')     // 36000000
        ms('2.5 hrs') // 9000000
        ms('2h')      // 7200000
        ms('1m')      // 60000
        ms('5s')      // 5000
        ms('1y')      // 31557600000
        ms('100')     // 100
        ms('-3 days') // -259200000
        ms('-1h')     // -3600000
        ms('-200')    // -200
 */

class AuthHandler {
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
     * 
     * @param {object} opt 
     */
    constructor(opt){
        this.options = typeof opt === 'object' ? opt : {}
        this.loginPath = this.options.login ? this.options.login : '/login'
        this.logoutPath = this.options.logout ? this.options.logout : '/logout'
        this.signinPath = this.options.signin ? this.options.signin : '/signin'
        this.signinActive = this.options.signinActive ? this.options.signinActive : true
        this.redirectPath = this.options.redirect ? this.options.redirect : '/index'
        this.redirectActive = this.options.redirectActive ? this.options.redirectActive : false
        this.cookieName = this.options.cookie ? this.options.cookie : 'bearer'
        this.db = this.options.db ? this.options.db : 'users'
        this.form = this.options.form ? this.options.form : { password : 'password', name : 'email'}
        this.secret = this.options.secret ? this.options.secret :  Math.random().toString(36).substring(2, 15)
        this.expire = this.options.expire ? this.options.expire :  '1y'
        this.routes = []
        this.cookies
        this.serve = this.serve.bind(this)
    }

    /** 
     * Set the auth-routes. These url's needs to be authenticated
     * Each argument is a route like '/admin' or '/secretepage'
    */
   setRoutes(arr){

        for(let i in arguments){
            if(Array.isArray(arguments[i]))
            this.routes = this.routes.concat(arguments[i])
            else
            this.routes.push(arguments[i])
        }

    }

    /**
     * Main-method. Serve the middleware
     * @param {object} req 
     * @param {object} res 
     * @param {function} next 
     */
    serve(req, res, next){
        let self = this

        // Parse cookie
        this.cookies = new Cookies(req, res)

        // Get cookie
        req.token = ''
        req.token = this.cookies.get(this.cookieName)

        // Handle the request by url
        switch(req.url){

            case this.loginPath:
                this.login(req,res,function(statusCode){
                    next(statusCode)
                })
            break
            
            case this.logoutPath:
                this.logout(req, res, function(statusCode){
                    next(statusCode)
                })

            break

            case this.signinPath:
                if(this.signinActive){
                    this.signin(req, res, function(statusCode){
                        next(statusCode)
                    })
                }
                else{
                    next(401)
                }

            break

            default:
                // Check if the path needs to be authenticated
                if(this.pathNeedsAuthentication(req.url)){
                    this.verify(req, res, function(statusCode){
                        next(statusCode)
                    })
                }
                // Whooohooooo, nothing to dooooo
                else{
                    next()
                }
            break
        }


    }

    /**
     * Check if the url needs to be authenticated
     * It's possible to define a url like '/admin' then every deeper url needs also to be authenticated
     * 
     * @param {string} url 
     */
    pathNeedsAuthentication(url){
        for(let p in this.routes){
            if(url.startsWith(this.routes[p])){
                return true
            }
        }
        return false
    }


    /**
     * Login-route
     * If a user POST the login data, check if user exist in database. If user exist validate the posted data
     * If user is authenticated, create a jsonwebtoken and set the token to the cookie
     * If user is unauthorized, fire next with statuscode 401
     * 
     * ToDo: Add host and client-stuff to add more security
     * 
     * @param {object} req 
     * @param {object} res 
     * @param {function} next callback with statuscode when error
     */
    login(req, res, next){
        let self = this

        // Handle the login
        if(req.method === 'POST' && Object.keys(req.body).length){
            // get the user by name. The key is the username or email or,...
            req.db.query('./' + this.db, 'get', { key : req.body[this.form.name] }, function(doc){

                if(!doc.err){
                    if( self.validateHash( req.body[self.form.password], doc.data.value[self.form.password]) ){

                        // ToDo: Add host and client-stuff to add more security

                        // Create the token
                        req.token = jwt.sign({data: doc.data}, self.secret, { expiresIn: self.expire });
                        // Set the cookie
                        self.cookies.set(self.cookieName, req.token)
                        // Response
                        if(self.redirectActive){
                            res.writeHead(302, {'Location': self.redirectPath});
                            res.end();
                            next(302)
                        }
                        else{
                            next(200)
                        }
                    }
                    // Unauthorized 
                    else{
                        next(401)
                    }
                }
                else{
                    // User not existing
                    next(401)
                }
            })
        }

        // Do nothing, when client get the login-page
        else if(req.method === 'GET'){
            next()
        }

        // Oooops somethin went wrong, method or body error
        else{
            next(500)
        }
    }

    /**
     * Logout-route
     * When a client wants to logout, clear the cookie data while replacing the token, the token can't be a empty string
     * ToDo: Check if it's possible to clear the cookie
     * 
     * @param {object} req 
     * @param {object} res 
     * @param {function} next 
     */
    logout(req, res, next){
        // cleare cookie
        this.cookies.set(this.cookieName, '-')
        // redirect to index
        if(this.redirectActive){
            res.writeHead(302, {'Location': this.redirectPath});
            res.end();
            next(302)
        }
        else{
            next(200)
        }
    }

    /**
     * Signin-route
     * When a client creates a user, check if method is post and handle the body, if user exist, send statuscode 409
     * When user-data is ok, create the hashed password and save the user in the db
     * The username is the key
     * 
     * @param {object} req 
     * @param {object} res 
     * @param {function} next callback with statuscode when error
     */
    signin( req, res, next ){
        let self = this
        if(req.method === 'POST' && Object.keys(req.body).length){

            // Check if user exist, the key is the name
            req.db.query('./' + this.db, 'get', { key : req.body[this.form.name] }, function(doc){
                if(doc.err){

                    // Encrypt password
                    req.body[self.form.password] = self.generateHash(req.body[self.form.password].toString());

                    // Add user
                    req.db.query('./' + self.db, 'put', { key : req.body[self.form.name], value : req.body }, function(doc){

                        // Response
                        if(self.redirectActive){
                            res.writeHead(302, {'Location': self.redirectPath});
                            res.end();
                            next(302)
                        }
                        else{
                            next(200)
                        }

                    })

                }
                else{
                    res.statusCode = 409
                    next(409)
                }
            })
        }

        // Do nothing when get the file
        else if(req.method === 'GET'){
            // Not handle for the auth,  it's the get requs
            next()
        }

        // Oooops somethin went wrong
        else{
            next(500)
        }
    }

    /**
     * Verify the user, parse the jsonwebtoken, get the user in the database and compare the password. Notice the password is hashed and not in plain text.
     * @param {object} req 
     * @param {object} res 
     * @param {function} next callback with statuscode when error
     */
    verify(req, res, next){
        let self = this
        if(!req.token){
            next(401)
        }
        else{
            // verify a token
            jwt.verify(req.token, this.secret, function(err, decoded) {
                if(!err){
                    req.db.query('./' + self.db, 'get', { key : decoded.data.value[self.form.name] }, function(doc){

                        // Authorized
                        if(!doc.err && decoded.data.value[self.form.password] == decoded.data.value[self.form.password]){
                            // empty callback to put the request to the other middlewares
                            next()
                        }

                        // Unauthorized
                        else{
                            next(401)
                        }
                    })
                }
                else{

                    // Token parsing error
                    next(401)
                }
            })
        }
    }

    /**
     * Generating a hash 
     * @param {string} plain 
     * 
     * return string
     */
    generateHash (plain) {
        return bcrypt.hashSync(plain, bcrypt.genSaltSync(8), null)
    }

    /**
     * Check if password is valid
     * @param {string} plain 
     * @param {string} hash 
     * 
     * return boolean
     */
    validateHash (plain, hash) {
        return bcrypt.compareSync(plain, hash)
    }

}




module.exports = AuthHandler