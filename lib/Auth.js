const path = require('path')
const Cookies = require('cookies')
const jwt = require('jsonwebtoken')
const crypto = require('crypto');

if(!crypto) throw new Error('Crypto not avaiable.')

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
     *  expire: '1y',
     *  assignUser: false
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
        this.db = this.options.db ? this.options.db : './users'
        this.form = this.options.form ? this.options.form : { password : 'password', name : 'email'}
        this.secret = this.options.secret || crypto.randomBytes(32).toString('hex');
        this.expire = this.options.expire ? this.options.expire :  '1y'
        this.assignUser = this.options.assignUser ? this.options.assignUser : false
        this.routes = []
        this.routesWs = []
        this.cookies
        this.websocketToken = {}
        this.serve = this.serve.bind(this)
        this.serveWebSocket = this.serveWebSocket.bind(this)

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
     * Set the auth-routes. These url's needs to be authenticated
     * Each argument is a route like '/admin' or '/secretepage'
    */
   setRoutesWebSocket(arr){

    for(let i in arguments){
        if(Array.isArray(arguments[i]))
        this.routesWs = this.routesWs.concat(arguments[i])
        else
        this.routesWs.push(arguments[i])
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
        try{
            switch(req.url){

                case this.loginPath:
                    this.login(req, res, function(code){
                        next(code)
                    })
                break
                
                case this.logoutPath:
                    this.logout(req, res, function(code){
                        next(code)
                    })
                break
    
                case this.signinPath:
                    if(this.signinActive){
                        this.signin(req, res, function(code){
                            next(code)
                        })
                    }
                    else{
                        next(401)
                    }
                break
    
                default:
                    // Check if the path needs to be authenticated
                    if(this.pathNeedsAuthentication(this.routes, req.url)){
                        this.verify(req, res, function(code){
                            next(code)
                        })
                    }
                    // Whooohooooo, nothing to dooooo, only parse token if exist to assign the user to req.user
                    else{
                        if(req.token && req.token !== '-'){
                            this.verify(req, res, function(code){
                                next()
                            })
                        }
                        else{
                            next()
                        }
                    }
                break
            }
        }
        catch(e){
            next(e)
        }
        


    }

    /**
     * Handle the metas by websocket data. Login, logout or signin. Or parse the jsonwebtoken. If normal data, verify the route
     * @param {object} req 
     * @param {object*} socket 
     * @param {function} next 
     */
    serveWebSocket(req, socket, next){
        let self = this
        // Get cookie
        req.token = ''
        req.token = req.headers['sec-websocket-key']

        try{
            if(Object.keys(req.body).length){
                switch(req.body.meta){
                    case 'login':
                        this.loginWs(req, socket, function(code){
                            next(code)
                        })
                    break
                    case 'logout':
                        this.logoutWs(req, socket, function(code){
                            next(code)
                        })
                    break
                    case 'signin':
                        if(this.signinActive){
                            this.signinWs(req, socket, function(code){
                                next(code)
                            })
                        }
                        else{
                            next(401)
                        }
                    break
                    case 'token':
                        jwt.verify( req.body.data, this.secret, function(err, decoded) {
                            if(!err){
                                // Add deocded data to body
                                req.body.data = decoded.data.value
    
                                self.loginWs(req, socket, function(code){
                                    next(code)
                                })
                            }
                            else{
                                next(500)
                            }
                        })
                    break
    
                    default:
                        // Check if the path needs to be authenticated
                        if(this.pathNeedsAuthentication(this.routesWs, req.url)){
                            this.verifyWs(req, socket, function(code){
                                next(code)
                            })
                        }
                        // Whooohooooo, nothing to dooooo, only parse token if exist to assign the user to req.user
                        else{
                            if(this.websocketToken[req.token]){
                                this.verifyWs(req, socket, function(code){
                                    next()
                                })
                            }
                            else{
                                next()
                            }
                        }
                    break
                }
            }
            else{
                socket.send(JSON.stringify({ err : 500, data : null}))
            }
        }
        catch(e){
            next(e)
        }


    }

    /**
     * Check if the url needs to be authenticated
     * It's possible to define a url like '/admin' then every deeper url needs also to be authenticated
     * 
     * @param {array} routes 
     * @param {string} url 
     */
    pathNeedsAuthentication(routes, url){
        for(let p in routes){
            if(url.startsWith(routes[p])){
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
            req.db.query(this.db, 'get', { key : req.body.value[this.form.name] }, function(doc){

                if(!doc.err){
                    if( self.validateHash( req.body.value[self.form.password], doc.data.value[self.form.password]) ){
                        // Assign the client-ip to token
                        doc.data = Object.assign(doc.data, { _clientIp : self.getClientIp(req)})
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
     * Websocket login, get the user, hold the sec-websocket-token as key and the jsonwebtoken as value in the object
     * The websocket connection generates on each connection a new token, that's why we doesn't save the token in the db
     * 
     * @param {object} req 
     * @param {object} socket 
     * @param {function} next 
     */
    loginWs(req, socket, next){
        let self = this
        req.db.query(this.db, 'get', { key : req.body.data.value[this.form.name] }, function(doc){
         
            if(!doc.err){
                // Assign the client-ip to token
                doc.data = Object.assign(doc.data, { _clientIp : self.getClientIp(req)})

                if(self.validateHash( req.body.data.value[self.form.password], doc.data.value[self.form.password])){
                    self.setLoggedWs(req, doc, socket)
                }
                // if token is passed
                else if(req.body.data.value[self.form.password] === doc.data.value[self.form.password]){
                    self.setLoggedWs(req, doc, socket)
                }
                // Unauthorized 
                else{
                    next(401)
                }
            }
            else{
                // User not existing
                socket.send(JSON.stringify({ err : doc.err, data : { body : 'User not exist.', status : 500}}))
            }
        })
    }

    // clear the websocket-object before adding the new authenticated user
    // create a key = username, value = token, create key = token, value = jsonwebtoken
    // to verify the user check the jsonwebtoken and the websocket token
    setLoggedWs(req, doc, socket){
        // clear the websocket token in object first
        this.deleteWsByName(req.body.data.value[this.form.name])
        // property username bind the unique base64 websocket id
        this.websocketToken[ req.body.data.value[this.form.name] ] = req.token
        // property unique base64 websocket id bind the jsonwebtoken
        this.websocketToken[req.token] = jwt.sign({data: doc.data}, this.secret, { expiresIn: this.expire })
        // Response
        socket.send(JSON.stringify({ err : doc.err, data : { body : 'logged in.', status : 200}}))
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
     * Logs out the websocket connection while deleting the token in object
     * @param {object} req 
     * @param {object} socket 
     * @param {function} next 
     */
    logoutWs(req, socket, next){
        if( this.websocketToken[req.token]  ){
            delete this.websocketToken[req.token]
            socket.send(JSON.stringify({ err : null, data : 200}))
        }
        else{
            socket.send(JSON.stringify({ err : 500, data : null}))
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
            req.db.query(this.db, 'get', { key : req.body.value[this.form.name] }, function(doc){
                if(doc.err){

                    // Encrypt password
                    req.body.value[self.form.password] = self.generateHash(req.body.value[self.form.password].toString());

                    // Add user
                    req.db.query(self.db, 'put', { key : req.body.value[self.form.name], value : req.body }, function(doc){

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
     * Signin a new user
     * @param {object} req 
     * @param {object} socket 
     * @param {function} next 
     */
    signinWs(req, socket, next){
        let self = this
        // Check if user exist, the key is the name
        req.db.query(this.db, 'get', { key : req.body.data.value[this.form.name] }, function(doc){
            if(doc.err){
                // Encrypt password
                req.body.data.value[self.form.password] = self.generateHash(req.body.data.value[self.form.password].toString());

                // Add user
                req.db.query(self.db, 'put', { key : req.body.data.value[self.form.name], value : req.body.data }, function(doc){
                    next(200)
                })

            }
            else{
                next(409)
            }
        })
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
                    req.db.query(self.db, 'get', { key : decoded.data.value[self.form.name] }, function(doc){

                        // Authorized
                        if(!doc.err && doc.data.value[self.form.password] == decoded.data.value[self.form.password] && decoded.data._clientIp === self.getClientIp(req)){
                            // empty callback to put the request to the other middlewares
                            self.assignUserToReq(req, decoded.data)
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

    verifyWs(req, socket, next){
        // verify a token
        let self = this
        jwt.verify( this.websocketToken[req.token], this.secret, function(err, decoded) {
            if(!err){
                // check if the base64 unique websocket id exist in object and the clientIp is the same like in the request
                if(self.websocketToken[ decoded.data.value[self.form.name] ] === req.token && decoded.data._clientIp === self.getClientIp(req)){
                    self.assignUserToReq(req, decoded.data)
                    next()
                }
                else{
                    socket.send(JSON.stringify({ err : err, data : 401}))
                }

            }
            else{
                next(500)
            }
        })
    }

    deleteWsByName(name){
        if(this.websocketToken[name]){
            delete this.websocketToken[ this.websocketToken[name] ]
            delete this.websocketToken[name]
        }
    }

    /**
     * Generating a hash, parse the salt
     * @param {string} plain 
     * 
     * return string
     */
    generateHash (password) {
        const salt = crypto.randomBytes(16).toString('hex');
        const hash = crypto.pbkdf2Sync(password, salt, 2048, 32, 'sha512').toString('hex');
        return salt + hash
    }

    /**
     * Check if password is valid
     * First split the hash into salt and original hash
     * Then create a new hash by the password and the given salt described above
     * At the end, compare the two hashes
     * @param {string} password plain password
     * @param {string} passwordHashed hashed password salt - secret - hash
     * 
     * return boolean
     */
    validateHash (password, passwordHashed) {
        try{
            const saltAndOriginalHash = passwordHashed.split(this.secret)
            const hash = crypto.pbkdf2Sync(password, passwordHashed.substr(0, 32), 2048, 32, 'sha512').toString('hex');
            return hash === passwordHashed.substr(32, passwordHashed.length)
        }
        catch(e){
            return false
        }
    }


    assignUserToReq(req, user){
        if(this.assignUser)
            req.docs = Object.assign(req.docs, { auth : { key : user.key, name : user.value[this.form.name] }})

        req.user = user
    }

    getClientIp(req) {
        return (req.headers["X-Forwarded-For"] ||
                req.headers["x-forwarded-for"] ||
                '').split(/\s*,\s*/)[0] ||
               req.client.remoteAddress;
    };
}




module.exports = AuthHandler