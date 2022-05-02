import express from 'express'
import session from 'express-session'
import bcrypt from 'bcrypt'
import mongoose from 'mongoose'
import passport from 'passport'
import {Strategy as LocalStrategy} from 'passport-local'
import {dirname} from 'path'
import {fileURLToPath} from 'url'
import {User} from './models/user.js'

const __dirname = dirname(fileURLToPath(import.meta.url))

const app = express()
const PORT = process.env.PORT||8080
const server = app.listen(PORT,()=>console.log(`Listening on port ${PORT}`))

app.set('views', __dirname+'/views')
app.set('view engine', 'ejs')

app.use(express.json())
app.use(express.urlencoded({extended:true}))

app.use(session({
    secret:'clavesecreta',
    resave:true,
    saveUninitialized:true,
    cookie:{
        expires: 30000
    }
}))

app.use(passport.initialize())
app.use(passport.session())

passport.serializeUser((user,done)=>{return done(null,user)})
passport.deserializeUser((id,done)=>{
    User.findById(id,(err,user)=>{
        return done(err,user.id)
    })
})

const createHash = (password) => {
    return bcrypt.hashSync(
        password,
        bcrypt.genSaltSync(10)
    )
}

const isUserLogged = (req,res,next)=>{
    if(req.isAuthenticated()) return next()
    res.redirect('/login')
}

passport.use('signupStrategy', new LocalStrategy(
    (username, password, done)=>{
        User.findOne({username:username},(err,user)=>{
            if(err) return done(err)
            if(user) return done(null,false,{message:'user already register'})

            const newUser = {
                username: username,
                password: createHash(password)
            }

            User.create(newUser,(err,userCreated)=>{
                if(err) return done(err)
                return done(null,userCreated)
            })
        })
    }
))

passport.use('loginStrategy', new LocalStrategy(
    (username, password, done)=>{
        User.findOne({username:username},(err,userFound)=>{
            if(err) return done(err)
            if(!userFound) return done(null,false,{message:'user already exist'})
            if(!bcrypt.compareSync(password,userFound.password)) return done(null,false,{message:'invalid password'})
            return done(null,userFound)
        })
    }
))

const URL = 'mongodb+srv://julian:coder123@clasecoderatlas.strau.mongodb.net/desafioPassport?retryWrites=true&w=majority'

mongoose.connect(URL,{
    useNewUrlParser:true,
    useUnifiedTopology:true
},(err)=>{
    if(err) throw new Error('unable to connect')
    console.log('connected to DB')
})

app.get('/',(req,res)=>{
    res.render('home',{prueba:0})
})
app.get('/signup',(req,res)=>{
    if(req.isAuthenticated()) return res.redirect('/profile')
    res.render('signup')
})
app.get('/login',(req,res)=>{
    if(req.isAuthenticated()) return res.redirect('/profile')
    res.render('login')
})
app.get('/profile',isUserLogged,(req,res)=>{
    res.render('profile',{user:req.session.passport.user.username})
})
app.get('/logout',(req,res)=>{
    if(req.isAuthenticated()) {
        req.logOut()
        res.render('logout') 
    }
    res.redirect('/')
})

app.get('/userExist',(req,res)=>{
    res.render('userExist')
})
app.get('/invalidPassword',(req,res)=>{
    res.render('invalidPassword')
})

app.post('/signup',passport.authenticate('signupStrategy',{
    failureRedirect:'/userExist'
}),(req,res)=>{
    res.redirect('/profile')
})

app.post('/login',passport.authenticate('loginStrategy',{
    failureRedirect:'/invalidPassword'
}),(req,res)=>{
    res.redirect('/profile')
})