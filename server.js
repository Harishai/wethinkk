require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const expressLayouts = require('express-ejs-layouts')
const flash = require('connect-flash')
const session = require('express-session')
const passport = require('passport')

const app = express()
app.set('view engine', 'ejs')
app.set('views'. __dirname + '/views')
app.use(expressLayouts)
app.use(express.static('public'))

// Passport
require('./config/passport')(passport)


// Mongodb
const URI = process.env.MONGODB_URL
mongoose.connect(URI, {
    useCreateIndex: true,
    useFindAndModify: false,
    useNewUrlParser: true,
    useUnifiedTopology: true
}, err => {
    if (err) throw err;
    console.log("Connected to mongodb")
})

// Bodyparser
app.use(express.urlencoded({extended:false}))

// Express Session
app.use(session({
    secret: process.env.SECRET,
    resave: true,
    saveUninitialized: true,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24
    }
}))

// Passport 
app.use(passport.initialize())
app.use(passport.session())

// Connect Flash
app.use(flash())

// Global Vars
app.use((req, res, next) => {
    res.locals.success_msg = req.flash('success_msg')
    res.locals.error_msg = req.flash('error_msg')
    res.locals.error = req.flash('error')
    res.locals.t_success_msg = req.flash('t_success_msg')
    res.locals.t_error_msg = req.flash('t_error_msg')
    res.locals.s_success_msg = req.flash('s_success_msg')
    res.locals.s_error_msg = req.flash('s_error_msg')
    next()
})

// Routes
app.use('/', require('./routes/index'))
app.use('/parents', require('./routes/parentsRouter'))
app.use('/students', require('./routes/studentsRouter'))
app.use('/teachers', require('./routes/teachersRouter'))
app.use('/admin', require('./routes/adminRouter'))


app.listen(process.env.PORT || 3000)