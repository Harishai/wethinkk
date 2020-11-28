const router = require('express').Router()
const Teachers = require('../models/teacherModel')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const sendMail = require('../middleware/sendMail')
const {google} = require('googleapis')
const {OAuth2} = google.auth
const fetch = require('node-fetch')
const client = new OAuth2(process.env.MAILING_SERVICE_CLIENT_ID)
const {CLIENT_URL} = process.env
const passport = require('passport')
const { ensureAuthenticated_t } = require('../middleware/teacher_auth')
const { authRole } = require('../middleware/role') 

router.get('/register', chectNotAuth_t, (req, res) => {
    res.render('app/index/teacherregister', {
        layout: 'layouts/index/indexlayout'
    })
})

router.post('/register', async (req, res) => {
    try {
        const {name, email, phone, password, cfpassword} = req.body
        
        let t_errors = []

        if (!name || !email || !phone || !password || !cfpassword){
            t_errors.push({msg: 'Please fill in all the details'})
        }

        if (password !== cfpassword){
            t_errors.push({msg: 'Password do not match'})
        }

        if (password.length < 6){
            t_errors.push({msg: 'Password is too short'})
        }

        if(!validateEmail(email)){
            t_errors.push({msg: "Invalid emails."})
        }

        if(!checkPassword(password)){
            t_errors.push({msg: "Password is too week."})
        }

        const user = await Teachers.findOne({email})
        
        if(user){
            t_errors.push({msg: "This email already exists."})
        }

        if (t_errors.length > 0){
            res.render('app/index/teacherregister', {
                t_errors,
                name,
                email,
                phone,
                password,
                cfpassword,
                layout: 'layouts/index/indexlayout'
            })
        } else {
            const passwordHash = await bcrypt.hash(password, 12)

            const newUser = {
                name, email, phone, password: passwordHash
            }

            const activation_token = createActivationToken(newUser)

            const url = `${CLIENT_URL}/teachers/activation/?token=${activation_token}`
            sendMail(email, url, "Verify your email address")

            req.flash('success_msg', "Please activate your email to start.")
            res.redirect('/teachers/login')
        }
        
    } catch (err) {
        return res.status(500).json({msg: err.message})
    }
})

router.get('/activation/', async (req, res) => {
    try {
        const activation_token = req.query.token

        let errors = []

        const user = jwt.verify(activation_token, process.env.ACTIVATION_TOKEN_SECRET)

        const {name, email, phone, password} = user

        const check = await Teachers.findOne({email})
        if(check){
            errors.push({msg:"This username already exists."})
        }

        const newUser = new Teachers({
            name, email, phone, password
        })

        await newUser.save()

        req.flash('success_msg', "Account Activated please login")
        res.redirect('/teachers/login')

    } catch (err) {
        return res.status(500).json({msg: err.message})
    }
})


router.get('/login', chectNotAuth_t, (req, res) => {
    res.render('app/index/teacherlogin', {
        layout: 'layouts/index/indexlayout'
    })
})

router.post('/login', async (req, res, next) => {
    passport.authenticate('local_teacher', {
        successRedirect: '/teachers/dashboard',
        failureRedirect: '/teachers/login',
        failureFlash: true
    })(req, res, next)
})


router.get('/dashboard', ensureAuthenticated_t, authRole("teacher"), async (req, res, next) => {
    const userID = req.user._id
    const user = await Teachers.findById(userID)
    if (!req.user.student){
        child = "Please add a child "
    } else {
        child = user.student
    }
    res.render('app/teacherdashboard/dashboard', {
        child,
        teacher_name: req.user.name,
        layout: 'layouts/teacherdashboard/dashboard',
    })
})


router.get('/logout', (req, res) => {
    req.logout()
    req.flash('t_success_msg', 'You are logged out')
    res.redirect('/')
})

function validateEmail(email) {
    const re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(email);
}

const createActivationToken = (payload) => {
    return jwt.sign(payload, process.env.ACTIVATION_TOKEN_SECRET, {expiresIn: '5m'})
}

function chectNotAuth_t(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect('/students/dashboard')
    }
    next()
}

function checkPassword(str) {
    var re = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$.!%*#?&])[A-Za-z\d@$.!%*#?&]{8,}$/;
    return re.test(str);
}

module.exports = router