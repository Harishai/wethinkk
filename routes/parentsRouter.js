const router = require('express').Router()
const Parents = require('../models/parentsModel')
const Students = require('../models/studentsModel')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const sendMail = require('../middleware/sendMail')
const {google} = require('googleapis')
const {OAuth2} = google.auth
const fetch = require('node-fetch')
const client = new OAuth2(process.env.MAILING_SERVICE_CLIENT_ID)
const {CLIENT_URL} = process.env
const passport = require('passport')
const { ensureAuthenticated } = require('../middleware/auth')
const { authRole } = require('../middleware/role') 

router.get('/register', chectNotAuth_p, (req, res) => {
    res.render('app/index/parentregister', {
        layout: 'layouts/index/indexlayout'
    })
})

router.post('/register', async (req, res) => {
    try {
        const {name, email, phone, password, cfpassword} = req.body
        
        let errors = []

        if (!name || !email || !phone || !password || !cfpassword){
            errors.push({msg: 'Please fill in all the details'})
        }

        if (password !== cfpassword){
            errors.push({msg: 'Password do not match'})
        }

        if (password.length < 6){
            errors.push({msg: 'Password is too short'})
        }

        if(!validateEmail(email)){
            errors.push({msg: "Invalid emails."})
        }

        if(!checkPassword(password)){
            errors.push({msg: "Password is too week."})
        }

        const user = await Parents.findOne({email})
        
        if(user){
            errors.push({msg: "This email already exists."})
        }

        if (errors.length > 0){
            res.render('app/index/parentregister', {
                errors,
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

            const url = `${CLIENT_URL}/parents/activation/?token=${activation_token}`
            sendMail(email, url, "Verify your email address")

            req.flash('success_msg', "Please activate your email to start.")
            res.redirect('/parents/login')
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

        const check = await Parents.findOne({email})
        if(check){
            errors.push({msg:"This username already exists."})
        }

        const newUser = new Parents({
            name, email, phone, password
        })

        await newUser.save()

        req.flash('success_msg', "Account Activated please login")
        res.redirect('/parents/login')

    } catch (err) {
        return res.status(500).json({msg: err.message})
    }
})

router.get('/login', chectNotAuth_p, (req, res) => {
    res.render('app/index/parentlogin', {
        layout: 'layouts/index/indexlayout'
    })
})

router.post('/login', async (req, res, next) => {
    passport.authenticate('local_parents', {
        successRedirect: '/parents/dashboard',
        failureRedirect: '/parents/login',
        failureFlash: true
    })(req, res, next)
})

router.get('/dashboard', ensureAuthenticated, authRole("parent"), async (req, res, next) => {
    const userID = req.user._id
    const user = await Parents.findById(userID).populate('student')
    if (!req.user.student){
        child = "Please add a child "
    } else {
        child = user.student
    }
    res.render('app/parentdashboard/dashboard', {
        child,
        parent_name: req.user.name,
        layout: 'layouts/parentdashoard/dashboard',
        colors : ['bg-indigo-200', 'bg-pink-200', 'bg-purple-200', 'bg-blue-200', 'bg-green-200', 'bg-red-200', 'bg-yellow-200']
    })
})

router.get('/dashboard/addchild', ensureAuthenticated, (req, res) => {
    res.render('app/parentdashboard/addchild', {
        parent_name: req.user.name,
        layout: 'layouts/parentdashoard/dashboard'
    })
})

router.post('/dashboard/addchild', async (req, res, next) => {
    const userID = req.user._id
    const user = await Parents.findById(userID)
    
    const { name,username,bday,grade,password,cfpassword } = req.body
    let derrors = []

    if (!name || !username || !bday || !grade ||!password || !cfpassword){
        derrors.push({msg: 'Please fill in all the details'})
    }
    if (password !== cfpassword){
        derrors.push({msg: 'Password do not match'})
    }
    if (password.length < 6){
        derrors.push({msg: 'Password is too short'})
    }
    if(!checkPassword(password)){
        derrors.push({msg: "Password is too week."})
    }

    if (derrors.length > 0){
        res.render('app/parentdashboard/addchild', {
            derrors,
            parent_name: req.user.name,
            name,
            username,
            bday,
            grade,
            password,
            cfpassword,
            layout: 'layouts/parentdashoard/dashboard'

        })
    } else {
        Students.findOne({username: username}).then(student => {
            if(student){
                derrors.push({msg: 'Username is already registered'})
                res.render('app/parentdashboard/addchild', {
                    derrors,
                    parent_name: req.user.name,
                    name,
                    username,
                    bday,
                    grade,
                    password,
                    cfpassword,
                    layout: 'layouts/parentdashoard/dashboard'
                })
            } else {
                const newStudent = new Students({
                    name,
                    username,
                    bday,
                    grade,
                    password,
                })
                bcrypt.genSalt(10, (err, salt) => bcrypt.hash(newStudent.password, salt, (err, hash) => {
                    if(err) throw err;
                    newStudent.password = hash;
                    newStudent.parent = user
                    newStudent.save().then(student => {
                        user.student.push(newStudent)
                        user.save()
                        req.flash('success_msg', 'Child add successfully')
                        res.redirect('/parents/dashboard')
                    }).catch(err => console.log(err))
                }))
            }
        })
    }

})

router.get('/logout', (req, res) => {
    req.logout()
    req.flash('success_msg', 'You are logged out')
    res.redirect('/')
})

function validateEmail(email) {
    const re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(email);
}

function checkPassword(str) {
    var re = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$.!%*#?&])[A-Za-z\d@$.!%*#?&]{8,}$/;
    return re.test(str);
}


const createActivationToken = (payload) => {
    return jwt.sign(payload, process.env.ACTIVATION_TOKEN_SECRET, {expiresIn: '5m'})
}

function chectNotAuth_p(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect('/parents/dashboard')
    }
    next()
}

module.exports = router