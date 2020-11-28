const router = require('express').Router()
const Parents = require('../models/parentsModel')
const Students = require('../models/studentsModel')
const Teachers = require('../models/teacherModel')
const Admin = require('../models/adminsModel')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const sendMail = require('../middleware/sendMail')
const {google} = require('googleapis')
const {OAuth2} = google.auth
const fetch = require('node-fetch')
const client = new OAuth2(process.env.MAILING_SERVICE_CLIENT_ID)
const {CLIENT_URL} = process.env
const passport = require('passport')
const { ensureAuthenticated_a } = require('../middleware/admin_auth')
const { authRole } = require('../middleware/role') 

router.get('/register', chectNotAuth_a, (req, res) => {
    res.render('app/index/adminregister', {
        layout: 'layouts/index/indexlayout'
    })
})

router.post('/register', async (req, res) => {
    try {
        const {name, email, password, cfpassword} = req.body
        
        let errors = []

        if (!name || !email || !password || !cfpassword){
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

        const user = await Admin.findOne({email})
        
        if(user){
            errors.push({msg: "This email already exists."})
        }

        if (errors.length > 0){
            res.render('app/index/adminregister', {
                errors,
                name,
                email,
                password,
                cfpassword,
                layout: 'layouts/index/indexlayout'
            })
        } else {
            const passwordHash = await bcrypt.hash(password, 12)
            const newUser = {
                name, email, password: passwordHash
            }

            const activation_token = createActivationToken(newUser)

            const url = `${CLIENT_URL}/admin/activation/?token=${activation_token}`
            sendMail(email, url, "Verify your email address")

            req.flash('success_msg', "Please activate your email to start.")
            res.redirect('/admin/login')
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

        const check = await Admin.findOne({email})
        if(check){
            errors.push({msg:"This username already exists."})
        }

        const newUser = new Admin({
            name, email, phone, password
        })

        await newUser.save()

        req.flash('success_msg', "Account Activated please login")
        res.redirect('/admin/login')

    } catch (err) {
        return res.status(500).json({msg: err.message})
    }
})



router.get('/login', chectNotAuth_a, (req, res) => {
    res.render('app/index/adminlogin', {
        layout: 'layouts/index/indexlayout'
    })
})

router.post('/login', async (req, res, next) => {
    passport.authenticate('local_admin', {
        successRedirect: '/admin/dashboard',
        failureRedirect: '/admin/login',
        failureFlash: true
    })(req, res, next)
})

router.get('/dashboard', ensureAuthenticated_a, authRole("admin"), async (req, res, next) => {
    const userID = req.user._id
    const user = await Admin.findById(userID)

    const parents = await Parents.find({})
    const students = await Students.find({})
    const teachers = await Teachers.find({})

    res.render('app/admindashboard/dashboard', {
        admin_name: req.user.name,
        parentslist: parents.length,
        studentslist: students.length,
        teacherslist: teachers.length,
        layout: 'layouts/admindashboard/dashboard',
        colors : ['bg-indigo-200', 'bg-pink-200', 'bg-purple-200', 'bg-blue-200', 'bg-green-200', 'bg-red-200', 'bg-yellow-200']
    })
})

router.get('/dashboard/parents', ensureAuthenticated_a, authRole("admin"), async (req, res, next) => {
    const userID = req.user._id
    const user = await Admin.findById(userID)
    const parents = await Parents.find({}).populate('student')

    res.render('app/admindashboard/parentsdetails', {
        admin_name: req.user.name,
        parents_details: parents,
        layout: 'layouts/admindashboard/dashboard'
    })
})

router.get('/dashboard/students', ensureAuthenticated_a, authRole("admin"), async (req, res, next) => {
    const userID = req.user._id
    const user = await Admin.findById(userID)
    const students = await Students.find({}).populate('parent')

    res.render('app/admindashboard/studentsdetails', {
        admin_name: req.user.name,
        students_details: students,
        layout: 'layouts/admindashboard/dashboard'
    })
})

router.get('/dashboard/teachers', ensureAuthenticated_a, authRole("admin"), async (req, res, next) => {
    const userID = req.user._id
    const user = await Admin.findById(userID)
    const teachers = await Teachers.find({})

    res.render('app/admindashboard/teachersdetails', {
        admin_name: req.user.name,
        teachers_details: teachers,
        layout: 'layouts/admindashboard/dashboard'
    })
})

router.get('/dashboard/course', ensureAuthenticated_a, authRole("admin"), async (req, res, next) => {
    const userID = req.user._id
    const user = await Admin.findById(userID)
    res.render('app/admindashboard/courses', {
        admin_name: req.user.name,
        layout: 'layouts/admindashboard/dashboard'
    })
})

router.get('/dashboard/addcourse', ensureAuthenticated_a, authRole("admin"), async (req, res, next) => {
    const userID = req.user._id
    const user = await Admin.findById(userID)
    res.render('app/admindashboard/addcourse', {
        admin_name: req.user.name,
        layout: 'layouts/admindashboard/dashboard'
    })
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

function chectNotAuth_a(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect('/admin/dashboard')
    }
    next()
}

module.exports = router