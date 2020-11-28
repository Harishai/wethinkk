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
const { ensureAuthenticated_s } = require('../middleware/student_auth')
const { authRole } = require('../middleware/role') 


router.get('/login',chectNotAuth_s, (req, res) => {
    res.render('app/index/studentlogin', {
        layout: 'layouts/index/indexlayout'
    })
})

router.post('/login', async (req, res, next) => {
    passport.authenticate('local_student', {
        successRedirect: '/students/dashboard',
        failureRedirect: '/students/login',
        failureFlash: true
    })(req, res, next)
})


router.get('/dashboard', ensureAuthenticated_s, authRole("student"), async (req, res, next) => {
    const userID = req.user._id
    const user = await Students.findById(userID)
    res.render('app/studentdashboard/dashboard', {
        student_name: req.user.name,
        layout: 'layouts/studentdashboard/dashboard',
    })
})


router.get('/logout', (req, res) => {
    req.logout()
    req.flash('s_success_msg', 'You are logged out')
    res.redirect('/')
})

function chectNotAuth_s(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect('/students/dashboard')
    }
    next()
}


module.exports = router