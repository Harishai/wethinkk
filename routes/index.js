const express = require('express')
const router = express.Router()

router.get('/', (req, res) => {
    res.render('app/index/index', {
        layout: 'layouts/index/indexlayout'
    })
})

router.get('/curriculum', (req, res) => {
    res.render('app/index/curriculum', {
        layout: 'layouts/index/indexlayout'
    })
})


router.get('/choose', (req, res) => {
    res.render('app/index/choose', {
        layout: 'layouts/index/indexlayout'
    })
})


module.exports = router