module.exports = {
    ensureAuthenticated_a: function(req, res, next) {
        if(req.isAuthenticated()) {
            return next();
        }
        req.flash('error_msg', 'Please login')
        res.redirect('/admin/login')
    }
}

