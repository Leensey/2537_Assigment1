function requireAuth(req, res, next) {
    if (!req.session.authenticated) {
        return res.redirect("/login");
    }
    next();
};

module.exports = requireAuth;