function requireAdmin(req, res, next) {
    if (!req.session.authenticated) return res.redirect("/login");
    if (req.session.user_type !== "admin") {
        return res.status(403).send("403 Forbidden - You are not authorized.");
    }
    next();
};

module.exports = requireAdmin;