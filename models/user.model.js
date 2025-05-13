const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String,
    user_type: {
        type: String,
        enum: ["admin", "user"],
        default: "user",
    },
});

module.exports = mongoose.model("User", userSchema);
