const express = require("express");
const bcrypt = require("bcrypt");
const adminModel = require("../model/adminModel");
const userModel = require("../model/userModel"); // Ensure userModel is imported
const adminRoute = new express.Router();

const findAndAuthenticate = async (model, email, password) => {
    const user = await model.findOne({ email });
    if (user && await bcrypt.compare(password, user.password)) {
        return user;
    }
    return null;
};

adminRoute.post("/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: "Email and password must be same" });
    }

    try {
        const admin = await findAndAuthenticate(adminModel, email, password);
        if (admin) {
            return res.status(200).json({
                message: "Login successful",
                userType: "admin",
                user: admin
            });
        }

        const user = await findAndAuthenticate(userModel, email, password);
        if (user) {
            return res.status(200).json({
                message: "Login successful",
                userType: "user",
                user
            });
        }

        res.status(401).json({ message: "Invalid email or password" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal server error" });
    }
});

module.exports = adminRoute;
