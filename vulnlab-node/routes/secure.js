const express = require("express");
const jwt = require("jsonwebtoken");
const router = express.express ? express.Router() : require('express').Router(); // Ensure router gets created

const JWT_SECRET = "super_secure_unhackable_secret_key_123!";

// 🟢 Phase 2: Secure Mode (Defense)

// Middleware to protect routes and securely extract data
const requireAuth = (req, res, next) => {
  const token = req.cookies.secureAuthToken;
  if (!token) {
    return res.redirect("/secure/login");
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // Contains id, username, role securely signed
    next();
  } catch (err) {
    res.clearCookie("secureAuthToken");
    return res.redirect("/secure/login");
  }
};

// LOGIN
router.get("/login", (req, res) => {
  res.render("secure/login", { error: null });
});

router.post("/login", (req, res) => {
  const { username, password } = req.body;
  const users = req.app.locals.users;

  if (users[username] && users[username].password === password) {
    // SECURE: Create a signed JWT instead of raw cookies
    const token = jwt.sign(
      { id: users[username].id, username: username, role: users[username].role }, 
      JWT_SECRET, 
      { expiresIn: '1h' }
    );
    
    // Cookie is signed and cannot be tampered with by the client
    res.cookie("secureAuthToken", token, { httpOnly: true, sameSite: 'strict' });
    res.redirect("/secure/dashboard");
  } else {
    res.render("secure/login", { error: "Invalid login credentials!" });
  }
});

router.get("/logout", (req, res) => {
  res.clearCookie("secureAuthToken");
  res.redirect("/secure/login");
});

// DASHBOARD
router.get("/dashboard", requireAuth, (req, res) => {
  res.render("secure/dashboard", {
    username: req.user.username,
    role: req.user.role,
    userId: req.user.id
  });
});

// PROTECTED ADMIN PANEL
router.get("/admin", requireAuth, (req, res) => {
  // SECURE: Role verification from the server-verified JWT payload
  if (req.user.role === "admin") { 
    res.render("secure/admin", { users: req.app.locals.users });
  } else {
    res.render("secure/dashboard", { 
      username: req.user.username,
      role: req.user.role,
      userId: req.user.id,
      error: "Access Denied: You securely do not hold the 'admin' role privileges."
    });
  }
});

// SECURE PROFILE 
router.get("/profile", requireAuth, (req, res) => {
  // SECURE: Ignore user input `id`, force mapping to the securely verified JWT `id`.
  // Eliminates IDOR attack surface completely.
  const secureId = req.user.id;
  const users = req.app.locals.users;

  for (let u in users) {
    if (users[u].id == secureId) {
      return res.render("secure/profile", { user: u, data: users[u] });
    }
  }
  
  res.render("secure/profile", { user: null, data: null, error: "System fault." });
});

module.exports = router;
