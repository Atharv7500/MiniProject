const express = require("express");
const router = express.Router();

// 🔴 Phase 1: Hacker Mode (Vulnerable)

// LOGIN
router.get("/login", (req, res) => {
  res.render("hacker/login", { error: null });
});

router.post("/login", (req, res) => {
  const { username, password } = req.body;
  const users = req.app.locals.users;

  if (users[username] && users[username].password === password) {
    // VULNERABLE: Setting role in a cleartext cookie trusting user input later
    res.cookie("username", username);
    res.cookie("role", users[username].role); 

    res.redirect("/hacker/dashboard");
  } else {
    res.render("hacker/login", { error: "Invalid login credentials!" });
  }
});

router.get("/logout", (req, res) => {
  res.clearCookie("username");
  res.clearCookie("role");
  res.redirect("/hacker/login");
});

// DASHBOARD
router.get("/dashboard", (req, res) => {
  if (!req.cookies.username) return res.redirect("/hacker/login");
  
  res.render("hacker/dashboard", {
    username: req.cookies.username,
    role: req.cookies.role
  });
});

// HIDDEN ADMIN PANEL
router.get("/admin_4521", (req, res) => {
  // VULNERABLE: Direct object reference check against cookie instead of server-verified session
  if (req.cookies.role === "admin") { 
    res.render("hacker/admin", { users: req.app.locals.users });
  } else {
    // Return to dashboard but showing access denied
    res.render("hacker/dashboard", { 
      username: req.cookies.username,
      role: req.cookies.role,
      error: "Access denied. Admin role required."
    });
  }
});

// IDOR PROFILE
router.get("/profile", (req, res) => {
  if (!req.cookies.username) return res.redirect("/hacker/login");
  
  const id = req.query.id;
  const users = req.app.locals.users;

  // VULNERABLE: Blindly serving user data based on query parameter
  for (let u in users) {
    if (users[u].id == id) {
      return res.render("hacker/profile", { user: u, data: users[u] });
    }
  }
  
  res.render("hacker/profile", { user: null, data: null, error: "User not found" });
});

module.exports = router;
