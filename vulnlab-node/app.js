const express = require("express");
const cookieParser = require("cookie-parser");
const path = require("path");

const hackerRoutes = require("./routes/hacker");
const secureRoutes = require("./routes/secure");

const app = express();

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

// View Engine
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Game Lobby / Hub
app.get("/", (req, res) => {
  res.render("index");
});

// Phase Routes
app.use("/hacker", hackerRoutes);
app.use("/secure", secureRoutes);

// Shared Dummy DB for demonstration mapping
app.locals.users = {
  user: { password: "123", role: "user", id: 1 },
  admin: { password: "admin", role: "admin", id: 2 }
};

app.listen(3000, () => {
  console.log("VulnLab Game Running on http://localhost:3000");
});
