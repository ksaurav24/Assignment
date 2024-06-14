const express = require("express");
const app = express();
const port = 3000;
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const dotenv = require("dotenv");
dotenv.config();

const mysql = require("mysql2");

// For running in node environment
if (typeof localStorage === "undefined" || localStorage === null) {
  var LocalStorage = require("node-localstorage").LocalStorage;
  localStorage = new LocalStorage("./scratch");
}

// Connection to database
// Database details are stored in .env file
const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Middlewares
const validateInput = (req, res, next) => {
  const { email, username, password } = req.body;
  if (!email || !username || !password) {
    res.status(400).send("All input is required");
  }
  next();
};

const authenticateJWT = (req, res, next) => {
  const token = localStorage.getItem("token");
  if (!token) return res.status(401).send("Access Denied");

  try {
    const verified = jwt.verify(token, process.env.SECRET_KEY);
    req.user = verified;
    next();
  } catch (err) {
    res.status(400).send("Invalid Token");
  }

  next();
};

const checkDuplicateEmail = (req, res, next) => {
  const email = req.body.email;
  let q = "SELECT * FROM users WHERE email = ?";
  connection.query(q, [email], (err, result) => {
    if (err) {
      console.log(err);
    }
    if (result.length > 0) {
      res.status(400).send("User already exists");
    }
    next();
  });
};

// Routes
// Profile route to get user profile(Protected Route)

app.get("/profile", authenticateJWT, (req, res) => {
  const email = req.body.email;
  let q = "SELECT * FROM users WHERE email = ?"; // Query to get user details
  connection.query(q, [email], (err, result) => {
    if (err) {
      // Error handling
      console.log(err);
      res.status(400).json({
        message: "Error in fetching data",
        error: err.message,
      });
    }
    const email = result[0].email;
    const username = result[0].username;
    res.json({ email: email, username: username }); // Sending user details
  });
});

// Register route to register user

app.post("/register", validateInput, checkDuplicateEmail, async (req, res) => {
  const { username, email, password } = req.body;
  const hashedPassword = await bcrypt.hashSync(password, 10); // Hashing password

  let q = "INSERT INTO users (email, username, password) VALUES ?"; // Query to insert data
  let values = [[email, username, hashedPassword]];
  connection.query(q, [values], async (err, result) => {
    if (err) {
      // Error handling
      console.log(err);
      res.status(400).json({
        message: "error in inserting data",
        error: err.message,
      });
    }
    res.send("Registered Successfully"); // Sending response
  });
});

// Login route to login user
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  let q = "SELECT * FROM users WHERE email = ?"; // Query to get user details
  connection.query(q, [email], async (err, result) => {
    if (err) {
      // Error handling
      console.log(err);
      res.status(400).json({
        message: "error in fetching data",
        error: err.message,
      });
    }
    if (result.length > 0) {
      // If user exists
      const user = result[0];
      const isPasswordMatch = await bcrypt.compare(password, user.password); // Comparing password
      if (isPasswordMatch) {
        const token = jwt.sign({ email: user.email }, process.env.SECRET_KEY); // Creating token
        localStorage.setItem("token", token);
        res.send("Logged In Successfully");
      } else {
        res.send("Invalid Password");
      }
    } else {
      // If user does not exist
      res.send("User not found");
    }
  });
});

// Error handling middleware
app.use((req, res, err, next) => {
  res.status(404).send("404 Not Found");
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
