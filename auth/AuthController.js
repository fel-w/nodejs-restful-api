var express = require("express");
var router = express.Router();
var bodyParser = require("body-parser");
router.use(bodyParser.urlencoded({ extended: false }));
router.use(bodyParser.json());

var User = require("../user/User");
var jwt = require("jsonwebtoken");
var bcrypt = require("bcryptjs");

router.post("/register", (req, res) => {
  var hashedPassword = bcrypt.hashSync(req.body.password, 8);

  // Create user with provided name, email and hashed password
  User.create(
    {
      name: req.body.name,
      email: req.body.email,
      password: hashedPassword,
    },
    (err, user) => {
      if (err) {
        return res.status(500).send("There was a problem registering the user");
      }

      // create a token using secret key and payload of object with user id
      var token = jwt.sign({ id: user._id }, process.env.SECRET, {
        expiresIn: 86400, // expires in 24 hrs
      });

      res.status(200).send({ auth: true, token: token });
    }
  );
});

router.get("/me", (req, res) => {
  // token is expected along with in request header
  var token = req.headers["x-access-token"];
  if (!token)
    return res
      .status(401)
      .send({ auth: false, message: "Not token provided." });

  // Decode token to view original payload
  jwt.verify(token, process.env.SECRET, (err, decoded) => {
    if (err)
      return res
        .status(500)
        .send({ auth: false, message: "Failed to authenticate token." });
    
    // Look up user with decoded token
    User.findById(decoded.id, { password: 0 }, (err, user) => {
      if (err) return res.status(500).send("There was a problem finding the user");
      if (!user) return res.status(404).send("There was no user found");

      res.status(200).send(user);
    });
  });
});

module.exports = router;
