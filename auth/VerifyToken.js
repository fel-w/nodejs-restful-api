var jwt = require("jsonwebtoken");

var verifyToken = (req, res, next) => {
  var token = req.headers["x-access-token"];
  if (!token)
    return res.status(500).send({ auth: false, message: "No token provided" });
  jwt.verify(token, process.env.SECRET, (err, decoded) => {
    if (err)
      return res
        .status(500)
        .send({ auth: false, message: "Failed to authenticate token" });
    // if everything good, save to request for use in other routes
    req.userId = decoded.id;
    next();
  });
};

module.exports = verifyToken