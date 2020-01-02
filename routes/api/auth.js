const express = require("express");
const router = express.Router();
const auth = require("../../middleware/auth");
const jwt = require("jsonwebtoken");
const config = require("config");
const { check, validationResult } = require("express-validator");

const User = require("../../models/User");

// @route     GET api/auth
// @desc      Test route
// @access    Public
router.get("/", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    res.json(user);
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server Error");
  }
});

// @route     GET api/auth
// @desc      Authenticate user @ get token
// @access    Public
router.post(
  "/",
  // validate the input and report any errors before creating the user
  [
    check("email", "Please include a valid email").isEmail(),
    check("password", "Password is required").isLength({ min: 6 })
  ],
  async (req, res) => {
    const errors = validationResult(req);

    // if there are errors, send a 400 and error message back to front end
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password } = req.body;

    try {
      // see if the user exists
      let user = await User.findOne({ email });

      // if the user already exist in database, then return 400 and return error message
      if (user) {
        return res
          .status(400)
          .json({ errors: [{ msg: "User already exist" }] });
      }

      // Get users gravatar
      const avatar = gravatar.url(email, {
        // default size
        s: "200",
        // rating
        r: "pg",
        // default image
        d: "mm"
      });

      user = new User({
        name,
        email,
        avatar,
        password
      });

      // Encrypt password using bCrypt
      const salt = await bcrypt.genSalt(10);

      user.password = await bcrypt.hash(password, salt);

      await user.save();

      // Return jsonwebtoken to front end for user to log in right away after registering
      const payload = {
        user: {
          // get id from the newly created user by mongoose
          id: user.id
        }
      };

      jwt.sign(
        payload,
        config.get("jwtSecret"),
        { expiresIn: 360000 },
        // if there is error return error, if not return the token
        (err, token) => {
          if (err) {
            throw err;
          } else {
            res.json({ token });
          }
        }
      );
    } catch (err) {
      console.error(err.message);
      res.status(500).send("server error");
    }
  }
);

module.exports = router;
