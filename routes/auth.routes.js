const {Router} = require('express');
const bcrypt = require('bcryptjs');
const config =  require('config');
const jwt = require('jsonwebtoken');
const {check, validationResult} = require('express-validator');
const User = require('../models/User');
const router = Router()

// /api/author/register - prethix to this route
router.post(
  '/register',
  [
    check('email', 'incorrect email').isEmail(),
    check('password', 'minimal length of password is 6 simbols ')
      .isLength({ min: 6 })
  ],
  async (req, res) => {
  try{
    const errors = validationResult(req)

    if (!errors.isEmpty()) {
      return res.status(400).json({
        errors: errors.array(),
        message: 'Incorrect registration data'
      })
    }

    const {email, password} = req.body

    const candidate= await User.findOne({ email })

    if (candidate) {
      return res.status(400).json({ message: 'this user is already exist' })
    }

    const hashedPassword = await bcrypt.hash(password, 12)
    const user = new User({ email, password: hashedPassword})

    await user.save()

    res.status(201).json({ message: 'New user is created'})

  } catch (e) {
    res.status(500).json({ message: 'something went wrong, try again'})
  }
})

// /api/author/login - prethix to this route
router.post(
  '/login',
  [
    check('email', 'Input a correct email').normalizeEmail().isEmail(),
    check('password', 'Input password').exists()
  ],
  async (req, res) => {
  try{
    const errors = validationResult(req)

    if (!errors.isEmpty()) {
      return res.status(400).json({
        errors: errors.array(),
        message: 'Incorrect entry data'
      })
    }

    const {email, password} = req.body

    const user = await User.findOne({ email })

    if (!user) {
      return res.status(400).json({ message: 'This user is unknown' })
    }

    const isMatch = await bcrypt.compare(password, user.password)

    if (!isMatch) {
      return res.status(400).json({ message: 'Incorrect password, try again'})
    }

    const token = jwt.sign(
      { userId: user.id },
      config.get('jwtSecret'),
      { expiresIn: '1h'}
    )

    res.json({ token, userId: user.id })

  } catch (e) {
    res.status(500).json({ message: 'something went wrong, try again'})
  }
})

module.exports = router
