const asyncHandler = require('express-async-handler')
const User = require('../models/userModel')
const Token = require('../models/tokenModel')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const crypto = require('crypto')
const sendEmail = require('../utils/sendEmail')


const generateToken = (id) => {
  return jwt.sign({id}, process.env.JWT_SECRET, {expiresIn: "1d"})
}


// REGISTER USER
const registerUser = asyncHandler(async (req, res) => {
  const {name, email, password} = req.body

  // Validation
  if(!name || !email || !password){
    res.status(400)
    throw new Error("Please fill in all required fields")
  }
  if (password.length < 6){
    res.status(400)
    throw new Error("Password must be up to 6 characters")
  }
  // Check if user email already exists
  const userExists = await User.findOne({email})
  if(userExists){
    res.status(400)
    throw new Error("Email has already been registered")
  }

  // Create new User
  const user = await User.create({
    name,
    email,
    password
  })

  // Generate Token 
  const token = generateToken(user._id)

  // Send HTTP-only cookie
  res.cookie("token", token, {
    path: "/",
    httpOnly: true,
    expires: new Date(Date.now() + 1000 * 86400), // 1 day
    sameSite: "none",
    secure: true
  })

  if(user) {
    const {_id, name, email, photo, phone, bio} = user
    res.status(201).json({
      _id,
      name,
      email,
      photo,
      phone,
      bio,
      token 
    })
  } else {
    res.status(400)
    throw new Error("Invalid user data")
  }

}) 


// LOGIN USER
const loginUser = asyncHandler(async (req, res) => {
  
  const { email, password } = req.body

  // Validate Request 
  if(!email || !password){
    res.status(400)
    throw new Error("Please add email and password")
  }

  // Check if user exists
  const user = await User.findOne({email})

  if(!user){
    res.status(400)
    throw new Error("User not found, please signup")
  }

  // User exists, check if password is correct
  const passwordIsCorrect = await bcrypt.compare(password, user.password)

  if(user && passwordIsCorrect){
  // Generate Token 
  const token = generateToken(user._id)

  // Send HTTP-only cookie
  res.cookie("token", token, {
    path: "/",
    httpOnly: true,
    expires: new Date(Date.now() + 1000 * 86400), // 1 day
    sameSite: "none",
    secure: true
  })

    const {_id, name, email, photo, phone, bio} = user
    res.status(200).json({
      _id,
      name,
      email,
      photo,
      phone,
      bio,
    })
  } else {
    res.status(400);
    throw new Error("Invalid email or password")
  }
})


// LOGOUT USER
const logoutUser = asyncHandler(async(req, res) => {
  res.cookie("token", "", {
    path: "/",
    httpOnly: true,
    expires: new Date(0),
    sameSite: "none",
    secure: true
  })
  // res.cookie("token")
  return res.status(200).json({ message: "Succesfully Logged Out" })
})


// GET USER PROFILE
const getUser = asyncHandler(async(req, res) => {
  // const user = await User.findById(req.user._id)
  const user = req.user

  if(user) {
    const {_id, name, email, photo, phone, bio} = user
    res.status(200).json({
      _id,
      name,
      email,
      photo,
      phone,
      bio,
    })
  } else {
    res.status(400)
    throw new Error("User not found")
  }
})


// GET LOGIN STATUS
const loginStatus = asyncHandler(async(req, res) => {
  const token = req.cookies.token
  console.log(token)
  if(!token) {
    return res.json(false)
  }

  const verified = jwt.verify(token, process.env.JWT_SECRET)
  console.log(verified)
  if(verified) {
   return res.json(true)
  }
  res.json(false)
})


// UPDATE USER
const updateUser = asyncHandler(async (req, res)=> {
  const user = await User.findById(req.user._id)

  if(user) {
    const { name, email, photo, phone, bio} = user
    user.email = email,
    user.name = req.body.name || name
    user.phone = req.body.phone || phone
    user.photo = req.body.photo || photo
    user.bio = req.body.bio || bio

    const updatedUser = await user.save()
    res.status(200).json({
      _id: updatedUser._id,         
      name: updatedUser.name,
      email: updatedUser.email,
      phone: updatedUser.phone, 
      bio: updatedUser.bio,
      photo: updatedUser.photo
    })
  } else {
    res.status(404)
    throw new Error("User not found")
  }
})


// CHANGE PASSWORD 
const changePassword = asyncHandler(async(req, res) => {
  const user = await User.findById(req.user._id)
  const { oldPassword, password } = req.body
  if(!user) {
    res.status(400)
    throw new Error("User not found, please signup")
  }
  // Validate 
  if(!oldPassword || !password) {
    res.status(400)
    throw new Error("Please add old and new password")
  }

  // Check if old password matches password in the DB
  const passwordIsCorrect = await bcrypt.compare(oldPassword, user.password)

  // Save new password 
  if(user && passwordIsCorrect){
    user.password = password
    await user.save()
    res.status(200).send("Password change succesful")
  } else {
    res.status(400)
    throw new Error("Old password is incorrect")
  }

})


// FORGOT PASSWORD
const forgotPassword = asyncHandler(async (req, res) => {

  const {email} = req.body
  const user = await User.findOne({email})

  if(!user){
    res.status(404)
    throw new Error("User does not exists")
  }

  // Delete token if its exits in DB
  let token = await Token.findOne({userId: user._id})

  if(token) {
    await token.deleteOne()
  }

  // Create reset Token 
  let resetToken = crypto.randomBytes(32).toString("hex") + user._id
  console.log(resetToken)

  // Hash token before saving to DB
  const hashedToken = crypto.createHash("sha256").update(resetToken).digest("hex")

  // Save token to DB
  await new Token({
    userId: user._id,
    token: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 30 * (60 * 1000), // 30 minutes after
  }).save() 

  // Construct reset Url
  const resetUrl = `${process.env.FRONTEND_URL}/resetpassword/${resetToken}`

  // Reset email 
  const message = `
    <h2>Hello ${user.name}</h2>
    <p>Please use the url below to reset your password</p>
    <p>This reset link is valid for only 30 minutes</p>
    <a href=${resetUrl} clicktracking=off>Reset Password</a>
    <p>Regards...</p>
    <p>Fabi Team</p>
  `
  const subject = "Password reset request"
  const send_to = user.email
  const sent_from = process.env.EMAIL_USER

  try {
    await sendEmail(subject, message, send_to, sent_from)
    res.status(200).json( {success: true, message: "Reset email send"} )
  }catch(error) {
    res.status(500)
    throw new Error("Email not sent, please try again")
  }

})

// RESET PASSWORD 
const resetPassword = asyncHandler(async (req, res) => {

  const { password } = req.body
  const { resetToken } = req.params
  
  // Hash token, then compare with the Token in DB
  const hashedToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex")
  
  // Find Token in DB
  const userToken = await Token.findOne({
    token: hashedToken,
    expiresAt: {$gt: Date.now()}
  })

  if(!userToken) {
    res.status(404)
    throw new Error("Invalid or expired token")
  }

  // Find user 
  const user = await User.findOne({_id: userToken.userId})

  user.password = password
  await user.save()
  res.status(200).json({ 
    message: "Password reset successfull, pleas login"
   })


})

module.exports = {
  registerUser,
  loginUser,
  logoutUser,
  getUser,
  loginStatus,
  updateUser,
  changePassword,
  forgotPassword,
  resetPassword
}
