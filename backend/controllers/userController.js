const asyncHandler = require('express-async-handler')
const User = require('../models/userModel')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')


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

module.exports = {
  registerUser,
  loginUser,
  logoutUser,
  getUser,
  loginStatus,
  updateUser,
  changePassword
}
