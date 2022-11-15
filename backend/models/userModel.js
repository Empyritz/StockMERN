const mongoose = require('mongoose')
const bcrypt = require('bcryptjs')

const userSchema = mongoose.Schema({
  name: {
    type: String,
    required: [true, "Please add a name"]
  },
  email: {
    type: String,
    required: [true, "Please enter an email"],
    unique: true,
    trim: true,
    match: [
      /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/, 
      "Pleae enter a valid email"
    ]
  },
  password: {
    type: String,
    required: [true, "Please add a password"],
    minLength: [6, "Password must be up to six characters"],
    // maxLength: [23, "Passeord must not be more than 23 characters"]
  },
  photo: {
    type: String,
    required: [true, "Please enter a profile photo"],
    default: "https://i.ibb.co/4pDNDk1/avatar.png"
  },
  phone: {
    type: String,
    default: "+52"
  },
  bio: {
    type: String,
    maxLength: [250, "Bio must not be more tha 250 characters"],
    default: "bio"
  }
}, {
  timestamps: true,
})

// Encrypt password before saving to DB
userSchema.pre("save", async function(next) {
  if(!this.isModified("password")) {
    return next()
  }

  // Hash password
  const salt = await bcrypt.genSalt(10)
  const hashedPassword = await bcrypt.hash(this.password, salt)
  this.password = hashedPassword
  next()
})

const User = mongoose.model("User", userSchema)
module.exports = User