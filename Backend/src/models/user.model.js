import mongoose, { Schema, Types } from "mongoose";
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken";

const userSchema = new Schema(
    {
        email: {
            type: String,
            required: true,
            unique: true,
            lowercase: true
        },
        password: {
            type: String,
            required: [true, "password is required"]
        },
        fullName: {
            type :  String,
            required: true,
        },
        phoneNumber: {
            type: Number,
            unique: true,
            required: true,
        },
        country: {
            type: String
        },
        address: [
            {
                type: mongoose.Schema.Types.ObjectId,
                ref: ""
            },
        ],
        refreshToken :{
            type: String
        },
        Orders: [
            {
                type: mongoose.Schema.Types.ObjectId,
                ref: ""
            }
        ]
    }
)

userSchema.pre("save", async function (next) {
    if (!this.isModified("password")) return next()
    this.password = await bcrypt.hash(this.password, 10)
    next()
})

userSchema.method.isPasswordCorrect = async function (password) {
    return await bcrypt.compare(password, this.password)
}

userSchema.method.generateAccessToken = function () {
    return jwt.sign(
        {
            _id: this._id,
            email: this.email,
            fullName: this.fullName,
            password: this.password
        },
        process.env.ACCESS_TOKEN_SECRET_USER,
        {
            expiresIn: process.env.ACCESS_TOKEN_EXPIRY
        }
    )
}

userSchema.method.generateRefreshToken = function () {
    return jwt.sign(
        {
            _id: this._id
        },
        process.env.REFRESH_TOKEN_SECRATE_USER,
        {
            expiresIn: process.env.REFRESH_TOKEN_EXPIRY
        }
    )
}

export const User = mongoose.model("User", userSchema)