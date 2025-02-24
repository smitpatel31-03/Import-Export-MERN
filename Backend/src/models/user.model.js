import mongoose, { Schema, Types } from "mongoose";
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken";

const userSchema = new Schema(
    {
        email: {
            Types: String,
            require: true,
            unique: true,
            lowercase: true
        },
        password: {
            type: String,
            require: [true, "password is required"]
        },
        fullName: {
            Types: String,
            require: true,
        },
        phoneNo: {
            type: Number,
            unique: true,
            required: true
        },
        country: {
            type: String
        },
        address: [
            {
                addressLine1: {
                    type: String,
                    require: true
                },
                addressLine2: {
                    type: String,
                    require: true
                },
                city: {
                    type: String,
                    require: true
                },
                postalcode: {
                    type: Number,
                    require: true
                },
                state: {
                    type: String,
                    require: true
                },
                country: {
                    type: String,
                    require: true
                },
                number: {
                    type: Number,
                    require: true
                },
            }
        ],
        Orders: [
            {
                type: mongoose.Schema.Types.ObjectId,
                ref: " "
            }
        ]
    }
)

userSchema.pre("save", async function (next) {
    if (!this.isModified("password")) return next()
    this.password = bcrypt.hash(this.password, 10)
    next()
})

userSchema.method.isPasswordCorrect = async function (password) {
    return await bcrypt.compare(password, this.password)
}

userSchema.mathod.genrateAccessToken = function () {
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

userSchema.mathod.genrateRefrashToken = function () {
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