import mongoose, { Schema } from "mongoose";
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"

const adminSchema = new Schema(
    {
        email: {
            type: String,
            require: true,
            unique: true,
            trim: true
        },
        password: {
            type: String,
            require: true,
            trim: true
        },
        name: {
            type: String,
            require: true,
            trim: true
        },
        adminId: {
            type: Number
        },
        role: {
            type: String,
            require: true,
            enum: ["ADMIN", "OWNER", "CREATOR", "DELIVERY"],
            default: "Admin"
        },
        curruntOrders: [
            {
                type: mongoose.Schema.Types.ObjectId,
                ref: "CurruntOrder"
            },
        ]
    }
)

adminSchema.pre("save", async function (next) {
    if (!this.isModified("password")) return next()
    this.password = bcrypt.hash(this.password, 10)
    next()
})

adminSchema.methods.isPasswordCorrect = async function (password) {
    return await bcrypt.compare(password, this.password)
}

adminSchema.methods.genrateAccessToken = function () {
    return jwt.sign(
        {
            _id: this._id,
            email: this.email,
            password: this.password,
            name: this.name
        },
        process.env.ACCESS_TOKEN_SECRET_ADMIN,
        {
            expiresIn: process.env.ACCESS_TOKEN_EXPIRY
        }
    )
}

adminSchema.methods.genrateRefreshToken = function () {
    return jwt.sign(
        {
            _id: this._id
        },
        process.env.REFRESH_TOKEN_SECRATE_ADMIN,
        {
            expiresIn: process.env.REFRESH_TOKEN_EXPIRY
        }
    )
}

export const Admin = new mongoose.model("Admin", adminSchema)