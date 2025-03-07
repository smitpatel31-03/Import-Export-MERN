import { asyncHandler } from "../utils/asyncHandler.js"
import { ApiError } from "../utils/ApiError.js"
import { ApiResponse } from "../utils/ApiResponse.js"
import { User } from "../models/user.model.js"
import { UserAddress } from "../models/usersAddress.model.js"
import { Order } from "../models/order.model.js"
import { CurruntOrder } from "../models/curruntOrders.model.js"
import jwt from "jsonwebtoken"
import { log } from "console"

const generateAccessAndRefreshToken = async (userId) => {
    try {
        //find user
        //genrate access and refresh token
        //update the database
        //save the database
        //return access and refresh token

        //find user
        const user = await User.findById(userId)
        console.log(user);


        //genrate access and refresh token
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()
        console.log(" accessToken : ", accessToken);
        console.log(" refreshToken : ", refreshToken);


        //update the database
        user.refreshToken = refreshToken
        await user.save({ validateBeforeSave: false })

        return { accessToken, refreshToken }

    } catch (error) {
        throw new ApiError(500, "Something Went Wrong While Genrating Refresh And Access Token")
    }
}

const registerUser = asyncHandler(async (req, res) => {
    //import user details
    //validate user details
    //check email and phone number is available or not
    //add user to database
    // remove password and refresh token field from response
    //check user is created or not
    //response user


    //import user details
    const { email, password, fullName, phoneNumber, country } = req.body


    //validate user details
    if ([email, password, fullName, phoneNumber, country].some((field) => field?.trim() === "")) {
        throw new ApiError(400, "All Fields Are Compulsory Or Required")
    }


    //check email and phone number is available or not
    const existedUser = await User.findOne({
        $or: [{ email }, { phoneNumber }]
    })

    if (existedUser) {
        throw new ApiError(409, "Email And Phonenumber Are Already Exist")
    }


    //add user to database
    const user = await User.create({
        email,
        password,
        fullName,
        phoneNumber,
        country
    })


    // remove password and refresh token field from response
    const createdUser = await User.findById(user._id).select("-password -refreshToken")


    //check user is created or not
    if (!createdUser) {
        throw new ApiError(500, "Something Went Wrong While Registering User");
    }


    //response user
    return res.status(201).json(
        new ApiResponse(200, createdUser, "User registerd successfully")
    )


})

const loginUser = asyncHandler(async (req, res) => {
    //get user details
    //validate user details
    //find user
    //validate password
    //refresh token and access token
    //response send cookie

    //get user details
    const { email, password, phoneNumber } = req.body


    //validate user details
    if (!email && !phoneNumber) {
        throw new ApiError(401, "Please Enter User Details")
    }

    //find user
    const user = await User.findOne({
        $or: [{ email }, { phoneNumber }]
    })

    if (!user) {
        throw new ApiError(404, "User Not Found")
    }
    //validate password
    const isPasswordValidate = await user.isPasswordCorrect(password)

    if (!isPasswordValidate) {
        throw new ApiError(401, "Invalid Crendentials")
    }



    //refresh token and access token
    const { accessToken, refreshToken } = await generateAccessAndRefreshToken(user._id)
    console.log("accessToken1 : ", accessToken);
    console.log("refreshToken1 : ", refreshToken);


    const logedInUser = await User.findById(user._id).select("-password -refreshToken")

    const options = {
        httpOnly: true,
        secured: true
    }

    //response send cookie
    return res
        .status(201)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options)
        .json(
            new ApiResponse(200, {
                user: logedInUser, accessToken, refreshToken
            },
                "User Loggend In Successfully"
            )
        )
})

const logoutUser = asyncHandler(async (req, res) => {
    //find user
    //remove refresh token
    //remove cookie

    //find user
    //remove refresh token
    console.log("req.user._id : ", req.user._id);
    console.log("req.user : ", req.user);

    await User.findByIdAndUpdate(
        req.user.id,
        {
            $set: {
                refreshToken: undefined
            }
        }, {
        new: true
    }
    )

    const options = {
        httpOnly: true,
        secured: true
    }

    res
        .status(200)
        .cookie("accessToken", options)
        .cookie("refreshToken", options)
        .json(new ApiResponse(200, {}, "User Loogedout Successfully"))
})

const UsersRefreshAccessToken = asyncHandler(async (req, res) => {
    //get refresh token
    //decode refresh token
    //find user
    //validate refresh token
    //set refresh and access token
    //response cookie


    //get refresh token
    const incomingRefreshToken = req.cookie.refreshToken || req.body.refreshToken

    if (!incomingRefreshToken) {
        throw new ApiError(401, "Unauthorized Request")
    }

    try {
        //decode refresh token
        const decodeToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRATE_USER)

        //find user
        const user = await User.findById(decodeToken?._id)

        if (!user) {
            throw new ApiError(401, "Invalid User Refresh Token")
        }

        //validate refresh token
        if (incomingRefreshToken !== user?.refreshToken) {
            throw new ApiError(401, "User Refresh Token Is Expired Or Used")
        }

        const options = {
            httpOnly: true,
            secured: true
        }

        //set refresh and access token
        const { accessToken, refreshToken } = await generateAccessAndRefreshToken(user._id)

        //response cookie
        return res.status(200)
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", refreshToken, options)
            .json(
                new ApiResponse(200, {
                    user: { accessToken, refreshToken }
                }),
                "User's Access Token Refreshed Successfully"
            )

    } catch (error) {
        throw new ApiError(401, "Invalid User Refresh Token")
    }
})

const addUserAddress = asyncHandler(async (req, res) => {
    //get address details
    //check all adddress fields
    //import users
    //save the data in database
    //response user

    //get address details
    const { name, addressLine1, addressLine2, city, postalCode, state, country, mobileNumber } = req.body

    if ([name, addressLine1, addressLine2, city, postalCode, state, country, mobileNumber].some((fild) => fild?.trim === "")) {
        throw new ApiError(400, "All Fields Are Compulsary Or Required")
    }

    // console.log(req.user);
    // console.log(req.user.paths);

    //import users
    const user = await User.findById(req.user?._id)

    const addAddress = await UserAddress.create({
        name,
        addressLine1,
        addressLine2,
        city,
        postalCode,
        state,
        country,
        mobileNumber,
        user: req.user?._id
    })

    user.address.push(addAddress)
    await user.save({ validateBeforeSave: false })

    res
        .status(200)
        .json(
            new ApiResponse(
                200,
                { addAddress },
                "User Address Add Successfully"
            )
        )
})

const changeUsersCurruntPassword = asyncHandler(async (req, res) => {
    //get oldpassword and new password
    //check new password and conform password
    //find user
    //check old password
    //save new password
    //return response


    //get oldpassword and new password
    const { oldPassword, newPassword, conformNewPassword } = req.body

    //check new password and conform password
    if (newPassword !== conformNewPassword) {
        throw new ApiError(401, "Conform Pawword Is Wrong")
    }

    //find user
    const user = await User.findById(req.user?._id)

    if (!user) {
        throw new ApiError(401, "Something Went Wrong While Finding the user")
    }

    //check old password
    const isPasswordValidate = await user.isPasswordCorrect(oldPassword)

    if (!isPasswordValidate) {
        throw new ApiError(400, "Invalid Old Password")
    }

    //save new password
    user.password = newPassword
    await user.save({ validateBeforeSave: false })

    //return response
    res
        .status(200)
        .json(
            new ApiResponse(
                201, {}, "Password Changed Successfully")
        )
})

const changeUserDetails = asyncHandler(async (req, res) => {
    //get oldpassword and new password
    //check new password and conform password
    //find user
    //check old password
    //save new password
    //return response


    //get oldpassword and new password
    const { email, phoneNumber, fullName, country } = req.body

    if ([email, phoneNumber, fullName, country].some((filed) => filed.trim() === "")) {
        throw new ApiError(401, "All Fields Are Compulsory Or Required")
    }


    //find user
    const user = await User.findOneAndUpdate(
        req.user?._id,
        {
            email,
            phoneNumber,
            fullName,
            country
        },
        {
            new: true
        }
    ).select("-password")

    //return response
    res
        .status(200)
        .json(
            new ApiResponse(
                201, {}, "Accounts Detaied Updated Successfully")
        )
})

// const addProductsToCart = asyncHandler(async (req, res) => {})

const bookOrder = asyncHandler(async (req, res) => {
    const { quntity, userDeliveryAddress } = req.body
    // const {productId} = req.params

    const user = await User.findById(req.user?._id).select("-password -refreshToken")
    const order = await Order.create({
        user,
        // product:productId,
        quntity,
        // userDeliveryAddress:userDeliveryAddress
    })

    const addToCurruntOrder = await CurruntOrder.create({
        curruntOrder: order,
        status: "PENDING"
    })

    console.log("order : ", order);
    console.log("addToCurruntOrder : ", addToCurruntOrder);
    console.log("addToCurruntOrder.curruntOrders : ", addToCurruntOrder.curruntOrders);

    user.Orders.push(addToCurruntOrder)
    user.save({ validateBeforeSave: false })


    res
        .status(200)
        .json(
            new ApiResponse(
                201,
                { order, addToCurruntOrder, user },
                "Product Added Successfully"
            )
        )
})

export {
    registerUser,
    loginUser,
    logoutUser,
    UsersRefreshAccessToken,
    addUserAddress,
    changeUsersCurruntPassword,
    changeUserDetails,
    // addProductsToCart,
    bookOrder
}
