import { asyncHandler } from "../utils/asyncHandler.js"
import { ApiError } from "../utils/ApiError.js"
import { ApiResponse } from "../utils/ApiResponse.js"
import { User } from "../models/user.model.js"
import jwt from "jsonwebtoken"

const generateAccessAndRefreshToken = async(userId)=>{
    try {
        //find user
        //genrate access and refresh token
        //update the database
        //save the database
        //return access and refresh token

        //find user
        const user = await User.findById(userId)

        //genrate access and refresh token
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        //update the database
        user.refreshToken = refreshToken
        await user.save({ validateBeforeSave:false })

        return {accessToken, refreshToken}

    } catch (error) {
        throw new ApiError(500, "Something Went Wrong While Genrating Refresh And Access Token")
    }
}

const registerUser = asyncHandler( async(req,res) => {
    //import user details
    //validate user details
    //check email and phone number is available or not
    //add user to database
    // remove password and refresh token field from response
    //check user is created or not
    //response user


    //import user details
    const {email, password, fullName, phoneNumber, country} = req.body


     //validate user details
    if([email, password, fullName, phoneNumber, country].some((field) => field?.trim() === "")){
        throw new ApiError(400, "All Fields Are Compulsory Or Required")
    }


    //check email and phone number is available or not
    const existedUser = await User.findOne({
        $or: [{email},{phoneNumber}]
    })

    if(existedUser){
        throw new ApiError(409,"Email And Phonenumber Are Already Exist")
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
    if(!createdUser){
        throw new ApiError(500,"Something Went Wrong While Registering User");
    }


    //response user
    return res.status(201).json(
        new ApiResponse(200, createdUser, "User registerd successfully")
    )


})

const loginUser = asyncHandler( async(req, res)=>{
    //get user details
    //validate user details
    //find user
    //validate password
    //refresh token and access token
    //response send cookie

    //get user details
    const {email, password, phoneNumber} = req.body

    //validate user details
    if(!email && !phoneNumber){
        throw new ApiError(401,"Please Enter User Details")
    }

    console.log("email : ",email);
    
    //find user
    const user = await User.findOne({
        $or: [{email, phoneNumber}]
    })

    if(!user){
        throw new ApiError(404,"User Not Found")
    }
    //validate password
    const isPasswordValidate = await user.isPasswordCorrect(password)

    if(!isPasswordValidate){
        throw new ApiError(401, "Invalid Crendentials")
    }


    
    //refresh token and access token
    const {accessToken, refreshToken} = generateAccessAndRefreshToken(user._id)
    const logedInUser = await User.findById(user._id).select("-password -refreshToken")

    const options = {
        httpOnly:true,
        secured: true
    }

    //response send cookie
    return res
    .status(201)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
        new ApiResponse(200,{
            user: logedInUser,accessToken, refreshToken
        }),
        "User Loggend In Successfully"
    )
})

const logoutUser = asyncHandler( async(req,res)=>{
    //find user
    //remove refresh token
    //remove cookie

    //find user
    //remove refresh token
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set:{
                refreshToken: undefined
            }
        },{
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

const UsersRefreshAccessToken = asyncHandler( async(req, res)=>{
    //get refresh token
    //decode refresh token
    //find user
    //validate refresh token
    //set refresh and access token
    //response cookie


    //get refresh token
    const incomingRefreshToken = req.cookie.refreshToken || req.body.refreshToken

    if(!incomingRefreshToken){
        throw new ApiError(401,"Unauthorized Request")
    }

    try {
        //decode refresh token
        const decodeToken = jwt.verify(incomingRefreshToken,process.env.REFRESH_TOKEN_SECRATE_USER)

         //find user
        const user = await User.findById(decodeToken?._id)

        if(!user){
            throw new ApiError(401,"Invalid User Refresh Token")
        }

        //validate refresh token
        if(incomingRefreshToken !== user?.refreshToken){
            throw new ApiError(401,"User Refresh Token Is Expired Or Used")
        }

        const options = {
            httpOnly: true,
            secured: true
        }

         //set refresh and access token
        const {accessToken, refreshToken} = await generateAccessAndRefreshToken(user._id)

        //response cookie
        return res.status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options)
        .json(
            new ApiResponse(200,{
                user: {accessToken, refreshToken}
            }),
            "User's Access Token Refreshed Successfully"
        )

    } catch (error) {
        throw new ApiError(401,"Invalid User Refresh Token")
    }
})

export {
    registerUser,
    loginUser,
    logoutUser,
    UsersRefreshAccessToken
}

