import { asyncHandler } from "../utils/asyncHandler.js"
import { ApiError } from "../utils/ApiError.js"
import { ApiResponse } from "../utils/ApiResponse.js"
import { User } from "../models/user.model.js"

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
        const refreshToken = user.generateRefreshToken

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
        throw new ApiError(409,"Email And Password Are Already Exist")
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
    const createdUser = await User.findById(user._id).some(
        "-password -refreshToken"
    )


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
    if(!email || !phoneNumber){
        throw new ApiError(401,"Please Enter User Details")
    }

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
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
        new ApiResponse(200,{
            user: logedInUser,accessToken, refreshToken
        }),
        "User Loggend In Successfully"
    )
})

export {
    registerUser,
    loginUser
}

