import { asyncHandler } from "../utils/asyncHandler.js"
import { ApiError } from "../utils/ApiError.js"
import { ApiResponse } from "../utils/ApiResponse.js"
import { User } from "../models/user.model.js"

const registerUser = asyncHandler( async(req,res) => {
    //import user details
    //validate user details
    //check email and phone number is available or not
    //add user to database
    // remove password and refresh token field from response
    //check user is created or not
    //response user


    //import user details
    const {email, password, fullName, phoneNumber, country, A_addressLine1, A_addressLine2, A_city, A_postalcode, A_state, A_country, A_phoneNumber} = req.body


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
        country, 
        A_addressLine1, 
        A_addressLine2, 
        A_city, 
        A_postalcode, 
        A_state, 
        A_country, 
        A_phoneNumber
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

export {
    registerUser,
}

