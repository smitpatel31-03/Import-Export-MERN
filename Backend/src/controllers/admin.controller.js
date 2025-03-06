import { asyncHandler } from "../utils/asyncHandler.js"
import { ApiError } from "../utils/ApiError.js"
import { Admin } from "../models/admin.model.js"
import { ApiResponse } from "../utils/ApiResponse.js"
import jwt from "jsonwebtoken"
import { uploadOnCloudnary } from "../utils/cloudinary.js"

const generateAccessAndRefreshToken = async(AdmnId)=>{
    try {
        //find admin
        //genrate accesstoken and refreshtoken
        //update database
        //retuen accesstoken and refreshtoken 

        //find admin
        const admin = await Admin.findById(AdmnId)

        //genrate accesstoken and refreshtoken
        const accessToken = admin.generateAccessToken()
        const refreshToken = admin.generateRefreshToken()
        
        admin.refreshToken = refreshToken
        await admin.save({validateBeforeSave:false})

        return {accessToken,refreshToken}

    } catch (error) {
        throw new ApiError(500, "Something Went Wrong While Genrating Refresh And Access Token")
    }
}

const registerAdmin = asyncHandler( async(req,res) => {
    //import data 
    //validate admin
    //check admin email is available or not
    //check admin enter a proper role or not
    //check if admin role is Owner then he k=have valid key or not
    //add admin to database
    // remove password , refreshtoken and key field from response
    //check Admin is crated or not
    //response Admin

    //import data 
    const{email, password, name, key, role} = req.body

    //validate admin
    if([email, password, name, key,role].some((field)=>field?.trim === "")){
        throw new ApiError(400, "All Fields Are Coumplsory Or Required")
    }


    //check admin email is available or not
    const existedUser = await Admin.findOne({email})

    if(existedUser){
        throw new ApiError(409,"User")
    }

    //check admin enter a proper role or not
    if(!["ADMIN", "OWNER", "CREATOR", "DELIVERY"].includes(role)){
        throw new ApiError(401,"Enter A Valid Role")
    }

    
    //check if admin role is Owner then he have valid key or not
    if(role==="ADMIN" && key!==process.env.ADMIN_KEY || role==="CREATOR" && key!==process.env.CREATOR_KEY || role==="OWNER" && key!==process.env.OWNER_KEY){
        throw new ApiError(409, "Enter A Valid Key")
    }


    //add admin to database
    const admin = await Admin.create({
        email, 
        password, 
        name, 
        role
    })


    
    // remove password , refreshtoken and key field from response
    const createdAdmin = await Admin.findById(admin._id).select(
        "-password -key -refreshToken"
    )


    //check Admin is crated or not
    if(!createdAdmin){
        throw new ApiError(500,"Something Went Wrong While Registering Admin")
    }

    //response admin
    res.status(201).json(
        new ApiResponse(200, createdAdmin, "Admin Created Successfully")
    )
})

const loginAdmin = asyncHandler( async(req,res)=>{
    //get Admin Details
    //validate Admin Details
    //find Admin
    //verify Password
    //genrate refreshtoken and accesstoken
    //send cookies

    //get Admin Details
    const {email, password, adminId} = req.body
    
    //validate Admin Details
    if(!email && !adminId){
        throw new ApiError(401,"Please Enter The Details")
    }

    //find Admin
    const admin = await Admin.findOne({
        $or: [{email, adminId}]
    })

    if(!admin){
        throw new ApiError(404,"Admin Not Found")
    }

    //verify Password
    const isPasswordValidate = await admin.isPasswordCorrect(password)
    
    if(!isPasswordValidate){
        throw new ApiError(401,"Invalid Credentails");
    }

    //genrate refreshtoken and accesstoken
    const {accessToken,refreshToken} = await generateAccessAndRefreshToken(admin._id)
    
    const loggedInAdmin = await Admin.findById(admin._id).select("-password -refreshToken")

    const options = {
        httpOnly:true,
        secured:true
    }

    //send cookies
    return res
    .status(200)
    .cookie("accessToken",accessToken,options)
    .cookie("refreshToken",refreshToken,options)
    .json(
        new ApiResponse(
            200,{
                Admin: loggedInAdmin, accessToken, refreshToken
            },
            "Admin Loggedin Successfully"
        )
    )
})

const logoutAdmin = asyncHandler( async(req,res)=>{
    //find admin
    //remove refresh token from database
    //remove cookie

    //find admin
    //remove refresh token from database
    console.log("req.admin :",req.admin);
    console.log("req.admin._id :",req.admin._id);
    
    await Admin.findByIdAndUpdate(
        req.admin._id,
        {
            $set:{
                refreshToken: undefined
            }
        },
        {
            new: true
        }
    )

    const options = {
        httpOnly: true,
        secured: true
    }

     //remove cookie
    return res.status(201)
     .cookie("accessToken",options)
     .cookie("refreshToken",options)
     .json(new ApiResponse(200, {}, "Admin Loggedout Successfully"))
})

const AdminsRefreshAccessToken = asyncHandler( async(req, res)=>{
    //get cookies and check cookie
    //decode the token
    //find user
    //vaidate refresh token
    //set refresh and access token
    //response cookies


     //get cookies and check cookie
     const incomingRefreshToken = req.cookie.refreshToken || req.body.refreshToken

     if (!incomingRefreshToken){
        throw new ApiError(401,"Unauthorized Admin")
     }

     try {
        //decode the token
        const decodeToken = jwt.verify(incomingRefreshToken,process.env.ACCESS_TOKEN_SECRET_ADMIN)

        //find user
        const admin = await Admin.findById(decodeToken)

        if(!admin){
            throw new ApiError(401,"Invalid Admin's Refresh Token");
        }

        //vaidate refresh token
        if(incomingRefreshToken !== admin?.refreshToken){
            throw new ApiError(401,"Admin's Refresh Token Is Expired Or Used")
        }

        const options = {
            httpOnly: true,
            secured: true
        }

        //set refresh and access token
        const {accessToken,refreshToken} = generateAccessAndRefreshToken(admin._id)

        return res
        .status(200)
        .cookie("accessToken",accessToken,options)
        .cookie("refreshToken",refreshToken,options)
        .json(
            new ApiResponse(
                201,
                {accessToken,refreshToken},
                "Admin's Access Token Refreshed Ruccessfully"
            )
        )

     } catch (error) {
        throw new ApiError(401,error?.message || "Invalid Admin's Refresh Token")
     }

})

const changeAdminCurruntPassword = asyncHandler(async(req,res)=>{
    //get oldpassword and new password
    //check new password and conform password
    //find user
    //check old password
    //save new password
    //return response


    //get oldpassword and new password
    const {oldPassword,newPassword,conformNewPassword} = req.body

    //check new password and conform password
    if(newPassword !== conformNewPassword){
        throw new ApiError(401,"Conform Pawword Is Wrong")
    }

    //find admin
    const admin = await Admin.findById(req.admin?._id)

    if(!admin){
        throw new ApiError(401,"Something Went Wrong While Finding the admin")
    }

    //check old password
    const isPasswordValidate = await admin.isPasswordCorrect(oldPassword)

    if(!isPasswordValidate){
        throw new ApiError(400,"Invalid Old Password")
    }

    //save new password
    admin.password = newPassword
    await admin.save({validateBeforeSave:false})

    //return response
    res
    .status(200)
    .json(
        new ApiResponse(
            201,{},"Password Changed Successfully")
    )
})

const changeAdminRole = asyncHandler( async(req,res)=>{
    const {role,key} = req.body

    if(!role || !key){
        throw new ApiError(401,"All Fields Are Required")
    }

    if(role==="ADMIN" && key!==process.env.ADMIN_KEY || role==="CREATOR" && key!==process.env.CREATOR_KEY || role==="OWNER" && key!==process.env.OWNER_KEY){
        throw new ApiError(409, "Enter A Valid Key")
    }

    const admin = await Admin.findById(req.admin?._id)

    admin.role = role
    await admin.save({validateBeforeSave:true})

    res
    .status(200)
    .json(
        201,
        {role},
        "Admin Role Udated Successfully"
    )
})

const changeUserDetails = asyncHandler(async(req,res)=>{
    //get oldpassword and new password
    //check new password and conform password
    //find user
    //check old password
    //save new password
    //return response


    //get oldpassword and new password
    const {email, name} = req.body

    if(!email || !name){
        throw new ApiError(401,"All Fields Are Compulsory Or Required")
    }


    //find user
    const admin = await Admin.findOneAndUpdate(
        req.admin?._id,
        {
            email, 
            name
        },
        {
            new : true
        }
    ).select("-password")

    //return response
    res
    .status(200)
    .json(
        new ApiResponse(
            201,{},"Accounts Detaied Updated Successfully")
    )
})

// const addCatagory = asyncHandler(async(req,res)=>{
//     const {name,description} = req.body

//     if(!name || !description){
//         throw new ApiError(401,"All Fileds Are Required");
//     }

//     const imageLocalPath = req.files?.image[0]?.path
// })

export {
    registerAdmin,
    loginAdmin,
    logoutAdmin,
    AdminsRefreshAccessToken,
    changeAdminCurruntPassword,
    changeAdminRole,
    changeUserDetails
}
