import { asyncHandler } from "../utils/asyncHandler.js"
import { ApiError } from "../utils/ApiError.js"
import { Admin } from "../models/admin.model.js"
import { ApiResponse } from "../utils/ApiResponse.js"

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

export {
    registerAdmin,
}
