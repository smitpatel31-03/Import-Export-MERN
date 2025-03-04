import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import jwt from "jsonwebtoken"
import { Admin } from "../models/admin.model.js";

export const verifyJWTAdmin = asyncHandler(async(req,_,next)=>{
    try {
        //get token
        //decode token
        //find admin
        //declared admin
        
        const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer","")
    
        if(!token){
            throw new ApiError(401,"Unauthorized Access")
        }
    
        //decode token
        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET_ADMIN)
        
            //find admin
        const admin = Admin.findById(decodedToken?._id).select("-password -refreshToken")
        
        if(!admin){
            throw new ApiError(401,"Invalid Token")
        }
    
        req.admin = admin
        next()
    
    } catch (error) {
        throw new ApiError(401,error?.message || "Something Went Wrong")
    }
})