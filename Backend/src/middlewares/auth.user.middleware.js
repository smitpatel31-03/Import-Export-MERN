import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import jwt from "jsonwebtoken"
import { User } from "../models/user.model.js"


export const verifyJWTUser = asyncHandler( async(req,_,next)=>{
    try {
        //get token
        //decoded token
        //find user
        //declare user
    
        //get token
        const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ","")
    
        if(!token){
            throw new ApiError(401,"Unauthorized Access")
        }
    
        //decoded token
        const decodedToken = jwt.verify(token, process.env?.ACCESS_TOKEN_SECRET_USER) 
    
        //find user
        const user = User.findById(decodedToken?._id).select("-password -refreshToken")
        
        
        if(!user){
            throw new ApiError(401,"Invalid Token")
        }
    
        //declare user
        req.user = decodedToken
        // console.log("req.user.schema: ",req.user.schema);
        
        next()
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid Token")
    }
})