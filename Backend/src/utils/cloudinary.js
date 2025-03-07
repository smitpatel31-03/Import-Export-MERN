import { v2 as cloudinary } from "cloudinary"
import fs from "fs"

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_NAME,
    api_secret: process.env.CLOUDINARY_API_SECRET
})

const uploadOnCloudnary = async(localFilePath)=>{
    try {
        if(!localFilePath) return null

        const response = await cloudinary.uploader.upload(localFilePath, {
            resource_type: "auto"
        })

        fs.unlinkSync(localFilePath)
        
        return response.url
    } catch (error) {
        fs.unlinkSync(localFilePath) //remove the locallysaved temorary file as the upload opration got failed
        return null
    }
}

export { uploadOnCloudnary } 