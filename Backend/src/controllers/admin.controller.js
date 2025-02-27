import { asyncHandler } from "../utils/asyncHandler.js"

const registerAdmin = asyncHandler( async(req,res) => {
    res.status(200).json ({
        message: "admin register"
    })
})

export {
    registerAdmin,
}
