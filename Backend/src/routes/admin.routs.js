import { Router }  from "express"
import { registerAdmin,loginAdmin,logoutAdmin,AdminsRefreshAccessToken,addCatagory } from "../controllers/admin.controller.js"
import { verifyJWTAdmin } from "../middlewares/auth.admin.middleware.js"
import { upload } from "../middlewares/multer.middleware.js"

const router = Router()

router.route("/register").post(registerAdmin)
router.route("/login").post(loginAdmin)
router.route("/logout").post(verifyJWTAdmin ,logoutAdmin)
router.route("/refresh-token").post(AdminsRefreshAccessToken)
router.route("/addCatagory").post(
    upload.fields([{
        name:"image",
        maxCount : 1
    }]),
    addCatagory)

export default router