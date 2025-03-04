import { Router }  from "express"
import { registerAdmin,loginAdmin,logoutAdmin,AdminsRefreshAccessToken } from "../controllers/admin.controller.js"
import { verifyJWTAdmin } from "../middlewares/auth.admin.middleware.js"

const router = Router()

router.route("/register").post(registerAdmin)
router.route("/login").post(loginAdmin)
router.route("/logout").post(verifyJWTAdmin ,logoutAdmin)
router.route("/refresh-token").post(AdminsRefreshAccessToken)

export default router