import { Router }  from "express"
import { registerUser,loginUser,logoutUser,UsersRefreshAccessToken } from "../controllers/user.controller.js"
import { verifyJWTUser } from "../middlewares/auth.user.middleware.js"

const router = Router()

router.route("/register").post(registerUser)
router.route("/login").post(loginUser)
router.route("/logout").post(verifyJWTUser,logoutUser)
router.route("/refresh-token").post(UsersRefreshAccessToken)

export default router