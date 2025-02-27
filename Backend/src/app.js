import express from 'express'
import cors from 'cors'
import cookieParser from 'cookie-parser'

const app = express()

app.use(cors({
    origin: process.env.CORS_ORIGIN,
    Credential: true
}))

app.use(express.json({ limit: "16kb" }))
app.use(express.urlencoded({ extended: true, limit: "16kb" }))
app.use(express.static("public"))
app.use(cookieParser())


//routes
import userRouter from "./routes/user.routs.js"
import adminRouter from "./routes/admin.routs.js"

//routes declaration
app.use("/api/v1/users", userRouter)
app.use("/api/v1/admin", adminRouter)

export { app }