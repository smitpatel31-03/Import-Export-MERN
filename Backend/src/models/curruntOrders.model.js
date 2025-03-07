import mongoose, { Schema } from "mongoose"

const curruntOrderSchema = new Schema(
    {
        curruntOrder: {
            type: Schema.Types.ObjectId,
            ref: "Order"
        },
        status: {
            type: String,
            enum: ["PENDING", "PROCESSING ", "SHIPPED", "IN TRANSIT", "CUSTOMS CLEARANCE", "DELIVERED", "CANCELLED", "FAILED"],
            default: "PENDING"
        }
    },
)

export const CurruntOrder = new mongoose.model("CurruntOrder", curruntOrderSchema) 