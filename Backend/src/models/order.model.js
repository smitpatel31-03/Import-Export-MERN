import mongoose,{Schema} from "mongoose";

const orderSchema = new Schema({
    user:{
        type: Schema.Types.ObjectId,
        ref: "User"
    },
    product:{
        type: Schema.Types.ObjectId,
        ref: "Product"
    },
    quntity:{
        type: Number,
        required : true,
        default: 1
    },
    userDeliveryAddress:{
        type: Schema.Types.ObjectId,
        ref: "UserAddress"
    }
})

export const Order = new mongoose.model("Order",orderSchema)