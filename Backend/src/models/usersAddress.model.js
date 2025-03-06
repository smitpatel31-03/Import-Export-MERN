import mongoose,{Schema} from "mongoose";

const userAddressSchema = Schema({
    addressLine1:{
        type: String,
        required: true
    },
    addressLine2:{
        type: String,
        required: true
    },
    city:{
        type: String,
        required: true
    },
    postalCode:{
        type: Number,
        required: true
    },
    state:{
        type: String,
        required: true
    },
    country:{
        type: String,
        required: true
    },
    mobileNumber:{
        type: Number,
        required: true
    },
    user:{
        type: Schema.Types.ObjectId,
        ref: "User"
    }
})

export const UserAddress = mongoose.model("UserAddress",userAddressSchema)