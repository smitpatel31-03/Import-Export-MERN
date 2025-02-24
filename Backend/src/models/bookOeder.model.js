import mongoose, { Schema } from 'mongoose';

const bookOrderSchema = new Schema({
    ProductId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Product"
    },
    OrderId: {
        type: String,
        required: true,
        unique: true
    },
    quntity: {
        type: Number
    },
    curruntStatus: {
        type: String,
        enum: ["PENDING", "SHIPPED", "READYTODELEVER", "DELIVERED", "CANCLED"],
        default: "PENDING"
    },
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User"
    }
});

const BookOrder = mongoose.model('BookOrder', bookOrderSchema);
