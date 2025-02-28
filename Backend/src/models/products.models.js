import mongoose, { Schema } from "mongoose";

const productSchema = new Schema(
    {
        name: {
            type: String,
            required: true,
        },
        productId: {
            type: String,
            unique: true,
            required: true,
        },
        price: {
            type: Number,
            required: true,
        },
        photos: [
            {
                type: String
            },
        ],
        description: {
            type: String,
            required: true,
        },
        category: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Category",
            required: true,
        },
        stock: {
            type: Number,
            required: true,
        },
        owner: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true,
        },
    }
);

export const Product = mongoose.model('Product', productSchema);

