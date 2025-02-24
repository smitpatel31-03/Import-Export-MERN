import mongoose, { Schema } from "mongoose";

const productSchema = new mongoose.Schema(
    {
        name: {
            type: String,
            required: true
        },
        productId: {
            type: String,
            unique: true,
            require: true
        },
        price: {
            type: Number,
            required: true
        },
        photos: [
            {
                type: String
            },
        ],
        description: {
            type: String,
            required: true
        },
        category: {
            type: String,
            required: true
        },
        stock: {
            type: Number,
            required: true
        },
        owner: {
            type: String,
            required: true
        }
    }
);

const Product = mongoose.model('Product', productSchema);

