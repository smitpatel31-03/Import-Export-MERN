import mongoose, { Schema } from 'mongoose';

const categorySchema = new Schema(
    {
        name: {
            type: String,
            required: true,
            unique: true,
            trim : true
        },
        description: {
            type: String,
            required: true,
        },
        image:{
            type: String,
            required: true
        },
        products: [
            {
                type: mongoose.Schema.Types.ObjectId,
                ref: "Product"
            }
        ],
    },
    {
        timestamps: true,
    }
);

export const Category = mongoose.model('Category', categorySchema);
