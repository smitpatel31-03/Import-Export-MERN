import mongoose, { Schema } from "mongoose"

const curruntOrderSchema = new Schema(
    [
        {
            type: mongoose.Schema.Types.ObjectId,
            ref: "BookOrder"
        },
    ]
)

export const CurruntOrder = new ("CurruntOrder", curruntOrderSchema) 