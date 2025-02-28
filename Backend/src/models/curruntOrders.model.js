import mongoose, { Schema } from "mongoose"

const curruntOrderSchema = new Schema(
    {
        orders:[
            {
                type: mongoose.Schema.Types.ObjectId,
                ref: "BookOrder"
            },
        ],
    }
)

export const CurruntOrder = new ("CurruntOrder", curruntOrderSchema) 