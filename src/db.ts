import mongoose from "mongoose"

const connectToDatabase = async () => {
    try {
        const connection = await mongoose.connect(
            "mongodb+srv://abhijeetps:w0aK7HNY9sWiE6r0@cluster0.c0sddwj.mongodb.net/blossom-app?retryWrites=true&w=majority"
        )
        if(connection){
            console.log("Connection established")
        }
    }
    catch (error) {
        console.log("Error in connectToDatabase", error)
        throw error
    }    
}


export default connectToDatabase