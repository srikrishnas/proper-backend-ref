const express = require("express");
const app = express();
const bcrypt = require('bcrypt');


require('dotenv').config();

const mongodb = require('mongodb');
const { hashing,hashCompare,createJWT,authenticate } = require("./server/authorize");
const mongoClient = mongodb.MongoClient;

//middleware
app.use(express.json());

const dbUrl = process.env.DB_URL || "mongodb://127.0.0.1:27017";
const port = process.env.PORT || 4000;

app.get("/",(req,res) => {
    res.send("Welcome to my app")
})

// register route
app.post("/register", async (req,res)=>{
  
    const client = await mongoClient.connect(dbUrl);
    if(client){
        try {
                const db = client.db("productManager");
                const documentFind = await db.collection("users").findOne({email:req.body.email});
                if(documentFind){
                    res.status(400).json({
                        message:"User already Exists"
                    })
                } else {

                    //getting hash of the password
                    const hash = await hashing(req.body.password);

                    // updating pwd with hash
                    req.body.password = hash;

                    // insert user regestration details to db
                    const document = await db.collection("users").insertOne(req.body);

                    if(document) {
                        res.status(200).json({
                            "message":"Record created"
                        })
                    }
                }
            client.close();
        } catch (error) {
            console.log(error);
            client.close();
        }
    } else {
        res.sendStatus(500);
    }
})

//Login
app.post("/login", async(req,res)=>{
    const client = await mongoClient.connect(dbUrl);
    if(client){
        try {
            const { email, password} = req.body;
            const db = client.db("productManager");

            //find if user exists
            const user = await db.collection("users").findOne({email});
            if(user){

                // comparing hashed with user pwd
                const compare = await hashCompare(password, user.password);
                if(compare){

                    //call to get token
                    const token = await createJWT({email,id:user._id,role:user.role});
                    return res.status(200).json({token})
                }
            }
            client.close()
        } catch (error) {
            console.log(error);
            client.close();
        }

    }
})

// add product
app.post("/add-product",authenticate,async(req,res)=>{
    const client = await mongoClient.connect(dbUrl);
    if(client){
        try {
            const db = client.db("productManager");
            const document = await db.collection("products").insertOne(req.body);
            if(document){
                res.status(200).json({
                    "message":"record updated"
                })
            }
            client.close();
        } catch (error) {
            console.log(error);
            client.close();
        }
    }
})

// all products
app.get("/all-products",authenticate,async(req,res)=>{
    const client = await mongoClient.connect(dbUrl);
    if(client){
        try {
            const db = client.db("productManager");
            const document = await db.collection("products").find().toArray();
            if(document){
                res.status(200).json(document)
            }
            client.close()
        } catch (error) {
            console.log(error);
            client.close();
        }
    }
})


app.listen(port, () => console.log("app is listning"))