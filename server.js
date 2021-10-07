require('dotenv').config();
const express= require('express')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt');
const saltRounds = 10;
const PORT = 3000; 
const SECRET_KEY = process.env.SECRET_ACCESS_KEY;

const mongoose = require('mongoose');
mongoose.connect('mongodb://mongodb:27017/hello');

const userSchema= new mongoose.Schema({
    name:String,
    pass:String
})

const userModel= mongoose.model('user',userSchema);

const app = express(); 

app.use(express.json());
app.use(express.urlencoded({extended:true}));

const users= []

app.get("/admin",(req,res)=>{
    res.send(users)
})

app.get('/database-admin',async(req,res)=>{
    const users = await userModel.find({});
    res.send(users)
})

app.get("/",verifyAuth,(req,res)=>{
    const user = req.user ;

    res.send(user)
})

app.post("/signup",  async (req,res)=>{
    const { username, password } = req.body ; 

    //check if user already exists;
    const found= await userModel.findOne({
        name: username
    })
    if(found) 
        return res.status(409).send({
            message:"failed",
            description:"user already exists"
        })

    //adding user to db
    bcrypt.genSalt(saltRounds, (err,salt)=>{
        if(err) return res.status(400).send({message:"failed"})
        bcrypt.hash(password,salt,(err, hash)=>{
            if(err) return res.send(400).send({message:"failed"})
            const user = new userModel({
                name: username,
                pass: hash
            });
            user.save().then(()=>{
                res.status(200).send({
                    message: "success"
                })
            })
        })
    })
})

app.post("/signin", async(req,res)=>{
    const {username, password} = req.body ; 
    
    const foundUser = await userModel.findOne({name:username});

    
    // check if user exists
    if(! foundUser)
        return res.status(404).send({
            message:"failure",
            description:"user does not exist"
        })

    //check if password is right
    bcrypt.compare(password,foundUser.pass,(err,result)=>{
        if(err) return res.status(400).send({message:"failure", description:"something went wrong"});
        if(!result) return  res.status(401).send({message:"failure", description: "wrong password"})

        const payload = {
            username : username, 
            logTime: (new Date()).toLocaleString("en-US")
        }

        console.log(payload.logTime)

        jwt.sign(payload, SECRET_KEY,(err,token)=>{
            if(err) return res.status(400).send({message:"failure"});
            res.status(200).send({
                message:"success",
                token,
            })
        });
    })
})


function verifyAuth(req, res , next){
    const {token} = req.headers ; 
    jwt.verify(token,SECRET_KEY,(err,decoded)=>{
        if(err) res.status(401).send("invalid token")
        req.user= decoded;
        next()
    })
}


app.listen(PORT,()=>{
    console.log(`listening on port ${PORT}`)
})