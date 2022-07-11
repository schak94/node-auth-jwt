require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');// It is an async function
const jwt = require('jsonwebtoken');
//const mongoose = require('mongoose');
const app = express();
const users=[];
// mongoose.connect('mongodb://localhost:27017/users',{useNewUrlParser:true})
// const db = mongoose.connection
// db.on('error', (error)=> console.log(error))
// db.once('open', ()=>console.log('Connected to Database'))

app.use(express.json())

const posts = [
    {
        username: "Shubham",
        post: "Post1"
    },
    {
        username: "Shubham1",
        post: "Post2"
    }
]

app.get('/posts',authenticateToken, (req, res)=>{
    res.json(posts.filter(post=> post.username === req.user.name))
})

app.get('/users', (req,res)=>{
    res.json(users)
})
 
app.post('/users', async (req,res)=>{
    try{
        const salt = await bcrypt.genSalt(); // Generates the salt for the password
        const hashPassword = await bcrypt.hash(req.body.password, salt); // Add the salt and create the combination
        const user = {name: req.body.name, password: hashPassword}
        users.push(user)
        res.status(201).send("Created")
    }
    catch(err){
        res.status(500).send("Something went wrong!")
    }
})

app.post('/users/login', async (req, res)=>{
    const user = users.find(user => user.name === req.body.name)
    console.log(user)
    if(user === undefined || user === null){
        return res.status(400).send("User not found!")
    }
    try{
        if(await bcrypt.compare(req.body.password, user.password)){
            const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET)
            res.json({accessToken: accessToken})
        }
        else{
            res.send("User Not Authorized!")
        }
    }
    catch(err){
        res.status(500).send("Something went wrong!",err) 
    }
})

function authenticateToken(req, res, next){
    const authHeader = req.headers['authorization'];// Bearer Token format
    const token = authHeader && authHeader.split(' ')[1];
    if(token === null) return res.status(401)
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET,(err,user)=>{
        if(err) return res.status(403)
        req.user = user;
        next()
    })
}


app.listen(3000, (err)=>{
    if(err){
        console.log("Something went wrong");
    }
    else{
        console.log("Server is listening to 3000")
    }
})