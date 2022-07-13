require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');// It is an async function
const jwt = require('jsonwebtoken');
const e = require('express');
//const mongoose = require('mongoose');
const app = express();
const users=[];
let refreshedToken = [];
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
    if(req.user === undefined) return res.status(404).send("User Not Authorized")
    res.json(posts.filter(post=> post.username === req.user.name))
})

app.get('/users', (req,res)=>{
    res.json(users)
})

app.delete('/logout',(req,res)=>{
    refreshedToken = refreshedToken.filter(token => token !== req.body.token)
    res.status(204)
})

app.post('/token',(req, res)=>{
    const refreshToken = req.body.token
    if(refreshToken === undefined || refreshToken === null) return res.status(401)
    if(!refreshedToken.includes(refreshToken)) return res.status(403)
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET,(err,data)=>{
        if(err) return res.status(403)
        const accessToken = generateAccessToken({name:data.name})
        res.json({accessToken:accessToken})
    })
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
    if(user === undefined || user === null){
        return res.status(400).send("User not found!")
    }
    try{
        if(await bcrypt.compare(req.body.password, user.password)){
            const accessToken = generateAccessToken({name:user.name})
            const refreshToken = jwt.sign(user,process.env.REFRESH_TOKEN_SECRET)
            refreshedToken.push(refreshToken)
            res.json({accessToken: accessToken, refreshToken:refreshToken})
        }
        else{
            res.send("User Not Authorized!")
        }
    }
    catch(err){
        res.status(500).send("Something went wrong!",err) 
    }
})

function generateAccessToken(val){
return jwt.sign(val, process.env.ACCESS_TOKEN_SECRET,{expiresIn:'50s'})
}

function authenticateToken(req, res, next){
    const authHeader = req.headers['authorization'];// Bearer Token format
    const token = authHeader && authHeader.split(' ')[1];
    if(token === null) return res.status(401)

    try{
        const data = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)
        req.user = data;

    }
    catch(err){
        res.status(403)
    }
    next();
}


app.listen(4000, (err)=>{
    if(err){
        console.log("Something went wrong");
    }
    else{
        console.log("Server is listening to 4000")
    }
})