require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');// It is an async function
const jwt = require('jsonwebtoken');
const app = express();
const users = require('./data')
app.use(express.json())


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


app.listen(4000, (err)=>{
    if(err){
        console.log("Something went wrong");
    }
    else{
        console.log("Server is listening to 4000")
    }
})