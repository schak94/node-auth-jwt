const express = require('express');
const bcrypt = require('bcrypt');// It is an async function
const app = express();
app.use(express.json())

const users = [];

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
    const user = users.find(user => user.name = req.body.name)
    if(user == null){
        res.status(400).send("User not found!")
    }
    try{
        if(await bcrypt.compare(req.body.password, user.password)){
            res.send("User Authenticated!")
        }
        else{
            res.send("User Not Authorized!")
        }
    }
    catch(err){
        res.status(500).send("Something went wrong!",err) 
    }
})

app.listen(3000, (err)=>{
    if(err){
        console.log("Something went wrong");
    }
    else{
        console.log("Server is listening to 3000")
    }
})