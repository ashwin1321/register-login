const express = require('express');
const app  = express()
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const User = require('./model/user')
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const localStorage = require('localstorage');

const JWT_SECRET = 'sadfgdafg@@#2343()*&%$^&*54f#$%#%sgsdgsgs'

mongoose.connect("mongodb://localhost/login",{
    useNewUrlParser: true,         // get rid of warnings                     
    useUnifiedTopology: true
})


app.use(express.static("public"))
app.use(bodyParser.json())


app.post('/api/change-password', async (req,res)=>{
    const { token} = req.body
    try{

        const user = await jwt.verify(token, JWT_SECRET)
        console.log('JWT decoded: ',user);
    }
    catch(error){
        res.json({status:'error', error: ';'})
    }
    res.json({status: 'ok' })
})

app.post('/api/login', async (req,res)=>{

    const {username, password} = req.body

    const user = await User.findOne({username}).lean()
     
    if(!user){
        return res.json({status:  'error', error :`Invalid credentials.....`})
    }
    // if( await bcrypt.compare(password, user.password)){
    //     // the username password combination is successful 
    //     return res.json({status: 'ok', data: ""})
    // }

    if(await bcrypt.compare(password, user.password)){
        const token = jwt.sign({
             id: user._id, 
             username: user.username
            }, JWT_SECRET)

        return res.json({status: "ok", data: token})
    }


    res.json({ status: 'error', data: "Invalid Credentials."})
})
app.post('/api/register', async (req,res)=>{
    // console.log(req.body);
    
    // Hashing the password
    var {username, password} =req.body
    // const password  =  await bcrypt.hash(password,10)

    if (!username || typeof username !== 'string'){
        return res.json({ status:'error', error: "Invalid username"})    
    }

    if (!password || typeof password !== 'string'){
        return res.json({ status:'error', error: "Invalid password"})    
    }

    if(password.length <8){
        return res.json({ status: 'error', error: "Password too small. Must be atleast 8 characters"})
    }
     
    var password = await bcrypt.hash(password,10)
    // console.log(req.body);
    // console.log(password);

    try{
        const response = await User.create({
            username,
            password
        })
        console.log(`User created Successfully....`, response);
        // console.log('hello');

    }
    catch(error){

        console.log(error.message);  
     }
        res.json({status: 'ok'})
})

app.listen(5000,()=>{ 
    console.log(`Server listening at port 5000......`);
})

