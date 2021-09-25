const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const saltRounds = 10
const jwt = require('jsonwebtoken')

const userSchema = mongoose.Schema({
    name : {
        type: String,
        maxlength: 50
    },
    emil: {
        type : String,
        trim: true,
        unique: 1
    },
    password: {
        type: String,
        minlength: 5
    },
    lastname: {
        type: String,
        maxlength: 50
    },
    role: {
        type: Number,
        default: 0
    },
    image: String,
    token: {
        type: String
    },
    tokenExp: {
        type: Number
    }
})

userSchema.pre('save',function(next){
    //비밀번호 암호화
    var user = this;
    if(user.isModified('password')) {
        bcrypt.genSalt(saltRounds,function(err,salt){
            if(err) return next(err)
            bcrypt.hash(user.password, salt, function(err,hash){
                if(err) return next(err)
                user.password = hash
                next()
            })
        })
    } else {
        next()
    }
}) //save 를 수정하기 전에 함수를 실행

userSchema.methods.comparePassword = function(plainPassword, cb) {
    //plainPassword를 변환시킨 후 db의 암호화된 비밀번호와 비교
    bcrypt.compare(plainPassword, this.password,function(err, isMatch) {
        if (err) return cb(err)
        cb(null,isMatch)
    })
}

userSchema.methods.generateToken = function(cb) {
    var user = this
    //jsonwebtoken을 이용해서 token을 생성하기
    //user._id + 'secretToken' = token 나중에 'secretToken 을 알면 user._id를 알 수 있다.
    var token = jwt.sign(user._idm ,'secretToken')
    user.token = token
    user.save(function(err,user) {
        if(err) return cb(err)
        cb(null,user)
    })
    
}

const User = mongoose.model('User', userSchema)

module.exports = {User}