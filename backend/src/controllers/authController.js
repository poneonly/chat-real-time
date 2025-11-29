import bcrypt from 'bcrypt';
import User from '../models/User.js';
import jwt from 'jsonwebtoken';
import Session from '../models/Session.js';
import crypto from 'crypto';

const ACCESS_TOKEN_TTL = '30m'; // thường là dưới 15ph
const REFRESH_TOKEN_TTL = 14 * 24 * 60 * 60 * 1000; // thường là dưới 1 tuần
export const signUp = async (req, res) => {
    try {
        const { username, email, password, lastName, firstName } = req.body;
        if (!username || !email || !password || !lastName || !firstName) {
            return res
            .status(400)
            .json({ message: "All fields are required"});
        }

        // check if username already exists
        const duplicate = await User.findOne({ username});

        if (duplicate) {
            return res.status(400).json({ message: "Username already exists"});
        }

        // hashed password
        const hashedPassword = await bcrypt.hash(password, 10); // 10 là salt rounds
        
        
        // create user
        await User.create({ 
            username, 
            email, 
            hashedPassword, 
            displayName: `${firstName} ${lastName}` });
        // return
        return res.sendStatus(201);

    } catch (error) {
        console.error("Error signing up", error);
        return res.status(500).json({ message: "Internal server error"});
    }
}

export const signIn = async (req, res) => {
    try {
        // lấy inputs 
        const {username, password} = req.body;
        if (!username || !password) {
            return res.status(400).json({ message: "All fields are required"});
        }

        // check if username exists
        const user = await User.findOne({ username});
        if (!user) {
            return res.status(400).json({ message: "username hoặc password không đúng"});
        }

        // kiểm tra password
        const passwordCorrect = await bcrypt.compare(password, user.hashedPassword);
        if (!passwordCorrect) {
            return res.status(401).json({ message: "username hoặc password không đúng"});
        }

        // nếu khớp, tạo access token với JWT
        const accessToken = jwt.sign({userId: user._id}, process.env.ACCESS_TOKEN_SECRET, {expiresIn: ACCESS_TOKEN_TTL});
        // tạo refresh token 
        const refreshToken = crypto.randomBytes(64).toString('hex');

        // tạo session mới để lưu refresh token
        await Session.create({ userId: user._id, refreshToken, expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL)});
        // trả về refresh token về trong cookie 
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: 'none',
            maxAge: REFRESH_TOKEN_TTL,
        })
        // trả access token về trong res
        return res.status(200).json({ message: `User ${user.displayName} đăng nhập thành công`, accessToken });
        
    } catch (error) {
        console.error("Error signing in", error);
        return res.status(500).json({ message: "Internal server error"});
    }
}

export const signOut = async (req, res) => {
    try {
        // lấy refresh token từ cookie
        const token = req.cookies?.refreshToken;

        if (token) {
            // xoá refresh token từ cookie
            await Session.deleteOne({ refreshToken: token });
            // xoá cookie
            res.clearCookie('refreshToken');
        }

        return res.status(204);
    } catch (error) {
        console.error("Error signing out", error);
        return res.status(500).json({ message: "Internal server error"});
    }
}