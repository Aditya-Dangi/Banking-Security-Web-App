import User from '../model/user.js';
import OTP from '../model/otp.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import validator from 'validator';
import nodemailer from "nodemailer";
import otpGenerator from 'otp-generator';

const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes in milliseconds

const sendEmail = async (email, subject, htmlContent) => {
    const transporter = nodemailer.createTransport({
        service: 'Gmail',
        auth: {
            user: process.env.SENDER_EMAIL,
            pass: process.env.SENDER_EMAIL_PASSWORD,
        },
    });

    const mailOptions = {
        from: process.env.SENDER_EMAIL,
        to: email,
        subject,
        html: htmlContent,
    };

    await transporter.sendMail(mailOptions);
};

export const login = async (req, res) => {
    try {
        const auth_token = 'auth_token';
        const { email, password } = req.body;

        if (!email || !password) return res.status(400).json({ message: 'make sure to provide all fields (email, password)', success: false });

        if (!validator.isEmail(email)) return res.status(400).json({ message: 'Invalid email format', success: false });

        const existingUser = await User.findOne({ email });
        if (!existingUser) return res.status(400).json({ message: 'Invalid Credentials', success: false });

        // Check if the user account is locked
        if (existingUser.isLocked) {
            const now = new Date();
            if (now < existingUser.lockUntil) {
                return res.status(403).json({ message: 'Account is locked. Please try again later.' });
            } else {
                // Unlock the account after cooldown period
                existingUser.isLocked = false;
                existingUser.failedLoginAttempts = 0;
                existingUser.lockUntil = null;
                await existingUser.save();
            }
        }

        // Check password
        const isPasswordCorrect = await bcrypt.compare(password, existingUser.password);
        if (!isPasswordCorrect) {
            existingUser.failedLoginAttempts += 1;

            // Lock account if max attempts reached
            if (existingUser.failedLoginAttempts >= MAX_FAILED_ATTEMPTS) {
                existingUser.isLocked = true;
                existingUser.lockUntil = new Date(Date.now() + LOCKOUT_DURATION);
            }

            await existingUser.save();
            return res.status(400).json({ message: 'Invalid Credentials', success: false });
        }

        // Reset failed attempts on successful login
        existingUser.failedLoginAttempts = 0;
        existingUser.lockUntil = null;
        existingUser.isLocked = false;
        await existingUser.save();

        // Generate auth token
        const token = jwt.sign({ email, _id: existingUser._id }, process.env.AUTH_TOKEN_SECRET_KEY);
        const tokenObj = { name: auth_token, token };
        existingUser.tokens.push(tokenObj);
        await User.findByIdAndUpdate(existingUser._id, existingUser, { new: true });

        res.status(200).json({ result: existingUser, message: 'login successfully', success: true });
    } catch (error) {
        res.status(404).json({ message: 'login failed - controllers/user.js', error, success: false });
    }
};

export const getAllUsers = async (req, res) => {
    try {
        const result = await User.find();
        res.status(200).json({ result, message: 'All users retrieved successfully', success: true });
    } catch (error) {
        res.status(404).json({ message: 'Error in getAllUsers - controllers/user.js', error, success: false });
    }
};

export const sendRegisterOTP = async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) return res.status(400).json({ message: 'Email field is required', success: false });
        if (!validator.isEmail(email)) return res.status(400).json({ message: 'Invalid email format', success: false });

        const isEmailAlreadyRegistered = await User.findOne({ email });
        if (isEmailAlreadyRegistered) return res.status(400).json({ message: `User with email ${email} is already registered`, success: false });

        const otp = otpGenerator.generate(6, { digits: true, lowerCaseAlphabets: false, upperCaseAlphabets: false, specialChars: false });
        const hashedOTP = await bcrypt.hash(otp, 12);
        await OTP.create({ email, otp: hashedOTP, name: 'register_otp' });

        await sendEmail(email, 'Verification', `<p>Your OTP code is ${otp}</p>`);

        res.status(200).json({ message: 'Register OTP sent successfully', success: true });
    } catch (error) {
        res.status(404).json({ message: 'Error in sendRegisterOTP - controllers/user.js', error, success: false });
    }
};

export const register = async (req, res) => {
    try {
        const { name, email, password, otp } = req.body;

        if (!name || !email || !password || !otp) return res.status(400).json({ message: 'All fields (name, email, password, otp) are required', success: false });
        if (!validator.isEmail(email)) return res.status(400).json({ message: 'Invalid email format', success: false });

        const isEmailAlreadyRegistered = await User.findOne({ email });
        if (isEmailAlreadyRegistered) return res.status(400).json({ message: `User with email ${email} is already registered`, success: false });

        const otpHolder = await OTP.find({ email });
        if (otpHolder.length === 0) return res.status(400).json({ message: 'Expired OTP entered', success: false });

        const registerOtps = otpHolder.filter(otp => otp.name === 'register_otp');
        const latestOTP = registerOtps[registerOtps.length - 1];

        const isValidOTP = await bcrypt.compare(otp, latestOTP.otp);
        if (isValidOTP) {
            const hashedPassword = await bcrypt.hash(password, 12);
            const newUser = new User({ name, email, password: hashedPassword });

            await newUser.generateAuthToken();
            await OTP.deleteMany({ email: latestOTP.email });
            await newUser.save();

            res.status(200).json({ result: newUser, message: 'Registration successful', success: true });
        } else {
            res.status(400).json({ message: 'Invalid OTP', success: false });
        }
    } catch (error) {
        res.status(404).json({ message: 'Error in register - controllers/user.js', error, success: false });
    }
};

export const sendForgetPasswordOTP = async (req, res) => {
    try {
        const { email } = req.body;

        const existingUser = await User.findOne({ email });
        if (!existingUser) return res.status(400).json({ message: `No user exists with email ${email}`, success: false });
        if (!validator.isEmail(email)) return res.status(400).json({ message: 'Invalid email format', success: false });

        const otp = otpGenerator.generate(6, { digits: true, lowerCaseAlphabets: false, upperCaseAlphabets: false, specialChars: false });
        const hashedOTP = await bcrypt.hash(otp, 12);
        await OTP.create({ email, otp: hashedOTP, name: 'forget_password_otp' });

        await sendEmail(email, 'Verification', `<p>Your OTP code is ${otp}</p>`);

        res.status(200).json({ message: 'Forget password OTP sent successfully', success: true });
    } catch (error) {
        res.status(404).json({ message: 'Error in sendForgetPasswordOTP - controllers/user.js', error, success: false });
    }
};

export const changePassword = async (req, res) => {
    try {
        const { email, password, otp } = req.body;

        if (!email || !password || !otp) return res.status(400).json({ message: 'All fields (email, password, otp) are required', success: false });
        if (!validator.isEmail(email)) return res.status(400).json({ message: 'Invalid email format', success: false });

        const existingUser = await User.findOne({ email });
        if (!existingUser) return res.status(400).json({ message: `User with email ${email} does not exist`, success: false });

        const otpHolder = await OTP.find({ email });
        if (otpHolder.length === 0) return res.status(400).json({ message: 'Expired OTP entered', success: false });

        const changePasswordOtps = otpHolder.filter(otp => otp.name === 'forget_password_otp');
        const latestOTP = changePasswordOtps[changePasswordOtps.length - 1];

        const isValidOTP = await bcrypt.compare(otp, latestOTP.otp);
        if (isValidOTP) {
            const hashedPassword = await bcrypt.hash(password, 12);
            existingUser.password = hashedPassword;

            await OTP.deleteMany({ email: latestOTP.email });
            await existingUser.save();

            res.status(200).json({ message: 'Password changed successfully', success: true });
        } else {
            res.status(400).json({ message: 'Invalid OTP', success: false });
        }
    } catch (error) {
        res.status(404).json({ message: 'Error in changePassword - controllers/user.js', error, success: false });
    }
};

export const deleteAllUsers = async (req, res) => {
    try {
        await User.deleteMany({});
        res.status(200).json({ message: 'All users deleted successfully', success: true });
    } catch (error) {
        res.status(404).json({ message: 'Error in deleteAllUsers - controllers/user.js', error, success: false });
    }
};
