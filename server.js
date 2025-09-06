const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const path = require('path');
const crypto = require('crypto');

require('dotenv').config();

const app = express();

const PORT = process.env.PORT || 3000;

// Correct CORS configuration
const corsOptions = {
    origin: 'http://127.0.0.1:5500', 
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type'],
};
app.use(cors(corsOptions));


app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, 'public')));

// New route to serve the main signup page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'signup', 'signup.html'));
});


const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const EMAIL_USERNAME = process.env.EMAIL_USERNAME;
const EMAIL_PASSWORD = process.env.EMAIL_PASSWORD;

if (!EMAIL_PASSWORD || !EMAIL_USERNAME) {
    console.error('Missing EMAIL_USERNAME or EMAIL_PASSWORD environment variables.');
    process.exit(1);
}

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: EMAIL_USERNAME,
        pass: EMAIL_PASSWORD,
    },
});

mongoose.connect(MONGODB_URI)
    .then(() => console.log('Connected to MongoDB Atlas database'))
    .catch(err => console.error('Database connection error:', err));

const userInfoSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isVerified: { type: Boolean, default: false },
    verificationToken: String,
    verificationTokenExpires: Date,
});

const UserInfo = mongoose.model('userINFO', userInfoSchema);


const sendVerificationEmail = async (email, code) => {
    const mailOptions = {
        from: EMAIL_USERNAME,
        to: email,
        subject: 'Saddman Academy - Your Verification Code',
        html: `
            <div style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px; text-align: center;">
                <div style="background-color: #fff; max-width: 600px; margin: auto; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1);">
                    <h2 style="color: #333;">Email Verification</h2>
                    <p style="color: #666;">Thank you for signing up with Saddman Academy. To complete your registration, please use the following verification code:</p>
                    <div style="background-color: #00d3ff; color: #fff; padding: 15px; border-radius: 5px; font-size: 24px; font-weight: bold; letter-spacing: 5px; display: inline-block; margin: 20px 0;">
                        ${code}
                    </div>
                    <p style="color: #666;">This code is valid for 1 hour. If you did not request this, please ignore this email.</p>
                    <p style="color: #666; font-size: 12px; margin-top: 30px;">&copy; 2025 Saddman Academy. All rights reserved.</p>
                </div>
            </div>
        `,
    };
    await transporter.sendMail(mailOptions);
};

// API Endpoints
app.post('/signup', async (req, res) => {
    const { username, email, password } = req.body;

    // Password matching is handled on the client-side
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'All fields are required.' });
    }

    try {
        const existingUser = await UserInfo.findOne({ $or: [{ username }, { email }] });
        if (existingUser) {
            return res.status(409).json({ error: 'Username or email already exists.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new UserInfo({ username, email, password: hashedPassword, isVerified: false });
        
        const verificationCode = crypto.randomInt(100000, 999999).toString();
        newUser.verificationToken = verificationCode;
        newUser.verificationTokenExpires = Date.now() + 3600000; // 1 hour expiration

        await newUser.save();

        await sendVerificationEmail(newUser.email, verificationCode);

        res.status(201).json({
            message: 'User registered successfully! A verification code has been sent to your email.',
            email: newUser.email,
            redirect: '/verification/verification.html'
        });

    } catch (err) {
        console.error('Error occurred during signup:', err);
        res.status(500).json({ error: 'Error registering user.' });
    }
});

app.post('/verification', async (req, res) => {
    const { email, code } = req.body;

    if (!email || !code) {
        return res.status(400).json({ error: 'Email and code are required.' });
    }

    try {
        const user = await UserInfo.findOne({ email });

        if (!user) {
            return res.status(400).json({ error: 'Invalid email or code.' });
        }

        if (user.verificationToken !== code) {
            return res.status(400).json({ error: 'Invalid verification code.' });
        }

        if (user.verificationTokenExpires < Date.now()) {
            return res.status(400).json({ error: 'Verification code has expired. Please request a new one.' });
        }

        user.isVerified = true;
        user.verificationToken = undefined;
        user.verificationTokenExpires = undefined;
        await user.save();

        res.status(200).json({ message: 'Account verified successfully!', redirect: '/login/login.html?verified=true' });
    } catch (err) {
        console.error('Error during code verification:', err);
        res.status(500).json({ error: 'Error verifying code.' });
    }
});

app.post('/resend-code', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ error: 'Email is required to resend the code.' });
    }

    try {
        const user = await UserInfo.findOne({ email });
        if (!user) {
            return res.status(400).json({ error: 'User not found.' });
        }
        if (user.isVerified) {
            return res.status(400).json({ message: 'Account is already verified.' });
        }

        const newVerificationCode = crypto.randomInt(100000, 999999).toString();
        user.verificationToken = newVerificationCode;
        user.verificationTokenExpires = Date.now() + 3600000;

        await user.save();

        await sendVerificationEmail(user.email, newVerificationCode);

        res.status(200).json({ message: 'A new verification code has been sent to your email.' });
    } catch (err) {
        console.error('Error in resend-code:', err);
        res.status(500).json({ error: 'Error processing request.' });
    }
});


app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'All fields are required.' });
    }

    try {
        const user = await UserInfo.findOne({ username });

        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }

        if (!user.isVerified) {
            // If user is not verified, resend code and prompt them to verify
            const newVerificationCode = crypto.randomInt(100000, 999999).toString();
            user.verificationToken = newVerificationCode;
            user.verificationTokenExpires = Date.now() + 3600000;
            await user.save();
            await sendVerificationEmail(user.email, newVerificationCode);

            return res.status(403).json({ error: 'Please verify your email first. A new code has been sent.', redirect: '/verification/verification.html' });
        }

        const isPasswordMatch = await bcrypt.compare(password, user.password);
        if (isPasswordMatch) {
            res.status(200).json({
                message: 'Login successful!',
                email: user.email,
                redirect: '/dashboard/dashboard.html'
            });
        } else {
            res.status(401).json({ error: 'Invalid credentials.' });
        }
    } catch (err) {
        console.error('Error occurred during login:', err);
        res.status(500).json({ error: 'Error logging in.' });
    }
});


app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});