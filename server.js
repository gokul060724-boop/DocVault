
 
require("dotenv").config();
 
const express = require("express");
const path = require("path");
const nodemailer = require("nodemailer");
const session = require("express-session");
const bcrypt = require("bcrypt");
const multer = require("multer");
const crypto = require("crypto");
const QRCode = require("qrcode");
 
const {
    MongoClient,
    GridFSBucket,
    ObjectId
} = require("mongodb");
 
const app = express();
const PORT = process.env.PORT || 3000;
 
// ==========================================
// BASIC SETUP
// ==========================================
 
app.use(express.json());
 
app.use(express.urlencoded({
    extended: true
}));
 
app.use(session({
    secret:
        process.env.SESSION_SECRET ||
        "docvault-secret",
 
    resave: false,
 
    saveUninitialized: false,
 
    cookie: {
        httpOnly: true,
        sameSite: "lax",
        secure: false,
        maxAge: 30 * 60 * 1000
    }
}));
 
app.use(express.static(__dirname));
 
// ==========================================
// PAGE ROUTES
// ==========================================
 
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});
 
[
    "index.html",
    "login.html",
    "register.html",
    "dashboard.html",
    "forgot-password.html",
    "create-pin.html",
    "create-password.html",
    "viewer-login.html",
    "viewer.html"
].forEach((file) => {
    app.get(`/${file}`, (req, res) => {
        res.sendFile(path.join(__dirname, file));
    });
});
 
// ==========================================
// MONGODB
// ==========================================
 
const client = new MongoClient(
    process.env.MONGODB_URI
);
 
let db;
let users;
let documents;
let bucket;
 
async function connectMongoDB() {
 
    await client.connect();
 
    db = client.db("docvault");
 
    users = db.collection("users");
 
    documents = db.collection("documents");
 
    bucket = new GridFSBucket(
        db,
        {
            bucketName: "documents"
        }
    );
 
    console.log(
        "MongoDB connected successfully."
    );
}
 
// ==========================================
// GMAIL
// ==========================================
 
const transporter =
    nodemailer.createTransport({
 
        service: "gmail",
 
        auth: {
            user:
                process.env.GMAIL_USER,
 
            pass:
                process.env.GMAIL_APP_PASSWORD
        }
    });
 
// ==========================================
// OTP STORE
// ==========================================
 
const otpStore = new Map();
 
// ==========================================
// MULTER
// ==========================================
 
const upload = multer({
 
    storage:
        multer.memoryStorage(),
 
    limits: {
        fileSize:
            10 * 1024 * 1024
    },
 
    fileFilter:
        (req, file, cb) => {
 
            const allowed = [
 
                "application/pdf",
 
                "image/jpeg",
 
                "image/png"
 
            ];
 
            if (
                allowed.includes(
                    file.mimetype
                )
            ) {
 
                cb(
                    null,
                    true
                );
 
            } else {
 
                cb(
                    new Error(
                        "Only PDF, JPG and PNG files are allowed."
                    )
                );
            }
        }
});
 
// ==========================================
// HELPERS
// ==========================================
 
function cleanEmail(email) {
 
    return String(
        email || ""
    )
        .trim()
        .toLowerCase();
}
 
 
function requireLogin(
    req,
    res,
    next
) {
 
    if (
        !req.session.userEmail
    ) {
 
        return res
            .status(401)
            .json({
 
                success: false,
 
                message:
                    "Please sign in first."
            });
    }
 
    next();
}
 
 
// ==========================================
// SEND OTP
// ==========================================
 
app.post(
    "/api/send-otp",
    async (req, res) => {
 
        try {
 
            const email =
                cleanEmail(
                    req.body.email
                );
 
 
            if (!email) {
 
                return res
                    .status(400)
                    .json({
 
                        success: false,
 
                        message:
                            "Gmail address is required."
                    });
            }
 
 
            if (
                !email.endsWith(
                    "@gmail.com"
                )
            ) {
 
                return res
                    .status(400)
                    .json({
 
                        success: false,
 
                        message:
                            "Please enter a valid Gmail address."
                    });
            }
 
 
            const existing =
                await users.findOne({
                    email
                });
 
 
            if (existing) {
 
                return res
                    .status(409)
                    .json({
 
                        success: false,
 
                        message:
                            "Account already exists. Please Sign In."
                    });
            }
 
 
            const otp =
                crypto
                    .randomInt(
                        100000,
                        1000000
                    )
                    .toString();
 
 
            otpStore.set(
                email,
                {
                    otp,
 
                    expires:
                        Date.now() +
                        5 * 60 * 1000
                }
            );
 
 
            await transporter.sendMail({
 
                from:
                    `"DocVault" <${process.env.GMAIL_USER}>`,
 
                to:
                    email,
 
                subject:
                    "DocVault - Email Verification OTP",
 
                text:
                    `Your DocVault verification OTP is ${otp}. ` +
                    `This OTP will expire in 5 minutes.`
            });
 
 
            res.json({
 
                success: true,
 
                message:
                    "OTP sent successfully."
            });
 
 
        } catch (error) {
 
            console.error(
                "SEND OTP ERROR:",
                error
            );
 
 
            res
                .status(500)
                .json({
 
                    success: false,
 
                    message:
                        "Unable to send OTP."
                });
        }
    }
);
 
 
// ==========================================
// VERIFY OTP
// ==========================================
 
app.post(
    "/api/verify-otp",
    (req, res) => {
 
        const email =
            cleanEmail(
                req.body.email
            );
 
        const otp =
            String(
                req.body.otp || ""
            ).trim();
 
 
        const saved =
            otpStore.get(
                email
            );
 
 
        if (!saved) {
 
            return res
                .status(400)
                .json({
 
                    success: false,
 
                    message:
                        "OTP not found. Please request a new OTP."
                });
        }
 
 
        if (
            Date.now() >
            saved.expires
        ) {
 
            otpStore.delete(
                email
            );
 
            return res
                .status(400)
                .json({
 
                    success: false,
 
                    message:
                        "OTP expired."
                });
        }
 
 
        if (
            saved.otp !== otp
        ) {
 
            return res
                .status(400)
                .json({
 
                    success: false,
 
                    message:
                        "Incorrect OTP."
                });
        }
 
 
        otpStore.delete(
            email
        );
 
 
        req.session.verifiedEmail =
            email;
 
 
        res.json({
 
            success: true,
 
            message:
                "Email verified successfully."
        });
    }
);
 
 
// ==========================================
// CREATE ACCOUNT
// ==========================================
 
app.post(
    "/api/create-account",
    async (req, res) => {
 
        try {
 
            const ownerName =
                String(
                    req.body.ownerName || ""
                ).trim();
 
            const email =
                cleanEmail(
                    req.body.email
                );
 
 
            const password =
                String(
                    req.body.password || ""
                );
 
 
            const securityPin =
                String(
                    req.body.securityPin ||
                    req.body.pin ||
                    ""
                );
 
 
            if (
                !ownerName ||
                ownerName.length < 2
            ) {
 
                return res
                    .status(400)
                    .json({
 
                        success: false,
 
                        message:
                            "Owner Name must contain at least 2 characters."
                    });
            }
 
 
            if (
                req.session.verifiedEmail !==
                email
            ) {
 
                return res
                    .status(403)
                    .json({
 
                        success: false,
 
                        message:
                            "Please verify your Gmail first."
                    });
            }
 
 
            if (
                password.length < 8
            ) {
 
                return res
                    .status(400)
                    .json({
 
                        success: false,
 
                        message:
                            "Password must be at least 8 characters."
                    });
            }
 
 
            if (
                !/^\d{6}$/.test(
                    securityPin
                )
            ) {
 
                return res
                    .status(400)
                    .json({
 
                        success: false,
 
                        message:
                            "Security PIN must contain exactly 6 digits."
                    });
            }
 
 
            const existing =
                await users.findOne({
                    email
                });
 
 
            if (existing) {
 
                return res
                    .status(409)
                    .json({
 
                        success: false,
 
                        message:
                            "Account already exists. Please Sign In."
                    });
            }
 
 
            const passwordHash =
                await bcrypt.hash(
                    password,
                    12
                );
 
 
            const securityPinHash =
                await bcrypt.hash(
                    securityPin,
                    12
                );
 
 
            const vaultId =
                crypto
                    .randomBytes(
                        16
                    )
                    .toString(
                        "hex"
                    );
 
 
            await users.insertOne({
 
                ownerName,
 
                email,
 
                passwordHash,
 
                securityPinHash,
 
                vaultId,
 
                permanentQrToken:
                    null,
 
                createdAt:
                    new Date()
            });
 
 
            delete
                req.session
                    .verifiedEmail;
 
 
            req.session.userEmail =
                email;
 
 
            res.json({
 
                success: true,
 
                message:
                    "Account created successfully."
            });
 
 
        } catch (error) {
 
            console.error(
                "CREATE ACCOUNT ERROR:",
                error
            );
 
 
            res
                .status(500)
                .json({
 
                    success: false,
 
                    message:
                        "Unable to create account."
                });
        }
    }
);
 
 
// ==========================================
// NORMAL LOGIN
// ==========================================
 
app.post(
    "/api/login",
    async (req, res) => {
 
        try {
 
            const email =
                cleanEmail(
                    req.body.email
                );
 
 
            const password =
                String(
                    req.body.password || ""
                );
 
 
            if (
                !email ||
                !password
            ) {
 
                return res
                    .status(400)
                    .json({
 
                        success: false,
 
                        message:
                            "Gmail and password are required."
                    });
            }
 
 
            const user =
                await users.findOne({
                    email
                });
 
 
            if (!user) {
 
                return res
                    .status(401)
                    .json({
 
                        success: false,
 
                        message:
                            "Invalid Gmail or password."
                    });
            }
 
 
            const correct =
                await bcrypt.compare(
                    password,
                    user.passwordHash
                );
 
 
            if (!correct) {
 
                return res
                    .status(401)
                    .json({
 
                        success: false,
 
                        message:
                            "Invalid Gmail or password."
                    });
            }
 
 
            req.session.userEmail =
                email;
 
 
            res.json({
 
                success: true,
 
                message:
                    "Login successful."
            });
 
 
        } catch (error) {
 
            console.error(
                "LOGIN ERROR:",
                error
            );
 
 
            res
                .status(500)
                .json({
 
                    success: false,
 
                    message:
                        "Unable to login."
                });
        }
    }
);
 
 
// ==========================================
// CURRENT USER
// ==========================================
 
app.get(
    "/api/me",
    async (req, res) => {
 
        try {
 
            if (
                !req.session.userEmail
            ) {
 
                return res.json({
 
                    success: false,
 
                    loggedIn: false
                });
            }
 
 
            const user =
                await users.findOne({
 
                    email:
                        req.session.userEmail
                });
 
 
            if (!user) {
 
                req.session.destroy(
                    () => {}
                );
 
 
                return res.json({
 
                    success: false,
 
                    loggedIn: false
                });
            }
 
 
            res.json({
 
                success: true,
 
                loggedIn: true,
 
                ownerName:
                    user.ownerName ||
                    "Owner",
 
                email:
                    user.email,
 
                vaultId:
                    user.vaultId
            });
 
 
        } catch (error) {
 
            console.error(
                "ME ERROR:",
                error
            );
 
 
            res
                .status(500)
                .json({
 
                    success: false,
 
                    message:
                        "Unable to check login."
                });
        }
    }
);
 
 
// ==========================================
// LOGOUT
// ==========================================
 
app.post(
    "/api/logout",
    (req, res) => {
 
        req.session.destroy(
            () => {
 
                res.json({
                    success: true
                });
            }
        );
    }
);
// ==========================================
// UPLOAD DOCUMENT
// ==========================================
 
app.post(
    "/api/documents",
    requireLogin,
    upload.single("document"),
    async (req, res) => {
 
        try {
 
            if (!req.file) {
 
                return res.status(400).json({
                    success: false,
                    message:
                        "Please select a PDF or image."
                });
            }
 
            const name =
                String(
                    req.body.name || ""
                ).trim();
 
            if (!name) {
 
                return res.status(400).json({
                    success: false,
                    message:
                        "Document name is required."
                });
            }
 
            const user =
                await users.findOne({
                    email:
                        req.session.userEmail
                });
 
            if (!user) {
 
                return res.status(401).json({
                    success: false,
                    message:
                        "User account not found."
                });
            }
 
            // Prevent duplicate document names inside the owner's vault.
            // Comparison is case-insensitive and ignores surrounding whitespace.
            const normalizedName = name.trim().toLowerCase();
 
            const duplicateDocument =
                await documents.findOne({
                    vaultId: user.vaultId,
                    $expr: {
                        $eq: [
                            {
                                $toLower: {
                                    $trim: {
                                        input: "$name"
                                    }
                                }
                            },
                            normalizedName
                        ]
                    }
                });
 
            if (duplicateDocument) {
 
                return res.status(409).json({
 
                    success: false,
 
                    message:
                        "Document name already exists. Please choose a different name."
                });
            }
 
 
            const fileId =
                new ObjectId();
 
            const stream =
                bucket.openUploadStream(
                    req.file.originalname,
                    {
                        id: fileId,
 
                        metadata: {
                            ownerEmail:
                                user.email,
 
                            vaultId:
                                user.vaultId,
 
                            contentType:
                                req.file.mimetype
                        }
                    }
                );
 
            await new Promise(
                (resolve, reject) => {
 
                    stream.on(
                        "finish",
                        resolve
                    );
 
                    stream.on(
                        "error",
                        reject
                    );
 
                    stream.end(
                        req.file.buffer
                    );
                }
            );
 
            const documentId =
                crypto
                    .randomBytes(16)
                    .toString("hex");
 
            await documents.insertOne({
 
                id:
                    documentId,
 
                ownerEmail:
                    user.email,
 
                vaultId:
                    user.vaultId,
 
                name,
 
                originalName:
                    req.file.originalname,
 
                fileType:
                    req.file.mimetype,
 
                size:
                    req.file.size,
 
                fileId,
 
                createdAt:
                    new Date()
            });
 
            res.json({
 
                success: true,
 
                message:
                    "Document uploaded successfully.",
 
                document: {
 
                    id:
                        documentId,
 
                    name,
 
                    fileType:
                        req.file.mimetype,
 
                    size:
                        req.file.size
                }
            });
 
        } catch (error) {
 
            console.error(
                "UPLOAD ERROR:",
                error
            );
 
            res.status(500).json({
 
                success: false,
 
                message:
                    "Unable to upload document."
            });
        }
    }
);
 
 
// ==========================================
// GET MY DOCUMENTS
// ==========================================
 
app.get(
    "/api/documents",
    requireLogin,
    async (req, res) => {
 
        try {
 
            const user =
                await users.findOne({
                    email:
                        req.session.userEmail
                });
 
            if (!user) {
 
                return res.status(401).json({
 
                    success: false,
 
                    message:
                        "User account not found."
                });
            }
 
            const list =
                await documents
                    .find({
                        vaultId:
                            user.vaultId
                    })
                    .project({
 
                        _id: 0,
 
                        id: 1,
 
                        name: 1,
 
                        originalName: 1,
 
                        fileType: 1,
 
                        size: 1,
 
                        createdAt: 1
                    })
                    .sort({
                        createdAt: -1
                    })
                    .toArray();
 
            res.json({
 
                success: true,
 
                documents:
                    list
            });
 
        } catch (error) {
 
            console.error(
                "GET DOCUMENTS ERROR:",
                error
            );
 
            res.status(500).json({
 
                success: false,
 
                message:
                    "Unable to load documents."
            });
        }
    }
);
 
 
// ==========================================
// FIND OWNER DOCUMENT
// ==========================================
 
async function getMyDocument(
    req,
    documentId
) {
 
    const user =
        await users.findOne({
            email:
                req.session.userEmail
        });
 
    if (!user) {
 
        return null;
    }
 
    return documents.findOne({
 
        id:
            documentId,
 
        vaultId:
            user.vaultId
    });
}
 
 
// ==========================================
// OWNER VIEW DOCUMENT
// ==========================================
 
app.get(
    "/api/documents/:id/view",
    requireLogin,
    async (req, res) => {
 
        try {
 
            const document =
                await getMyDocument(
                    req,
                    req.params.id
                );
 
            if (!document) {
 
                return res
                    .status(404)
                    .send(
                        "Document not found."
                    );
            }
 
            res.setHeader(
                "Content-Type",
                document.fileType
            );
 
            res.setHeader(
                "Content-Disposition",
                `inline; filename="${encodeURIComponent(
                    document.originalName
                )}"`
            );
 
            bucket
                .openDownloadStream(
                    document.fileId
                )
                .pipe(res);
 
        } catch (error) {
 
            console.error(
                "VIEW ERROR:",
                error
            );
 
            res
                .status(500)
                .send(
                    "Unable to view document."
                );
        }
    }
);
 
 
// ==========================================
// OWNER DOWNLOAD DOCUMENT
// ==========================================
 
app.get(
    "/api/documents/:id/download",
    requireLogin,
    async (req, res) => {
 
        try {
 
            const document =
                await getMyDocument(
                    req,
                    req.params.id
                );
 
            if (!document) {
 
                return res
                    .status(404)
                    .send(
                        "Document not found."
                    );
            }
 
            res.setHeader(
                "Content-Type",
                document.fileType
            );
 
            res.setHeader(
                "Content-Disposition",
                `attachment; filename="${encodeURIComponent(
                    document.originalName
                )}"`
            );
 
            bucket
                .openDownloadStream(
                    document.fileId
                )
                .pipe(res);
 
        } catch (error) {
 
            console.error(
                "DOWNLOAD ERROR:",
                error
            );
 
            res
                .status(500)
                .send(
                    "Unable to download document."
                );
        }
    }
);
 
 
app.post("/api/recovery/send-otp", async (req, res) => {
 
 
 
 
 
 
 
    try {
 
 
 
 
 
 
 
        const email = cleanEmail(req.body.email);
 
 
 
 
 
 
 
        const type = String(req.body.type || "").trim();
 
 
 
 
 
 
 
 
 
 
 
        if (!email || !email.endsWith("@gmail.com")) {
 
 
 
 
 
 
 
            return res.status(400).json({
 
 
 
 
 
 
 
                success: false,
 
 
 
 
 
 
 
                message: "Please enter a valid Gmail address."
 
 
 
 
 
 
 
            });
 
 
 
 
 
 
 
        }
 
 
 
 
 
 
 
 
 
 
 
        if (!["pin", "password"].includes(type)) {
 
 
 
 
 
 
 
            return res.status(400).json({
 
 
 
 
 
 
 
                success: false,
 
 
 
 
 
 
 
                message: "Invalid recovery type."
 
 
 
 
 
 
 
            });
 
 
 
 
 
 
 
        }
 
 
 
 
 
 
 
 
 
 
 
        const user = await users.findOne({ email });
 
 
 
 
 
 
 
 
 
 
 
        if (!user) {
 
 
 
 
 
 
 
            return res.status(404).json({
 
 
 
 
 
 
 
                success: false,
 
 
 
 
 
 
 
                message: "No DocVault account found for this Gmail."
 
 
 
 
 
 
 
            });
 
 
 
 
 
 
 
        }
 
 
 
 
 
 
 
 
 
 
 
        const otp = crypto
 
 
 
 
 
 
 
            .randomInt(100000, 1000000)
 
 
 
 
 
 
 
            .toString();
 
 
 
 
 
 
 
 
 
 
 
        const key = `recovery:${type}:${email}`;
 
 
 
 
 
 
 
 
 
 
 
        otpStore.set(key, {
 
 
 
 
 
 
 
            otp,
 
 
 
 
 
 
 
            expires: Date.now() + 5 * 60 * 1000
 
 
 
 
 
 
 
        });
 
 
 
 
 
 
 
 
 
 
 
        await transporter.sendMail({
 
 
 
 
 
 
 
            from: `"DocVault" <${process.env.GMAIL_USER}>`,
 
 
 
 
 
 
 
            to: email,
 
 
 
 
 
 
 
            subject:
 
 
 
 
 
 
 
                type === "pin"
 
 
 
 
 
 
 
                    ? "DocVault - Security PIN Recovery OTP"
 
 
 
 
 
 
 
                    : "DocVault - Password Recovery OTP",
 
 
 
 
 
 
 
            text:
 
 
 
 
 
 
 
                `Your DocVault ${type === "pin" ? "Security PIN" : "Password"} recovery OTP is ${otp}. ` +
 
 
 
 
 
 
 
                `This OTP will expire in 5 minutes.`
 
 
 
 
 
 
 
        });
 
 
 
 
 
 
 
 
 
 
 
        return res.json({
 
 
 
 
 
 
 
            success: true,
 
 
 
 
 
 
 
            message: "Verification code sent successfully."
 
 
 
 
 
 
 
        });
 
 
 
 
 
 
 
 
 
 
 
    } catch (error) {
 
 
 
 
 
 
 
        console.error("RECOVERY SEND OTP ERROR:", error);
 
 
 
 
 
 
 
 
 
 
 
        return res.status(500).json({
 
 
 
 
 
 
 
            success: false,
 
 
 
 
 
 
 
            message: "Unable to send recovery code."
 
 
 
 
 
 
 
        });
 
 
 
 
 
 
 
    }
 
 
 
 
 
 
 
});
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
// ==========================================
 
 
 
 
 
 
 
// VERIFY RECOVERY OTP
 
 
 
 
 
 
 
// ==========================================
 
 
 
 
 
 
 
 
 
 
 
app.post("/api/recovery/verify-otp", async (req, res) => {
 
 
 
 
 
 
 
    try {
 
 
 
 
 
 
 
        const email = cleanEmail(req.body.email);
 
 
 
 
 
 
 
        const otp = String(req.body.otp || "").trim();
 
 
 
 
 
 
 
        const type = String(req.body.type || "").trim();
 
 
 
 
 
 
 
 
 
 
 
        if (!email || !otp) {
 
 
 
 
 
 
 
            return res.status(400).json({
 
 
 
 
 
 
 
                success: false,
 
 
 
 
 
 
 
                message: "Email and verification code are required."
 
 
 
 
 
 
 
            });
 
 
 
 
 
 
 
        }
 
 
 
 
 
 
 
 
 
 
 
        if (!["pin", "password"].includes(type)) {
 
 
 
 
 
 
 
            return res.status(400).json({
 
 
 
 
 
 
 
                success: false,
 
 
 
 
 
 
 
                message: "Invalid recovery type."
 
 
 
 
 
 
 
            });
 
 
 
 
 
 
 
        }
 
 
 
 
 
 
 
 
 
 
 
        const key = `recovery:${type}:${email}`;
 
 
 
 
 
 
 
        const saved = otpStore.get(key);
 
 
 
 
 
 
 
 
 
 
 
        if (!saved) {
 
 
 
 
 
 
 
            return res.status(400).json({
 
 
 
 
 
 
 
                success: false,
 
 
 
 
 
 
 
                message:
 
 
 
 
 
 
 
                    "Verification code not found. Please request a new code."
 
 
 
 
 
 
 
            });
 
 
 
 
 
 
 
        }
 
 
 
 
 
 
 
 
 
 
 
        if (Date.now() > saved.expires) {
 
 
 
 
 
 
 
            otpStore.delete(key);
 
 
 
 
 
 
 
 
 
 
 
            return res.status(400).json({
 
 
 
 
 
 
 
                success: false,
 
 
 
 
 
 
 
                message: "Verification code expired."
 
 
 
 
 
 
 
            });
 
 
 
 
 
 
 
        }
 
 
 
 
 
 
 
 
 
 
 
        if (saved.otp !== otp) {
 
 
 
 
 
 
 
            return res.status(400).json({
 
 
 
 
 
 
 
                success: false,
 
 
 
 
 
 
 
                message: "Incorrect verification code."
 
 
 
 
 
 
 
            });
 
 
 
 
 
 
 
        }
 
 
 
 
 
 
 
 
 
 
 
        otpStore.delete(key);
 
 
 
 
 
 
 
 
 
 
 
        req.session.recoveryVerified = {
 
 
 
 
 
 
 
            email,
 
 
 
 
 
 
 
            type,
 
 
 
 
 
 
 
            expires: Date.now() + 10 * 60 * 1000
 
 
 
 
 
 
 
        };
 
 
 
 
 
 
 
 
 
 
 
        return res.json({
 
 
 
 
 
 
 
            success: true,
 
 
 
 
 
 
 
            message: "Verification successful."
 
 
 
 
 
 
 
        });
 
 
 
 
 
 
 
 
 
 
 
    } catch (error) {
 
 
 
 
 
 
 
        console.error("RECOVERY VERIFY OTP ERROR:", error);
 
 
 
 
 
 
 
 
 
 
 
        return res.status(500).json({
 
 
 
 
 
 
 
            success: false,
 
 
 
 
 
 
 
            message: "Unable to verify recovery code."
 
 
 
 
 
 
 
        });
 
 
 
 
 
 
 
    }
 
 
 
 
 
 
 
});
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
// ==========================================
 
 
 
 
 
 
 
// RESET PASSWORD
 
 
 
 
 
 
 
// ==========================================
 
 
 
 
 
 
 
 
 
 
 
app.post("/api/recovery/reset-password", async (req, res) => {
 
 
 
 
 
 
 
    try {
 
 
 
 
 
 
 
        const recovery = req.session.recoveryVerified;
 
 
 
 
 
 
 
 
 
 
 
        const newPassword = String(
 
 
 
 
 
 
 
            req.body.newPassword || ""
 
 
 
 
 
 
 
        );
 
 
 
 
 
 
 
 
 
 
 
        const confirmPassword = String(
 
 
 
 
 
 
 
            req.body.confirmPassword || ""
 
 
 
 
 
 
 
        );
 
 
 
 
 
 
 
 
 
 
 
        if (
 
 
 
 
 
 
 
            !recovery ||
 
 
 
 
 
 
 
            recovery.type !== "password" ||
 
 
 
 
 
 
 
            Date.now() > recovery.expires
 
 
 
 
 
 
 
        ) {
 
 
 
 
 
 
 
            return res.status(403).json({
 
 
 
 
 
 
 
                success: false,
 
 
 
 
 
 
 
                message:
 
 
 
 
 
 
 
                    "Recovery verification expired. Please start again."
 
 
 
 
 
 
 
            });
 
 
 
 
 
 
 
        }
 
 
 
 
 
 
 
 
 
 
 
        if (newPassword.length < 8) {
 
 
 
 
 
 
 
            return res.status(400).json({
 
 
 
 
 
 
 
                success: false,
 
 
 
 
 
 
 
                message:
 
 
 
 
 
 
 
                    "Password must contain at least 8 characters."
 
 
 
 
 
 
 
            });
 
 
 
 
 
 
 
        }
 
 
 
 
 
 
 
 
 
 
 
        if (newPassword !== confirmPassword) {
 
 
 
 
 
 
 
            return res.status(400).json({
 
 
 
 
 
 
 
                success: false,
 
 
 
 
 
 
 
                message:
 
 
 
 
 
 
 
                    "New password entries do not match."
 
 
 
 
 
 
 
            });
 
 
 
 
 
 
 
        }
 
 
 
 
 
 
 
 
 
 
 
        const user = await users.findOne({
 
 
 
 
 
 
 
            email: recovery.email
 
 
 
 
 
 
 
        });
 
 
 
 
 
 
 
 
 
 
 
        if (!user) {
 
 
 
 
 
 
 
            return res.status(404).json({
 
 
 
 
 
 
 
                success: false,
 
 
 
 
 
 
 
                message: "User account not found."
 
 
 
 
 
 
 
            });
 
 
 
 
 
 
 
        }
 
 
 
 
 
 
 
 
 
 
 
        const passwordHash =
 
 
 
 
 
 
 
            await bcrypt.hash(newPassword, 12);
 
 
 
 
 
 
 
 
 
 
 
        await users.updateOne(
 
 
 
 
 
 
 
            { email: recovery.email },
 
 
 
 
 
 
 
            {
 
 
 
 
 
 
 
                $set: {
 
 
 
 
 
 
 
                    passwordHash
 
 
 
 
 
 
 
                }
 
 
 
 
 
 
 
            }
 
 
 
 
 
 
 
        );
 
 
 
 
 
 
 
 
 
 
 
        delete req.session.recoveryVerified;
 
 
 
 
 
 
 
 
 
 
 
        return res.json({
 
 
 
 
 
 
 
            success: true,
 
 
 
 
 
 
 
            message:
 
 
 
 
 
 
 
                "Account password reset successfully."
 
 
 
 
 
 
 
        });
 
 
 
 
 
 
 
 
 
 
 
    } catch (error) {
 
 
 
 
 
 
 
        console.error("RECOVERY RESET PASSWORD ERROR:", error);
 
 
 
 
 
 
 
 
 
 
 
        return res.status(500).json({
 
 
 
 
 
 
 
            success: false,
 
 
 
 
 
 
 
            message:
 
 
 
 
 
 
 
                "Unable to reset account password."
 
 
 
 
 
 
 
        });
 
 
 
 
 
 
 
    }
 
 
 
 
 
 
 
});
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
// ==========================================
 
 
 
 
 
 
 
// RESET SECURITY PIN
 
 
 
 
 
 
 
// ==========================================
 
 
 
 
 
 
 
 
 
 
 
app.post("/api/recovery/reset-pin", async (req, res) => {
 
 
 
 
 
 
 
    try {
 
 
 
 
 
 
 
        const recovery = req.session.recoveryVerified;
 
 
 
 
 
 
 
 
 
 
 
        const newPin = String(
 
 
 
 
 
 
 
            req.body.newPin || ""
 
 
 
 
 
 
 
        ).trim();
 
 
 
 
 
 
 
 
 
 
 
        const confirmPin = String(
 
 
 
 
 
 
 
            req.body.confirmPin || ""
 
 
 
 
 
 
 
        ).trim();
 
 
 
 
 
 
 
 
 
 
 
        if (
 
 
 
 
 
 
 
            !recovery ||
 
 
 
 
 
 
 
            recovery.type !== "pin" ||
 
 
 
 
 
 
 
            Date.now() > recovery.expires
 
 
 
 
 
 
 
        ) {
 
 
 
 
 
 
 
            return res.status(403).json({
 
 
 
 
 
 
 
                success: false,
 
 
 
 
 
 
 
                message:
 
 
 
 
 
 
 
                    "Recovery verification expired. Please start again."
 
 
 
 
 
 
 
            });
 
 
 
 
 
 
 
        }
 
 
 
 
 
 
 
 
 
 
 
        if (!/^\d{6}$/.test(newPin)) {
 
 
 
 
 
 
 
            return res.status(400).json({
 
 
 
 
 
 
 
                success: false,
 
 
 
 
 
 
 
                message:
 
 
 
 
 
 
 
                    "Security PIN must contain exactly 6 digits."
 
 
 
 
 
 
 
            });
 
 
 
 
 
 
 
        }
 
 
 
 
 
 
 
 
 
 
 
        if (newPin !== confirmPin) {
 
 
 
 
 
 
 
            return res.status(400).json({
 
 
 
 
 
 
 
                success: false,
 
 
 
 
 
 
 
                message:
 
 
 
 
 
 
 
                    "New Security PIN entries do not match."
 
 
 
 
 
 
 
            });
 
 
 
 
 
 
 
        }
 
 
 
 
 
 
 
 
 
 
 
        const user = await users.findOne({
 
 
 
 
 
 
 
            email: recovery.email
 
 
 
 
 
 
 
        });
 
 
 
 
 
 
 
 
 
 
 
        if (!user) {
 
 
 
 
 
 
 
            return res.status(404).json({
 
 
 
 
 
 
 
                success: false,
 
 
 
 
 
 
 
                message: "User account not found."
 
 
 
 
 
 
 
            });
 
 
 
 
 
 
 
        }
 
 
 
 
 
 
 
 
 
 
 
        const securityPinHash =
 
 
 
 
 
 
 
            await bcrypt.hash(newPin, 12);
 
 
 
 
 
 
 
 
 
 
 
        await users.updateOne(
 
 
 
 
 
 
 
            { email: recovery.email },
 
 
 
 
 
 
 
            {
 
 
 
 
 
 
 
                $set: {
 
 
 
 
 
 
 
                    securityPinHash
 
 
 
 
 
 
 
                }
 
 
 
 
 
 
 
            }
 
 
 
 
 
 
 
        );
 
 
 
 
 
 
 
 
 
 
 
        delete req.session.recoveryVerified;
 
 
 
 
 
 
 
 
 
 
 
        return res.json({
 
 
 
 
 
 
 
            success: true,
 
 
 
 
 
 
 
            message:
 
 
 
 
 
 
 
                "Security PIN reset successfully."
 
 
 
 
 
 
 
        });
 
 
 
 
 
 
 
 
 
 
 
    } catch (error) {
 
 
 
 
 
 
 
        console.error("RECOVERY RESET PIN ERROR:", error);
 
 
 
 
 
 
 
 
 
 
 
        return res.status(500).json({
 
 
 
 
 
 
 
            success: false,
 
 
 
 
 
 
 
            message:
 
 
 
 
 
 
 
                "Unable to reset Security PIN."
 
 
 
 
 
 
 
        });
 
 
 
 
 
 
 
    }
 
 
 
 
 
 
 
});
 
 
 
 
 
 
 
 
 
// ==========================================
// PERMANENT QR
// ==========================================
 
app.get(
    "/api/permanent-qr",
    requireLogin,
    async (req, res) => {
 
        try {
 
            const email =
                cleanEmail(
                    req.session.userEmail
                );
 
            const user =
                await users.findOne({
                    email
                });
 
            if (!user) {
 
                return res.status(404).json({
 
                    success: false,
 
                    message:
                        "User not found."
                });
            }
 
            let qrToken =
                user.permanentQrToken;
 
            if (!qrToken) {
 
                qrToken =
                    crypto
                        .randomBytes(32)
                        .toString("hex");
 
                await users.updateOne(
 
                    {
                        email
                    },
 
                    {
                        $set: {
                            permanentQrToken:
                                qrToken
                        }
                    }
                );
            }
 
            const viewerUrl =
                `http://10.20.137.41:3000/viewer-login.html?token=${encodeURIComponent(
                    qrToken
                )}`;
 
            const qrImage =
                await QRCode.toDataURL(
 
                    viewerUrl,
 
                    {
                        width: 700,
 
                        margin: 3,
 
                        errorCorrectionLevel:
                            "H"
                    }
                );
 
            res.json({
 
                success: true,
 
                qrImage,
 
                viewerUrl,
 
                ownerName:
                    user.ownerName ||
                    "Owner",
 
                email:
                    user.email
            });
 
        } catch (error) {
 
            console.error(
                "PERMANENT QR ERROR:",
                error
            );
 
            res.status(500).json({
 
                success: false,
 
                message:
                    "Unable to generate permanent QR."
            });
        }
    }
);
 
 
// ==========================================
// VIEWER LOGIN
// ==========================================
 
app.post(
    "/api/viewer-login",
    async (req, res) => {
 
        try {
 
            const email =
                cleanEmail(
                    req.body.email
                );
 
            const pin =
                String(
                    req.body.pin || ""
                ).trim();
 
            const token =
                String(
                    req.body.token || ""
                ).trim();
 
 
            if (
                !/^\d{6}$/.test(pin)
            ) {
 
                return res.status(400).json({
 
                    success: false,
 
                    message:
                        "Security PIN must contain exactly 6 digits."
                });
            }
 
 
            let user = null;
 
 
            if (token) {
 
                user =
                    await users.findOne({
 
                        permanentQrToken:
                            token
                    });
 
            } else {
 
                if (!email) {
 
                    return res.status(400).json({
 
                        success: false,
 
                        message:
                            "Gmail address is required."
                    });
                }
 
                user =
                    await users.findOne({
                        email
                    });
            }
 
 
            if (!user) {
 
                return res.status(401).json({
 
                    success: false,
 
                    message:
                        "Invalid access details."
                });
            }
 
 
            if (
                !user.securityPinHash
            ) {
 
                return res.status(401).json({
 
                    success: false,
 
                    message:
                        "Security PIN is not configured."
                });
            }
 
 
            const correct =
                await bcrypt.compare(
 
                    pin,
 
                    user.securityPinHash
                );
 
 
            if (!correct) {
 
                return res.status(401).json({
 
                    success: false,
 
                    message:
                        "Invalid Security PIN."
                });
            }
 
 
            req.session.viewerVaultId =
                user.vaultId;
 
            req.session.viewerEmail =
                user.email;
 
 
            res.json({
 
                success: true,
 
                message:
                    "Access granted.",
 
                ownerName:
                    user.ownerName ||
                    "Owner"
            });
 
 
        } catch (error) {
 
            console.error(
                "VIEWER LOGIN ERROR:",
                error
            );
 
            res.status(500).json({
 
                success: false,
 
                message:
                    "Unable to verify access."
            });
        }
    }
);
 
 
// ==========================================
// VIEWER DOCUMENT LIST
// ==========================================
 
app.get(
    "/api/viewer/documents",
    async (req, res) => {
 
        try {
 
            if (
                !req.session.viewerVaultId
            ) {
 
                return res
                    .status(401)
                    .json({
 
                        success: false,
 
                        message:
                            "Viewer access required."
                    });
            }
 
 
            const list =
                await documents
                    .find({
 
                        vaultId:
                            req.session.viewerVaultId
                    })
                    .project({
 
                        _id: 0,
 
                        id: 1,
 
                        name: 1,
 
                        originalName: 1,
 
                        fileType: 1,
 
                        size: 1,
 
                        createdAt: 1
                    })
                    .sort({
                        createdAt: -1
                    })
                    .toArray();
 
 
            res.json({
 
                success: true,
 
                documents:
                    list
            });
 
 
        } catch (error) {
 
            console.error(
                "VIEWER DOCUMENT ERROR:",
                error
            );
 
            res.status(500).json({
 
                success: false,
 
                message:
                    "Unable to load documents."
            });
        }
    }
);
// ==========================================
// VIEWER VIEW DOCUMENT
// ==========================================
 
app.get(
    "/api/viewer/documents/:id/view",
    async (req, res) => {
 
        try {
 
            if (!req.session.viewerVaultId) {
 
                return res
                    .status(401)
                    .send(
                        "Viewer access required."
                    );
            }
 
            const document =
                await documents.findOne({
 
                    id:
                        req.params.id,
 
                    vaultId:
                        req.session.viewerVaultId
                });
 
            if (!document) {
 
                return res
                    .status(404)
                    .send(
                        "Document not found."
                    );
            }
 
            res.setHeader(
                "Content-Type",
                document.fileType
            );
 
            res.setHeader(
                "Content-Disposition",
                `inline; filename="${encodeURIComponent(
                    document.originalName
                )}"`
            );
 
            bucket
                .openDownloadStream(
                    document.fileId
                )
                .pipe(res);
 
        } catch (error) {
 
            console.error(
                "VIEWER VIEW ERROR:",
                error
            );
 
            res
                .status(500)
                .send(
                    "Unable to view document."
                );
        }
    }
);
 
 
// ==========================================
// VIEWER DOWNLOAD DOCUMENT
// ==========================================
 
app.get(
    "/api/viewer/documents/:id/download",
    async (req, res) => {
 
        try {
 
            if (!req.session.viewerVaultId) {
 
                return res
                    .status(401)
                    .send(
                        "Viewer access required."
                    );
            }
 
            const document =
                await documents.findOne({
 
                    id:
                        req.params.id,
 
                    vaultId:
                        req.session.viewerVaultId
                });
 
            if (!document) {
 
                return res
                    .status(404)
                    .send(
                        "Document not found."
                    );
            }
 
            res.setHeader(
                "Content-Type",
                document.fileType
            );
 
            res.setHeader(
                "Content-Disposition",
                `attachment; filename="${encodeURIComponent(
                    document.originalName
                )}"`
            );
 
            bucket
                .openDownloadStream(
                    document.fileId
                )
                .pipe(res);
 
        } catch (error) {
 
            console.error(
                "VIEWER DOWNLOAD ERROR:",
                error
            );
 
            res
                .status(500)
                .send(
                    "Unable to download document."
                );
        }
    }
);
 
 
// ==========================================
// VERIFY CURRENT PASSWORD
// ==========================================
 
app.post(
    "/api/verify-current-password",
    requireLogin,
    async (req, res) => {
 
        try {
 
            const currentPassword =
                String(
                    req.body.currentPassword || ""
                );
 
            if (!currentPassword) {
 
                return res.status(400).json({
 
                    success: false,
 
                    message:
                        "Current account password is required."
                });
            }
 
            const user =
                await users.findOne({
 
                    email:
                        req.session.userEmail
                });
 
            if (!user) {
 
                return res.status(404).json({
 
                    success: false,
 
                    message:
                        "User account not found."
                });
            }
 
            const valid =
                await bcrypt.compare(
                    currentPassword,
                    user.passwordHash
                );
 
            if (!valid) {
 
                return res.status(401).json({
 
                    success: false,
 
                    message:
                        "Incorrect account password. Please re-enter."
                });
            }
 
            res.json({
 
                success: true,
 
                message:
                    "Current password verified."
            });
 
        } catch (error) {
 
            console.error(
                "VERIFY PASSWORD ERROR:",
                error
            );
 
            res.status(500).json({
 
                success: false,
 
                message:
                    "Unable to verify current password."
            });
        }
    }
);
 
 
// ==========================================
// VERIFY CURRENT SECURITY PIN
// ==========================================
 
app.post(
    "/api/verify-current-security-pin",
    requireLogin,
    async (req, res) => {
 
        try {
 
            const currentPin =
                String(
                    req.body.currentPin || ""
                ).trim();
 
            if (
                !/^\d{6}$/.test(
                    currentPin
                )
            ) {
 
                return res.status(400).json({
 
                    success: false,
 
                    message:
                        "Security PIN must contain exactly 6 digits."
                });
            }
 
            const user =
                await users.findOne({
 
                    email:
                        req.session.userEmail
                });
 
            if (!user) {
 
                return res.status(404).json({
 
                    success: false,
 
                    message:
                        "User account not found."
                });
            }
 
            if (!user.securityPinHash) {
 
                return res.status(400).json({
 
                    success: false,
 
                    message:
                        "Security PIN is not configured."
                });
            }
 
            const valid =
                await bcrypt.compare(
 
                    currentPin,
 
                    user.securityPinHash
                );
 
            if (!valid) {
 
                return res.status(401).json({
 
                    success: false,
 
                    message:
                        "Incorrect Security PIN. Please re-enter."
                });
            }
 
            res.json({
 
                success: true,
 
                message:
                    "Current Security PIN verified."
            });
 
        } catch (error) {
 
            console.error(
                "VERIFY PIN ERROR:",
                error
            );
 
            res.status(500).json({
 
                success: false,
 
                message:
                    "Unable to verify Security PIN."
            });
        }
    }
);
 
 
// ==========================================
// CHANGE PASSWORD
// ==========================================
 
app.post(
    "/api/change-password",
    requireLogin,
    async (req, res) => {
 
        try {
 
            const currentPassword =
                String(
                    req.body.currentPassword || ""
                );
 
            const newPassword =
                String(
                    req.body.newPassword || ""
                );
 
            const confirmPassword =
                String(
                    req.body.confirmPassword || ""
                );
 
 
            if (!currentPassword) {
 
                return res.status(400).json({
 
                    success: false,
 
                    message:
                        "Current account password is required."
                });
            }
 
 
            if (
                newPassword.length < 8
            ) {
 
                return res.status(400).json({
 
                    success: false,
 
                    message:
                        "New password must contain at least 8 characters."
                });
            }
 
 
            if (
                newPassword !==
                confirmPassword
            ) {
 
                return res.status(400).json({
 
                    success: false,
 
                    message:
                        "New password entries do not match."
                });
            }
 
 
            const user =
                await users.findOne({
 
                    email:
                        req.session.userEmail
                });
 
 
            if (!user) {
 
                return res.status(404).json({
 
                    success: false,
 
                    message:
                        "User account not found."
                });
            }
 
 
            const valid =
                await bcrypt.compare(
 
                    currentPassword,
 
                    user.passwordHash
                );
 
 
            if (!valid) {
 
                return res.status(401).json({
 
                    success: false,
 
                    message:
                        "Incorrect account password."
                });
            }
 
 
            const passwordHash =
                await bcrypt.hash(
                    newPassword,
                    12
                );
 
 
            await users.updateOne(
 
                {
                    email:
                        user.email
                },
 
                {
                    $set: {
                        passwordHash
                    }
                }
            );
 
 
            res.json({
 
                success: true,
 
                message:
                    "Account password updated successfully."
            });
 
 
        } catch (error) {
 
            console.error(
                "CHANGE PASSWORD ERROR:",
                error
            );
 
            res.status(500).json({
 
                success: false,
 
                message:
                    "Unable to change account password."
            });
        }
    }
);
 
 
// ==========================================
// CHANGE SECURITY PIN
// ==========================================
 
app.post(
    "/api/change-security-pin",
    requireLogin,
    async (req, res) => {
 
        try {
 
            const currentPin =
                String(
                    req.body.currentPin || ""
                ).trim();
 
            const newPin =
                String(
                    req.body.newPin || ""
                ).trim();
 
            const confirmPin =
                String(
                    req.body.confirmPin || ""
                ).trim();
 
 
            if (
                !/^\d{6}$/.test(
                    currentPin
                )
            ) {
 
                return res.status(400).json({
 
                    success: false,
 
                    message:
                        "Current Security PIN must contain exactly 6 digits."
                });
            }
 
 
            if (
                !/^\d{6}$/.test(
                    newPin
                )
            ) {
 
                return res.status(400).json({
 
                    success: false,
 
                    message:
                        "New Security PIN must contain exactly 6 digits."
                });
            }
 
 
            if (
                newPin !==
                confirmPin
            ) {
 
                return res.status(400).json({
 
                    success: false,
 
                    message:
                        "New Security PIN entries do not match."
                });
            }
 
 
            const user =
                await users.findOne({
 
                    email:
                        req.session.userEmail
                });
 
 
            if (!user) {
 
                return res.status(404).json({
 
                    success: false,
 
                    message:
                        "User account not found."
                });
            }
 
 
            if (
                !user.securityPinHash
            ) {
 
                return res.status(400).json({
 
                    success: false,
 
                    message:
                        "Security PIN is not configured."
                });
            }
 
 
            const valid =
                await bcrypt.compare(
 
                    currentPin,
 
                    user.securityPinHash
                );
 
 
            if (!valid) {
 
                return res.status(401).json({
 
                    success: false,
 
                    message:
                        "Incorrect Security PIN."
                });
            }
 
 
            const securityPinHash =
                await bcrypt.hash(
                    newPin,
                    12
                );
 
 
            await users.updateOne(
 
                {
                    email:
                        user.email
                },
 
                {
                    $set: {
                        securityPinHash
                    }
                }
            );
 
 
            res.json({
 
                success: true,
 
                message:
                    "Security PIN updated successfully."
            });
 
 
        } catch (error) {
 
            console.error(
                "CHANGE PIN ERROR:",
                error
            );
 
            res.status(500).json({
 
                success: false,
 
                message:
                    "Unable to change Security PIN."
            });
        }
    }
);
// ==========================================
// CHANGE SECURITY PIN
// ==========================================
 
// ==========================================
// DELETE DOCUMENT
// ==========================================
 
app.delete(
    "/api/documents/:id",
    requireLogin,
    async (req, res) => {
 
        try {
 
            const document =
                await getMyDocument(
                    req,
                    req.params.id
                );
 
 
            if (!document) {
 
                return res.status(404).json({
 
                    success: false,
 
                    message:
                        "Document not found."
                });
            }
 
 
            await documents.deleteOne({
 
                id:
                    document.id,
 
                vaultId:
                    document.vaultId
            });
 
 
            try {
 
                await bucket.delete(
                    document.fileId
                );
 
            } catch (fileError) {
 
                console.error(
                    "GRIDFS DELETE ERROR:",
                    fileError
                );
            }
 
 
            res.json({
 
                success: true,
 
                message:
                    "Document deleted successfully."
            });
 
 
        } catch (error) {
 
            console.error(
                "DELETE DOCUMENT ERROR:",
                error
            );
 
 
            res.status(500).json({
 
                success: false,
 
                message:
                    "Unable to delete document."
            });
        }
    }
);
 
 
// ==========================================
// VIEWER LOGOUT
// ==========================================
 
app.post(
    "/api/viewer-logout",
    (req, res) => {
 
        req.session.viewerVaultId =
            null;
 
        req.session.viewerEmail =
            null;
 
 
        res.json({
 
            success: true,
 
            message:
                "Viewer session closed."
        });
    }
);
 
 
// JSON response for missing API endpoints.
app.use("/api", (req, res) => {
    res.status(404).json({
        success: false,
        message: "API endpoint not found."
    });
});
 
// ==========================================
// GENERIC ERROR HANDLER
// ==========================================
 
app.use(
    (error, req, res, next) => {
 
        console.error(
            "UNHANDLED SERVER ERROR:",
            error
        );
 
 
        if (
            error &&
            error.code ===
                "LIMIT_FILE_SIZE"
        ) {
 
            return res.status(400).json({
 
                success: false,
 
                message:
                    "File size must be 10 MB or less."
            });
        }
 
 
        if (
            error &&
            error.message &&
            error.message.includes(
                "Only PDF, JPG and PNG"
            )
        ) {
 
            return res.status(400).json({
 
                success: false,
 
                message:
                    error.message
            });
        }
 
 
        res.status(500).json({
 
            success: false,
 
            message:
                "Something went wrong on the server."
        });
    }
);
 
 
// ==========================================
// START SERVER
// ==========================================
 
async function startServer() {
 
    try {
 
        await connectMongoDB();
 
 
        app.listen(
            PORT,
            "0.0.0.0",
 
            () => {
 
                console.log(
                    `DocVault server started on port ${PORT}`
                );
 
                console.log(
                    `Local: http://localhost:${PORT}`
                );
 
                console.log(
                    `Network: http://10.20.137.41:${PORT}`
                );
            }
        );
 
 
    } catch (error) {
 
        console.error(
            "SERVER START ERROR:"
        );
 
        console.error(
            error
        );
 
        process.exit(1);
    }
}
 
 
startServer();
