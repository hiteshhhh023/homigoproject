
require("dotenv").config();

const express = require("express");
const path = require("path");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.JWT_SECRET) {
    console.error("Missing JWT_SECRET in .env file.");
    process.exit(1);
}

app.use(express.json({ limit: "100kb" }));
app.use(express.static(path.join(__dirname, "public")));


const pgSchema = new mongoose.Schema(
    {
        name: { type: String, required: true, trim: true },
        location: { type: String, default: "" },
        address: { type: String, default: "" },
        monthlyRent: { type: Number, min: 1 },
        roomType: { type: String, default: "" },
        facilities: { type: [String], default: [] },
        availableBeds: { type: Number, default: 0 },
        rating: { type: Number, min: 0, max: 5 },
        image: { type: String, default: "" },
        ownerId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            default: null
        }
    },
    {
        collection: "pgs",
        timestamps: true
    }
);

const PG = mongoose.model("PG", pgSchema);


const userSchema = new mongoose.Schema(
    {
        name: {
            type: String,
            required: true,
            trim: true,
            maxlength: 100
        },
        email: {
            type: String,
            required: true,
            unique: true,
            lowercase: true,
            trim: true,
            maxlength: 254
        },
        password: {
            type: String,
            required: true,
            select: false
        },
        role: {
            type: String,
            enum: ["tenant", "owner"],
            default: "tenant"
        }
    },
    {
        collection: "users",
        timestamps: true
    }
);

const User = mongoose.model("User", userSchema);


function createToken(user) {
    return jwt.sign(
        {
            userId: user._id.toString(),
            role: user.role
        },
        process.env.JWT_SECRET,
        { expiresIn: "1d" }
    );
}

function requireAuth(req, res, next) {
    const header = req.headers.authorization || "";
    const [scheme, token] = header.split(" ");

    if (scheme !== "Bearer" || !token) {
        return res.status(401).json({
            error: "Please log in to continue."
        });
    }

    try {
        req.auth = jwt.verify(token, process.env.JWT_SECRET);
        next();
    } catch (error) {
        return res.status(401).json({
            error: "Invalid or expired session. Please log in again."
        });
    }
}

function requireRole(role) {
    return (req, res, next) => {
        if (req.auth.role !== role) {
            return res.status(403).json({
                error: "You do not have permission for this action."
            });
        }

        next();
    };
}


app.get("/api/status", (req, res) => {
    res.json({
        message: "HOMIGO backend is working!",
        database:
            mongoose.connection.readyState === 1
                ? "Connected"
                : "Disconnected"
    });
});


app.post("/api/auth/signup", async (req, res) => {
    try {
        const { name, email, password } = req.body || {};

        if (
            typeof name !== "string" ||
            !name.trim() ||
            name.trim().length > 100 ||
            typeof email !== "string" ||
            email.trim().length > 254 ||
            !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()) ||
            typeof password !== "string" ||
            password.length < 8 ||
            password.length > 72
        ) {
            return res.status(400).json({
                error:
                    "Enter a valid name and email. Password must be 8–72 characters."
            });
        }

        const normalizedEmail = email.trim().toLowerCase();

        const existingUser = await User.findOne({
            email: normalizedEmail
        });

        if (existingUser) {
            return res.status(409).json({
                error: "An account with this email already exists."
            });
        }

        const hashedPassword = await bcrypt.hash(password, 12);

        const user = await User.create({
            name: name.trim(),
            email: normalizedEmail,
            password: hashedPassword,
            role: "tenant"
        });

        res.status(201).json({
            message: "Account created successfully.",
            token: createToken(user),
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });
    } catch (error) {
        if (error.code === 11000) {
            return res.status(409).json({
                error: "An account with this email already exists."
            });
        }

        console.error("Signup error:", error.message);

        res.status(500).json({
            error: "Could not create account."
        });
    }
});


app.post("/api/auth/login", async (req, res) => {
    try {
        const { email, password } = req.body || {};

        if (
            typeof email !== "string" ||
            typeof password !== "string" ||
            !email.trim() ||
            !password
        ) {
            return res.status(400).json({
                error: "Enter your email and password."
            });
        }

        const user = await User.findOne({
            email: email.trim().toLowerCase()
        }).select("+password");

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({
                error: "Invalid email or password."
            });
        }

        res.json({
            message: "Login successful.",
            token: createToken(user),
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });
    } catch (error) {
        console.error("Login error:", error.message);

        res.status(500).json({
            error: "Could not log in."
        });
    }
});


app.get("/api/auth/me", requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.auth.userId).lean();

        if (!user) {
            return res.status(404).json({
                error: "User account not found."
            });
        }

        res.json({
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });
    } catch (error) {
        res.status(500).json({
            error: "Could not fetch account details."
        });
    }
});


app.get("/api/pgs", async (req, res) => {
    try {
        const pgs = await PG.find().lean();
        res.json(pgs);
    } catch (error) {
        console.error("Fetch PGs error:", error.message);

        res.status(500).json({
            error: "Could not fetch PG listings."
        });
    }
});


app.get("/api/pgs/:id", async (req, res) => {
    try {
        if (!mongoose.isValidObjectId(req.params.id)) {
            return res.status(400).json({
                error: "Invalid PG ID."
            });
        }

        const pg = await PG.findById(req.params.id).lean();

        if (!pg) {
            return res.status(404).json({
                error: "PG not found."
            });
        }

        res.json(pg);
    } catch (error) {
        console.error("PG details error:", error.message);

        res.status(500).json({
            error: "Could not load PG details."
        });
    }
});


app.post(
    "/api/pgs",
    requireAuth,
    requireRole("owner"),
    async (req, res) => {
        try {
            const {
                name,
                location,
                address,
                monthlyRent,
                roomType,
                facilities,
                availableBeds,
                rating,
                image
            } = req.body || {};

            if (
                typeof name !== "string" ||
                !name.trim() ||
                typeof location !== "string" ||
                !location.trim() ||
                typeof address !== "string" ||
                !address.trim() ||
                monthlyRent === "" ||
                monthlyRent === null ||
                !Number.isFinite(Number(monthlyRent)) ||
                Number(monthlyRent) <= 0 ||
                !Number.isInteger(Number(availableBeds)) ||
                Number(availableBeds) < 0 ||
                typeof roomType !== "string" ||
                !roomType.trim() ||
                (rating !== undefined &&
                    rating !== "" &&
                    (!Number.isFinite(Number(rating)) ||
                        Number(rating) < 0 ||
                        Number(rating) > 5)) ||
                (facilities !== undefined &&
                    (!Array.isArray(facilities) ||
                        !facilities.every(
                            item => typeof item === "string"
                        ))) ||
                (image !== undefined && typeof image !== "string")
            ) {
                return res.status(400).json({
                    error: "Please provide valid PG details."
                });
            }

            const pg = await PG.create({
                name: name.trim(),
                location: location.trim(),
                address: address.trim(),
                monthlyRent: Number(monthlyRent),
                roomType: roomType.trim(),
                facilities: facilities || [],
                availableBeds: Number(availableBeds),
                ownerId: req.auth.userId,
                ...(rating !== undefined && rating !== ""
                    ? { rating: Number(rating) }
                    : {}),
                ...(typeof image === "string"
                    ? { image: image.trim() }
                    : {})
            });

            res.status(201).json(pg);
        } catch (error) {
            console.error("Add PG error:", error.message);

            res.status(400).json({
                error: "Could not add PG.",
                details: error.message
            });
        }
    }
);


app.get(
    "/api/owner/pgs",
    requireAuth,
    requireRole("owner"),
    async (req, res) => {
        try {
            const pgs = await PG.find({
                ownerId: req.auth.userId
            })
                .sort({ createdAt: -1 })
                .lean();

            res.json(pgs);
        } catch (error) {
            console.error("Owner PG fetch error:", error.message);

            res.status(500).json({
                error: "Could not fetch your PG listings."
            });
        }
    }
);


app.put(
    "/api/owner/pgs/:id",
    requireAuth,
    requireRole("owner"),
    async (req, res) => {
        try {
            const { id } = req.params;

            if (!mongoose.isValidObjectId(id)) {
                return res.status(400).json({
                    error: "Invalid PG ID."
                });
            }

            const {
                name,
                location,
                address,
                monthlyRent,
                roomType,
                facilities,
                availableBeds,
                rating,
                image
            } = req.body || {};

            if (
                typeof name !== "string" ||
                !name.trim() ||
                typeof location !== "string" ||
                !location.trim() ||
                typeof address !== "string" ||
                !address.trim() ||
                typeof roomType !== "string" ||
                !roomType.trim() ||
                monthlyRent === "" ||
                monthlyRent === null ||
                !Number.isFinite(Number(monthlyRent)) ||
                Number(monthlyRent) <= 0 ||
                !Number.isInteger(Number(availableBeds)) ||
                Number(availableBeds) < 0 ||
                (rating !== undefined &&
                    rating !== "" &&
                    (!Number.isFinite(Number(rating)) ||
                        Number(rating) < 0 ||
                        Number(rating) > 5)) ||
                (facilities !== undefined &&
                    (!Array.isArray(facilities) ||
                        !facilities.every(
                            item => typeof item === "string"
                        ))) ||
                (image !== undefined && typeof image !== "string")
            ) {
                return res.status(400).json({
                    error: "Please provide valid PG details."
                });
            }

            const fieldsToUpdate = {
                name: name.trim(),
                location: location.trim(),
                address: address.trim(),
                monthlyRent: Number(monthlyRent),
                roomType: roomType.trim(),
                facilities: facilities || [],
                availableBeds: Number(availableBeds)
            };

            if (rating !== undefined && rating !== "") {
                fieldsToUpdate.rating = Number(rating);
            } else {
                fieldsToUpdate.rating = undefined;
            }

            if (typeof image === "string") {
                fieldsToUpdate.image = image.trim();
            }

            const pg = await PG.findOne({
                _id: id,
                ownerId: req.auth.userId
            });

            if (!pg) {
                return res.status(404).json({
                    error: "PG not found or you do not own this listing."
                });
            }

            Object.assign(pg, fieldsToUpdate);
            await pg.save();

            res.json({
                message: "PG updated successfully.",
                pg
            });
        } catch (error) {
            console.error("Update PG error:", error.message);

            res.status(400).json({
                error: "Could not update PG."
            });
        }
    }
);


app.delete(
    "/api/owner/pgs/:id",
    requireAuth,
    requireRole("owner"),
    async (req, res) => {
        try {
            if (!mongoose.isValidObjectId(req.params.id)) {
                return res.status(400).json({
                    error: "Invalid PG ID."
                });
            }

            const pg = await PG.findOneAndDelete({
                _id: req.params.id,
                ownerId: req.auth.userId
            });

            if (!pg) {
                return res.status(404).json({
                    error: "PG not found or you do not own this listing."
                });
            }

            res.json({
                message: "PG deleted successfully."
            });
        } catch (error) {
            console.error("Delete PG error:", error.message);

            res.status(500).json({
                error: "Could not delete PG."
            });
        }
    }
);


app.use("/api", (req, res) => {
    res.status(404).json({
        error: "API route not found.",
        path: req.originalUrl
    });
});


async function startServer() {
    try {
        const mongoURI =
            process.env.MONGODB_URI ||
            "mongodb://127.0.0.1:27017/homigo";

        await mongoose.connect(mongoURI);

        console.log("MongoDB connected successfully!");

        app.listen(PORT, () => {
            console.log(`HOMIGO is running at http://localhost:${PORT}`);
            console.log(`All PGs: http://localhost:${PORT}/api/pgs`);
        });
    } catch (error) {
        console.error("Server startup failed:", error.message);
        process.exit(1);
    }
}

startServer();
