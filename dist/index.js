"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const dotenv_1 = __importDefault(require("dotenv"));
const mongodb_1 = require("mongodb");
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const jose_cjs_1 = require("jose-cjs");
const multer_1 = __importDefault(require("multer"));
const cloudinary_1 = require("cloudinary");
const stream_1 = require("stream");
dotenv_1.default.config();
const app = (0, express_1.default)();
app.use((0, cors_1.default)({
    origin: process.env.FRONTEND_URL,
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
}));
app.use(express_1.default.json({ limit: "10mb" }));
app.use(express_1.default.urlencoded({ extended: true, limit: "10mb" }));
const uri = process.env.MONGODB_URI || "";
const dbName = process.env.DB_NAME || "StayEase";
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:3000";
// ============================================================
// CLOUDINARY CONFIG
// ============================================================
cloudinary_1.v2.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME || "",
    api_key: process.env.CLOUDINARY_API_KEY || "",
    api_secret: process.env.CLOUDINARY_API_SECRET || "",
});
// ============================================================
// MULTER CONFIG - memory storage (buffer → Cloudinary)
// ============================================================
const ALLOWED_MIME_TYPES = ["image/jpeg", "image/jpg", "image/png", "image/webp"];
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5 MB
const MAX_FILES = 10;
// ✅ Fix 1: FileFilterCallback imported from multer (not Express.Multer)
const multerFilter = (_req, file, cb) => {
    if (ALLOWED_MIME_TYPES.includes(file.mimetype)) {
        cb(null, true);
    }
    else {
        // cast because multer's CB overloads are strict
        cb(new Error(`Invalid file type: ${file.mimetype}. Only JPEG, PNG, WebP allowed.`), false);
    }
};
const upload = (0, multer_1.default)({
    storage: multer_1.default.memoryStorage(),
    fileFilter: multerFilter,
    limits: { fileSize: MAX_FILE_SIZE, files: MAX_FILES },
});
// ============================================================
// MONGODB CONNECTION
// ============================================================
const globalWithMongo = global;
function getClientPromise() {
    if (!uri)
        throw new Error("MONGODB_URI is not set");
    if (globalWithMongo._mongoClientPromise)
        return globalWithMongo._mongoClientPromise;
    const client = new mongodb_1.MongoClient(uri, {
        serverApi: { version: mongodb_1.ServerApiVersion.v1, strict: true, deprecationErrors: true },
    });
    globalWithMongo._mongoClientPromise = client.connect();
    return globalWithMongo._mongoClientPromise;
}
async function getDb() {
    const c = await getClientPromise();
    return c.db(dbName);
}
// ============================================================
// INDEXES
// ============================================================
async function ensurePropertyIndexes() {
    try {
        const db = await getDb();
        const col = db.collection("properties");
        // Single-field
        await col.createIndex({ "location.city": 1 });
        await col.createIndex({ "location.country": 1 });
        await col.createIndex({ category: 1 });
        await col.createIndex({ "price.perNight": 1 });
        await col.createIndex({ status: 1 });
        await col.createIndex({ hostId: 1 });
        await col.createIndex({ isFeatured: -1 });
        await col.createIndex({ rating: -1 });
        await col.createIndex({ createdAt: -1 });
        await col.createIndex({ amenities: 1 });
        await col.createIndex({ "details.maxGuests": 1 });
        // Full-text search
        await col.createIndex({
            title: "text",
            description: "text",
            "location.city": "text",
            "location.country": "text",
            "location.address": "text",
        }, {
            weights: { title: 10, "location.city": 8, "location.country": 6, description: 3, "location.address": 2 },
            name: "property_text_search",
        });
        // Compound
        await col.createIndex({ status: 1, category: 1 });
        await col.createIndex({ status: 1, "location.city": 1 });
        await col.createIndex({ status: 1, isFeatured: -1, rating: -1 });
        await col.createIndex({ status: 1, "price.perNight": 1, rating: -1 });
        await col.createIndex({ hostId: 1, status: 1, createdAt: -1 });
        console.log("✅ Property indexes created");
    }
    catch (error) {
        console.warn("⚠️ Index creation warning:", error);
    }
}
ensurePropertyIndexes().catch((err) => console.error("❌ Failed to create indexes:", err));
// Users indexes
async function ensureUserIndexes() {
    try {
        const db = await getDb();
        const col = db.collection("user");
        await col.createIndex({ role: 1 });
        await col.createIndex({ banned: 1 });
        await col.createIndex({ email: 1 }, { unique: true });
        await col.createIndex({ name: 1 });
        await col.createIndex({ createdAt: -1 });
        await col.createIndex({ role: 1, banned: 1 });
        console.log("✅ User indexes created");
    }
    catch (error) {
        console.warn("⚠️ User index creation warning:", error);
    }
}
ensureUserIndexes().catch((err) => console.error("❌ Failed to create user indexes:", err));
// ============================================================
// HELPERS
// ============================================================
let JWKS = null;
function getJWKS() {
    if (!JWKS)
        JWKS = (0, jose_cjs_1.createRemoteJWKSet)(new URL(`${FRONTEND_URL}/api/auth/jwks`));
    return JWKS;
}
function userIdFilter(id) {
    return { _id: id };
}
function toIdString(id) {
    return id.toString();
}
// Always string from Express params
function parseId(param) {
    return String(param || "").trim();
}
// Safe ObjectId — null if invalid
function toObjectId(id) {
    const s = String(id).trim();
    if (!s || !mongodb_1.ObjectId.isValid(s))
        return null;
    return new mongodb_1.ObjectId(s);
}
async function findUserById(usersCol, userId) {
    const s = String(userId).trim();
    // ObjectId lookup first
    if (mongodb_1.ObjectId.isValid(s) && s.length === 24) {
        try {
            const u = await usersCol.findOne({ _id: new mongodb_1.ObjectId(s) });
            if (u)
                return u;
        }
        catch { }
    }
    // Fallback: string _id (social auth)
    try {
        const u = await usersCol.findOne({ _id: s });
        if (u)
            return u;
    }
    catch { }
    return null;
}
function checkPassword(pw) {
    if (!pw)
        return "Password is required.";
    if (pw.length < 8)
        return "Password must be at least 8 characters.";
    if (!/[A-Z]/.test(pw))
        return "Password must have at least one uppercase letter.";
    if (!/[0-9]/.test(pw))
        return "Password must have at least one number.";
    return null;
}
function getPagination(query, maxLimit = 50, defaultLimit = 12) {
    const page = Math.max(1, parseInt(String(query.page || "1")));
    const limit = Math.min(maxLimit, Math.max(1, parseInt(String(query.limit || defaultLimit))));
    const skip = (page - 1) * limit;
    return { page, limit, skip };
}
// ✅ Fix 3: explicit Cloudinary callback types (no implicit any)
async function uploadToCloudinary(buffer, folder, filename) {
    return new Promise((resolve, reject) => {
        const stream = cloudinary_1.v2.uploader.upload_stream({
            folder: `stayease/${folder}`,
            public_id: filename,
            overwrite: true,
            resource_type: "image",
            transformation: [
                { width: 1920, height: 1080, crop: "limit" },
                { quality: "auto:good" },
                { fetch_format: "auto" },
            ],
        }, 
        // ✅ explicit types for error & result params
        (error, result) => {
            if (error || !result) {
                reject(new Error(error?.message || "Cloudinary upload failed"));
                return;
            }
            resolve({ url: result.secure_url, publicId: result.public_id });
        });
        const readable = new stream_1.Readable();
        readable.push(buffer);
        readable.push(null);
        readable.pipe(stream);
    });
}
// Delete by Cloudinary URL
async function deleteFromCloudinary(imageUrl) {
    try {
        const parts = imageUrl.split("/");
        const uploadIndex = parts.indexOf("upload");
        if (uploadIndex === -1)
            return;
        const afterUpload = parts.slice(uploadIndex + 2).join("/"); // skip "upload/v{version}"
        const publicId = afterUpload.replace(/\.[^/.]+$/, ""); // remove extension
        if (publicId)
            await cloudinary_1.v2.uploader.destroy(publicId);
    }
    catch (err) {
        console.warn("Cloudinary delete warning:", err); // non-critical
    }
}
// ============================================================
// PROPERTY VALIDATION
// ============================================================
const VALID_CATEGORIES = ["hotel", "apartment", "villa", "event-space"];
const VALID_STATUSES = ["active", "inactive", "draft", "pending", "rejected", "deleted"];
const VALID_AMENITIES = [
    "wifi", "pool", "ac", "parking", "gym", "kitchen", "washer", "dryer",
    "tv", "heating", "workspace", "elevator", "balcony", "garden", "bbq",
    "fireplace", "security-camera", "smoke-alarm", "first-aid", "fire-extinguisher",
];
function validatePropertyInput(body) {
    const { title, description, category, location, price, details, amenities, images, houseRules, status } = body;
    if (!title || typeof title !== "string" || title.trim().length < 5)
        return { valid: false, error: "Title must be at least 5 characters." };
    if (title.trim().length > 150)
        return { valid: false, error: "Title cannot exceed 150 characters." };
    if (!description || typeof description !== "string" || description.trim().length < 20)
        return { valid: false, error: "Description must be at least 20 characters." };
    if (description.trim().length > 5000)
        return { valid: false, error: "Description cannot exceed 5000 characters." };
    if (!category || !VALID_CATEGORIES.includes(category))
        return { valid: false, error: `Category must be one of: ${VALID_CATEGORIES.join(", ")}` };
    if (!location || typeof location !== "object")
        return { valid: false, error: "Location is required." };
    if (!location.address || String(location.address).trim().length < 3)
        return { valid: false, error: "Location address is required (min 3 chars)." };
    if (!location.city || String(location.city).trim().length < 2)
        return { valid: false, error: "Location city is required (min 2 chars)." };
    if (!location.country || String(location.country).trim().length < 2)
        return { valid: false, error: "Location country is required (min 2 chars)." };
    if (location.coordinates) {
        const { lat, lng } = location.coordinates;
        if (typeof lat !== "number" || lat < -90 || lat > 90 || typeof lng !== "number" || lng < -180 || lng > 180)
            return { valid: false, error: "Invalid coordinates. Lat: -90~90, Lng: -180~180." };
    }
    if (!price || typeof price !== "object")
        return { valid: false, error: "Price information is required." };
    const perNight = Number(price.perNight);
    if (!price.perNight || isNaN(perNight) || perNight <= 0)
        return { valid: false, error: "Price per night must be a positive number." };
    if (perNight > 100000)
        return { valid: false, error: "Price per night cannot exceed 100,000." };
    if (price.weeklyDiscount !== undefined && (Number(price.weeklyDiscount) < 0 || Number(price.weeklyDiscount) > 90))
        return { valid: false, error: "Weekly discount must be 0%–90%." };
    if (price.monthlyDiscount !== undefined && (Number(price.monthlyDiscount) < 0 || Number(price.monthlyDiscount) > 90))
        return { valid: false, error: "Monthly discount must be 0%–90%." };
    if (price.cleaningFee !== undefined && (Number(price.cleaningFee) < 0 || Number(price.cleaningFee) > 10000))
        return { valid: false, error: "Cleaning fee must be 0–10,000." };
    if (price.serviceFee !== undefined && (Number(price.serviceFee) < 0 || Number(price.serviceFee) > 10000))
        return { valid: false, error: "Service fee must be 0–10,000." };
    if (!details || typeof details !== "object")
        return { valid: false, error: "Property details are required." };
    const bedrooms = Number(details.bedrooms);
    const bathrooms = Number(details.bathrooms);
    const maxGuests = Number(details.maxGuests);
    if (isNaN(bedrooms) || bedrooms < 0 || bedrooms > 50)
        return { valid: false, error: "Bedrooms must be 0–50." };
    if (isNaN(bathrooms) || bathrooms < 0 || bathrooms > 50)
        return { valid: false, error: "Bathrooms must be 0–50." };
    if (isNaN(maxGuests) || maxGuests < 1 || maxGuests > 100)
        return { valid: false, error: "Max guests must be 1–100." };
    if (amenities !== undefined) {
        if (!Array.isArray(amenities))
            return { valid: false, error: "Amenities must be an array." };
        const invalid = amenities.filter((a) => !VALID_AMENITIES.includes(a));
        if (invalid.length > 0)
            return { valid: false, error: `Invalid amenities: ${invalid.join(", ")}` };
    }
    if (images !== undefined) {
        if (!Array.isArray(images))
            return { valid: false, error: "Images must be an array." };
        if (images.length > 20)
            return { valid: false, error: "Maximum 20 images allowed." };
        for (const img of images) {
            if (typeof img !== "string" || !img.trim())
                return { valid: false, error: "Each image must be a valid URL." };
            try {
                new URL(img);
            }
            catch {
                return { valid: false, error: `Invalid image URL: ${img}` };
            }
        }
    }
    if (houseRules !== undefined && typeof houseRules !== "object")
        return { valid: false, error: "House rules must be an object." };
    if (houseRules) {
        const timeRe = /^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/;
        if (houseRules.checkInTime && !timeRe.test(houseRules.checkInTime))
            return { valid: false, error: "Check-in time must be HH:MM format." };
        if (houseRules.checkOutTime && !timeRe.test(houseRules.checkOutTime))
            return { valid: false, error: "Check-out time must be HH:MM format." };
    }
    if (status !== undefined && !VALID_STATUSES.includes(status))
        return { valid: false, error: `Status must be one of: ${VALID_STATUSES.join(", ")}` };
    // Build clean validated object
    const data = {
        title: title.trim(),
        description: description.trim(),
        category: category,
        location: {
            address: String(location.address).trim(),
            city: String(location.city).trim(),
            country: String(location.country).trim(),
            ...(location.coordinates && {
                coordinates: { lat: Number(location.coordinates.lat), lng: Number(location.coordinates.lng) },
            }),
        },
        price: {
            perNight,
            ...(price.weeklyDiscount !== undefined && { weeklyDiscount: Number(price.weeklyDiscount) }),
            ...(price.monthlyDiscount !== undefined && { monthlyDiscount: Number(price.monthlyDiscount) }),
            ...(price.cleaningFee !== undefined && { cleaningFee: Number(price.cleaningFee) }),
            ...(price.serviceFee !== undefined && { serviceFee: Number(price.serviceFee) }),
        },
        details: {
            bedrooms,
            bathrooms,
            maxGuests,
            ...(details.beds !== undefined && { beds: Number(details.beds) }),
            ...(details.area !== undefined && { area: Number(details.area) }),
        },
        amenities: Array.isArray(amenities) ? amenities : [],
        images: Array.isArray(images) ? images : [],
        houseRules: houseRules
            ? {
                smokingAllowed: Boolean(houseRules.smokingAllowed),
                petsAllowed: Boolean(houseRules.petsAllowed),
                partiesAllowed: Boolean(houseRules.partiesAllowed),
                checkInTime: String(houseRules.checkInTime || "14:00"),
                checkOutTime: String(houseRules.checkOutTime || "11:00"),
                ...(houseRules.quietHoursStart && { quietHoursStart: String(houseRules.quietHoursStart) }),
                ...(houseRules.quietHoursEnd && { quietHoursEnd: String(houseRules.quietHoursEnd) }),
                ...(Array.isArray(houseRules.additionalRules) && {
                    additionalRules: houseRules.additionalRules.filter((r) => typeof r === "string" && r.trim()),
                }),
            }
            : { smokingAllowed: false, petsAllowed: false, partiesAllowed: false, checkInTime: "14:00", checkOutTime: "11:00" },
    };
    return { valid: true, data };
}
// Strips _id & internal fields for API response
function buildPropertyResponse(p) {
    return {
        id: p._id?.toString() || "",
        hostId: p.hostId,
        title: p.title,
        description: p.description,
        category: p.category,
        location: p.location,
        price: p.price,
        details: p.details,
        amenities: p.amenities || [],
        images: p.images || [],
        houseRules: p.houseRules,
        availability: p.availability || [],
        status: p.status,
        rating: p.rating ?? 0,
        reviewCount: p.reviewCount ?? 0,
        isFeatured: p.isFeatured ?? false,
        rejectionReason: p.rejectionReason || null,
        createdAt: p.createdAt,
        updatedAt: p.updatedAt,
    };
}
// ============================================================
// MIDDLEWARE
// ============================================================
const verifyToken = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
        res.status(401).json({ success: false, message: "Authorization header is required." });
        return;
    }
    const token = authHeader.substring(7).trim();
    if (!token) {
        res.status(401).json({ success: false, message: "Token is required." });
        return;
    }
    try {
        const { payload } = await (0, jose_cjs_1.jwtVerify)(token, getJWKS());
        const jwtPayload = payload;
        if (!jwtPayload.sub) {
            res.status(401).json({ success: false, message: "Invalid token payload." });
            return;
        }
        const db = await getDb();
        const user = await findUserById(db.collection("user"), jwtPayload.sub);
        if (!user) {
            res.status(401).json({ success: false, message: "User not found." });
            return;
        }
        if (user.banned) {
            res.status(403).json({ success: false, message: user.banReason || "Account suspended." });
            return;
        }
        req.user = user;
        req.jwtPayload = jwtPayload;
        next();
    }
    catch (error) {
        if (error?.code === "ERR_JWT_EXPIRED") {
            res.status(401).json({ success: false, message: "Token expired. Please login again." });
            return;
        }
        if (error?.code === "ERR_JWS_INVALID" || error?.code === "ERR_JWT_INVALID") {
            res.status(401).json({ success: false, message: "Invalid token." });
            return;
        }
        console.error("[verifyToken] error:", error);
        res.status(401).json({ success: false, message: "Invalid or expired token." });
    }
};
const verifyAdmin = (req, res, next) => {
    if (req.user?.role !== "admin") {
        res.status(403).json({ success: false, message: "Admin privileges required." });
        return;
    }
    next();
};
const verifyHostOrAdmin = (req, res, next) => {
    if (req.user?.role !== "host" && req.user?.role !== "admin") {
        res.status(403).json({ success: false, message: "Host or Admin privileges required." });
        return;
    }
    next();
};
// ============================================================
// HEALTH ROUTES
// ============================================================
app.get("/", (_req, res) => {
    res.status(200).json({
        success: true,
        message: "🏡 StayEase Server is Running!",
        version: "1.0.0",
        env: {
            hasMongoUri: !!process.env.MONGODB_URI,
            hasDbName: !!process.env.DB_NAME,
            hasFrontendUrl: !!process.env.FRONTEND_URL,
            hasCloudinary: !!process.env.CLOUDINARY_CLOUD_NAME && !!process.env.CLOUDINARY_API_KEY,
            nodeEnv: process.env.NODE_ENV || "not set",
        },
    });
});
app.get("/api/health", async (_req, res) => {
    try {
        const db = await getDb();
        await db.command({ ping: 1 });
        const cloudinaryOk = !!process.env.CLOUDINARY_CLOUD_NAME && !!process.env.CLOUDINARY_API_KEY && !!process.env.CLOUDINARY_API_SECRET;
        res.status(200).json({
            success: true,
            message: "All systems operational",
            services: {
                mongodb: { status: "connected", database: dbName },
                cloudinary: { status: cloudinaryOk ? "configured" : "not configured" },
                server: { status: "running" },
            },
        });
    }
    catch (error) {
        res.status(500).json({
            success: false,
            message: "MongoDB connection failed",
            error: error instanceof Error ? error.message : "Unknown",
        });
    }
});
// ============================================================
// USER ROUTES
// ============================================================
// GET profile
app.get("/api/users/profile", verifyToken, async (req, res) => {
    try {
        const user = req.user;
        res.status(200).json({
            success: true,
            data: {
                id: toIdString(user._id),
                name: user.name,
                email: user.email,
                emailVerified: user.emailVerified,
                image: user.image || null,
                role: user.role,
                createdAt: user.createdAt,
                updatedAt: user.updatedAt,
            },
        });
    }
    catch {
        res.status(500).json({ success: false, message: "Failed to get profile." });
    }
});
// PUT update profile
app.put("/api/users/profile", verifyToken, async (req, res) => {
    try {
        const user = req.user;
        const { name, image } = req.body;
        const updates = {};
        if (name !== undefined) {
            const trimmed = String(name).trim();
            if (!trimmed) {
                res.status(400).json({ success: false, message: "Name cannot be empty." });
                return;
            }
            if (trimmed.length < 3) {
                res.status(400).json({ success: false, message: "Name must be at least 3 characters." });
                return;
            }
            if (trimmed.length > 100) {
                res.status(400).json({ success: false, message: "Name cannot exceed 100 characters." });
                return;
            }
            updates.name = trimmed;
        }
        if (image !== undefined)
            updates.image = image || null;
        if (Object.keys(updates).length === 0) {
            res.status(400).json({ success: false, message: "Nothing to update." });
            return;
        }
        const db = await getDb();
        const usersCol = db.collection("user");
        updates.updatedAt = new Date();
        await usersCol.updateOne(userIdFilter(user._id), { $set: updates });
        const updated = await usersCol.findOne(userIdFilter(user._id));
        if (!updated) {
            res.status(404).json({ success: false, message: "User not found." });
            return;
        }
        res.status(200).json({
            success: true, message: "Profile updated.",
            data: {
                id: toIdString(updated._id),
                name: updated.name,
                email: updated.email,
                emailVerified: updated.emailVerified,
                image: updated.image || null,
                role: updated.role,
                createdAt: updated.createdAt,
                updatedAt: updated.updatedAt,
            },
        });
    }
    catch {
        res.status(500).json({ success: false, message: "Failed to update profile." });
    }
});
// PUT profile image
app.put("/api/users/profile-image", verifyToken, async (req, res) => {
    try {
        const user = req.user;
        const { imageUrl } = req.body;
        if (!imageUrl || typeof imageUrl !== "string") {
            res.status(400).json({ success: false, message: "Valid image URL required." });
            return;
        }
        try {
            new URL(imageUrl);
        }
        catch {
            res.status(400).json({ success: false, message: "Invalid URL format." });
            return;
        }
        const db = await getDb();
        await db.collection("user").updateOne(userIdFilter(user._id), { $set: { image: imageUrl, updatedAt: new Date() } });
        res.status(200).json({ success: true, message: "Profile image updated.", data: { image: imageUrl } });
    }
    catch {
        res.status(500).json({ success: false, message: "Failed to update image." });
    }
});
// PUT change password
app.put("/api/users/change-password", verifyToken, async (req, res) => {
    try {
        const user = req.user;
        const { currentPassword, newPassword, confirmNewPassword } = req.body;
        if (!currentPassword) {
            res.status(400).json({ success: false, message: "Current password required." });
            return;
        }
        if (!newPassword) {
            res.status(400).json({ success: false, message: "New password required." });
            return;
        }
        if (!confirmNewPassword) {
            res.status(400).json({ success: false, message: "Confirm password required." });
            return;
        }
        if (newPassword !== confirmNewPassword) {
            res.status(400).json({ success: false, message: "Passwords do not match." });
            return;
        }
        if (currentPassword === newPassword) {
            res.status(400).json({ success: false, message: "New password must be different." });
            return;
        }
        const pwError = checkPassword(newPassword);
        if (pwError) {
            res.status(400).json({ success: false, message: pwError });
            return;
        }
        const db = await getDb();
        const accountsCol = db.collection("account");
        const sessionsCol = db.collection("session");
        const userId = toIdString(user._id);
        const account = await accountsCol.findOne({ userId, providerId: "credential" });
        if (!account?.password) {
            res.status(400).json({ success: false, message: "No password account found." });
            return;
        }
        const isMatch = await bcryptjs_1.default.compare(currentPassword, account.password);
        if (!isMatch) {
            res.status(400).json({ success: false, message: "Current password is wrong." });
            return;
        }
        const hashed = await bcryptjs_1.default.hash(newPassword, 10);
        await accountsCol.updateOne({ userId, providerId: "credential" }, { $set: { password: hashed, updatedAt: new Date() } });
        await sessionsCol.deleteMany({ userId });
        res.status(200).json({ success: true, message: "Password changed. Please login again." });
    }
    catch {
        res.status(500).json({ success: false, message: "Failed to change password." });
    }
});
// DELETE self account
app.delete("/api/users/account", verifyToken, async (req, res) => {
    try {
        const user = req.user;
        const { password } = req.body;
        if (!password) {
            res.status(400).json({ success: false, message: "Password required." });
            return;
        }
        if (user.role === "admin") {
            res.status(403).json({ success: false, message: "Admin cannot self-delete." });
            return;
        }
        const db = await getDb();
        const usersCol = db.collection("user");
        const accountsCol = db.collection("account");
        const sessionsCol = db.collection("session");
        const propertiesCol = db.collection("properties");
        const bookingsCol = db.collection("bookings");
        const userId = toIdString(user._id);
        const account = await accountsCol.findOne({ userId, providerId: "credential" });
        if (!account?.password) {
            res.status(400).json({ success: false, message: "No password account found." });
            return;
        }
        const isMatch = await bcryptjs_1.default.compare(password, account.password);
        if (!isMatch) {
            res.status(400).json({ success: false, message: "Wrong password." });
            return;
        }
        const bookingFilter = user.role === "host" ? { hostId: userId } : { guestId: userId };
        const activeCount = await bookingsCol.countDocuments({ ...bookingFilter, status: { $in: ["confirmed", "pending", "checked-in"] } });
        if (activeCount > 0) {
            res.status(400).json({ success: false, message: `You have ${activeCount} active booking(s).` });
            return;
        }
        await sessionsCol.deleteMany({ userId });
        await accountsCol.deleteMany({ userId });
        if (user.role === "host")
            await propertiesCol.updateMany({ hostId: userId }, { $set: { status: "deleted", deletedAt: new Date() } });
        await usersCol.deleteOne(userIdFilter(user._id));
        res.status(200).json({ success: true, message: "Account permanently deleted." });
    }
    catch {
        res.status(500).json({ success: false, message: "Failed to delete account." });
    }
});
// ============================================================
// ADMIN USER ROUTES
// ============================================================
// GET all users
app.get("/api/admin/users", verifyToken, verifyAdmin, async (req, res) => {
    try {
        const db = await getDb();
        const col = db.collection("user");
        const currentUserId = toIdString(req.user._id);
        const { page, limit, skip } = getPagination(req.query, 100, 50);
        const filter = {};
        if (req.query.role && ["guest", "host", "admin"].includes(String(req.query.role)))
            filter.role = String(req.query.role);
        if (req.query.banned === "true")
            filter.banned = true;
        if (req.query.banned === "false")
            filter.banned = { $ne: true };
        if (req.query.search) {
            const term = String(req.query.search).trim();
            if (term)
                filter.$or = [
                    { name: { $regex: term, $options: "i" } },
                    { email: { $regex: term, $options: "i" } },
                ];
        }
        const [users, total] = await Promise.all([
            col.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
            col.countDocuments(filter),
        ]);
        const safeUsers = users.map((u) => ({
            id: toIdString(u._id),
            name: u.name,
            email: u.email,
            emailVerified: u.emailVerified,
            image: u.image || null,
            role: u.role,
            banned: u.banned ?? false,
            banReason: u.banReason ?? null,
            createdAt: u.createdAt,
            updatedAt: u.updatedAt,
        }));
        const totalPages = Math.ceil(total / limit);
        // Stats via aggregation (much faster than fetching all docs)
        const [roleStats, bannedCount] = await Promise.all([
            col.aggregate([
                { $group: { _id: "$role", count: { $sum: 1 } } },
            ]).toArray(),
            col.countDocuments({ banned: true }),
        ]);
        const roleMap = roleStats.reduce((acc, s) => ({ ...acc, [s._id]: s.count }), {});
        res.status(200).json({
            success: true,
            data: {
                users: safeUsers,
                currentUserId,
                pagination: { total, totalPages, currentPage: page, limit, hasNextPage: page < totalPages, hasPrevPage: page > 1 },
                stats: {
                    total: Object.values(roleMap).reduce((a, b) => a + b, 0),
                    admins: roleMap["admin"] || 0,
                    hosts: roleMap["host"] || 0,
                    guests: roleMap["guest"] || 0,
                    banned: bannedCount,
                },
            },
        });
    }
    catch {
        res.status(500).json({ success: false, message: "Failed to fetch users." });
    }
});
// GET single user
app.get("/api/admin/users/:id", verifyToken, verifyAdmin, async (req, res) => {
    try {
        const db = await getDb();
        const user = await findUserById(db.collection("user"), parseId(req.params.id));
        if (!user) {
            res.status(404).json({ success: false, message: "User not found." });
            return;
        }
        res.status(200).json({
            success: true,
            data: {
                id: toIdString(user._id),
                name: user.name,
                email: user.email,
                emailVerified: user.emailVerified,
                image: user.image || null,
                role: user.role,
                banned: user.banned ?? false,
                banReason: user.banReason ?? null,
                createdAt: user.createdAt,
                updatedAt: user.updatedAt,
            },
        });
    }
    catch {
        res.status(500).json({ success: false, message: "Failed to fetch user." });
    }
});
// PUT update role
app.put("/api/admin/users/:id/role", verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { role } = req.body;
        const validRoles = ["admin", "host", "guest"];
        if (!role || !validRoles.includes(role)) {
            res.status(400).json({ success: false, message: `Role must be: ${validRoles.join(", ")}` });
            return;
        }
        const db = await getDb();
        const usersCol = db.collection("user");
        const user = await findUserById(usersCol, parseId(req.params.id));
        if (!user) {
            res.status(404).json({ success: false, message: "User not found." });
            return;
        }
        const reqUserId = toIdString(req.user._id);
        const targetUserId = toIdString(user._id);
        if (reqUserId === targetUserId && role !== "admin") {
            res.status(400).json({ success: false, message: "Cannot change your own admin role." });
            return;
        }
        await usersCol.updateOne(userIdFilter(user._id), { $set: { role, updatedAt: new Date() } });
        res.status(200).json({ success: true, message: `Role updated to "${role}".`, data: { id: targetUserId, name: user.name, email: user.email, role } });
    }
    catch {
        res.status(500).json({ success: false, message: "Failed to update role." });
    }
});
// PUT ban/unban
app.put("/api/admin/users/:id/status", verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { banned, banReason } = req.body;
        if (typeof banned !== "boolean") {
            res.status(400).json({ success: false, message: "banned must be boolean." });
            return;
        }
        const db = await getDb();
        const usersCol = db.collection("user");
        const sessionsCol = db.collection("session");
        const user = await findUserById(usersCol, parseId(req.params.id));
        if (!user) {
            res.status(404).json({ success: false, message: "User not found." });
            return;
        }
        const reqUserId = toIdString(req.user._id);
        const targetUserId = toIdString(user._id);
        if (reqUserId === targetUserId) {
            res.status(400).json({ success: false, message: "Cannot block yourself." });
            return;
        }
        if (user.role === "admin") {
            res.status(400).json({ success: false, message: "Cannot block admin." });
            return;
        }
        const updateData = { banned, updatedAt: new Date() };
        if (banned) {
            updateData.banReason = banReason || "Blocked by admin";
            await sessionsCol.deleteMany({ userId: targetUserId });
        }
        else {
            updateData.banReason = null;
        }
        await usersCol.updateOne(userIdFilter(user._id), { $set: updateData });
        res.status(200).json({
            success: true,
            message: banned ? "User blocked." : "User unblocked.",
            data: { id: targetUserId, name: user.name, email: user.email, banned, banReason: banned ? banReason || "Blocked by admin" : null },
        });
    }
    catch {
        res.status(500).json({ success: false, message: "Failed to update status." });
    }
});
// DELETE user (admin)
app.delete("/api/admin/users/:id", verifyToken, verifyAdmin, async (req, res) => {
    try {
        const db = await getDb();
        const usersCol = db.collection("user");
        const accountsCol = db.collection("account");
        const sessionsCol = db.collection("session");
        const propertiesCol = db.collection("properties");
        const bookingsCol = db.collection("bookings");
        const user = await findUserById(usersCol, parseId(req.params.id));
        if (!user) {
            res.status(404).json({ success: false, message: "User not found." });
            return;
        }
        const reqUserId = toIdString(req.user._id);
        const targetUserId = toIdString(user._id);
        if (reqUserId === targetUserId) {
            res.status(400).json({ success: false, message: "Cannot delete yourself." });
            return;
        }
        const bookingFilter = user.role === "host" ? { hostId: targetUserId } : { guestId: targetUserId };
        const activeBookings = await bookingsCol.countDocuments({ ...bookingFilter, status: { $in: ["confirmed", "pending", "checked-in"] } });
        if (activeBookings > 0) {
            res.status(400).json({ success: false, message: `User has ${activeBookings} active booking(s).` });
            return;
        }
        await sessionsCol.deleteMany({ userId: targetUserId });
        await accountsCol.deleteMany({ userId: targetUserId });
        if (user.role === "host")
            await propertiesCol.updateMany({ hostId: targetUserId }, { $set: { status: "deleted", deletedAt: new Date() } });
        await usersCol.deleteOne(userIdFilter(user._id));
        res.status(200).json({ success: true, message: `User "${user.name}" deleted.` });
    }
    catch {
        res.status(500).json({ success: false, message: "Failed to delete user." });
    }
});
// ============================================================
// PROPERTY ROUTES — PUBLIC
// ⚠️ Specific routes MUST come before /:id parameterized routes
// ============================================================
// GET featured (homepage)
app.get("/api/properties/featured", async (_req, res) => {
    try {
        const db = await getDb();
        const properties = await db.collection("properties")
            .find({ status: "active", isFeatured: true })
            .sort({ rating: -1, reviewCount: -1 })
            .limit(8)
            .toArray();
        res.status(200).json({ success: true, data: properties.map(buildPropertyResponse) });
    }
    catch {
        res.status(500).json({ success: false, message: "Failed to fetch featured properties." });
    }
});
// GET homepage stats
app.get("/api/properties/stats", async (_req, res) => {
    try {
        const db = await getDb();
        const col = db.collection("properties");
        const [totalActive, totalFeatured, categoryStats, cityStats, avgRatingResult, priceStats] = await Promise.all([
            col.countDocuments({ status: "active" }),
            col.countDocuments({ status: "active", isFeatured: true }),
            col.aggregate([
                { $match: { status: "active" } },
                { $group: { _id: "$category", count: { $sum: 1 }, avgPrice: { $avg: "$price.perNight" } } },
                { $sort: { count: -1 } },
            ]).toArray(),
            col.aggregate([
                { $match: { status: "active" } },
                { $group: { _id: "$location.city", count: { $sum: 1 }, avgPrice: { $avg: "$price.perNight" }, country: { $first: "$location.country" } } },
                { $sort: { count: -1 } },
                { $limit: 8 },
            ]).toArray(),
            col.aggregate([
                { $match: { status: "active", rating: { $gt: 0 } } },
                { $group: { _id: null, avgRating: { $avg: "$rating" }, totalReviews: { $sum: "$reviewCount" } } },
            ]).toArray(),
            col.aggregate([
                { $match: { status: "active" } },
                { $group: { _id: null, minPrice: { $min: "$price.perNight" }, maxPrice: { $max: "$price.perNight" }, avgPrice: { $avg: "$price.perNight" } } },
            ]).toArray(),
        ]);
        res.status(200).json({
            success: true,
            data: {
                totalProperties: totalActive,
                totalFeatured,
                avgRating: avgRatingResult[0]?.avgRating ? parseFloat(avgRatingResult[0].avgRating.toFixed(1)) : 0,
                totalReviews: avgRatingResult[0]?.totalReviews || 0,
                byCategory: categoryStats.map((c) => ({ category: c._id, count: c.count, avgPrice: Math.round(c.avgPrice || 0) })),
                topCities: cityStats.map((c) => ({ city: c._id, country: c.country, count: c.count, avgPrice: Math.round(c.avgPrice || 0) })),
                priceRange: priceStats[0]
                    ? { min: Math.round(priceStats[0].minPrice || 0), max: Math.round(priceStats[0].maxPrice || 0), avg: Math.round(priceStats[0].avgPrice || 0) }
                    : { min: 0, max: 0, avg: 0 },
            },
        });
    }
    catch {
        res.status(500).json({ success: false, message: "Failed to fetch stats." });
    }
});
// GET host's own properties
app.get("/api/properties/host/my-properties", verifyToken, verifyHostOrAdmin, async (req, res) => {
    try {
        const user = req.user;
        const db = await getDb();
        const col = db.collection("properties");
        const { page, limit, skip } = getPagination(req.query, 50, 10);
        // Admin sees all, host sees own
        const baseFilter = user.role === "admin"
            ? { status: { $ne: "deleted" } }
            : { hostId: toIdString(user._id), status: { $ne: "deleted" } };
        if (req.query.status && VALID_STATUSES.includes(req.query.status) && req.query.status !== "deleted")
            baseFilter.status = String(req.query.status);
        if (req.query.search) {
            const term = String(req.query.search).trim();
            if (term)
                baseFilter.$or = [
                    { title: { $regex: term, $options: "i" } },
                    { "location.city": { $regex: term, $options: "i" } },
                ];
        }
        if (req.query.category && VALID_CATEGORIES.includes(req.query.category))
            baseFilter.category = String(req.query.category);
        let sort = { createdAt: -1 };
        if (req.query.sort === "oldest")
            sort = { createdAt: 1 };
        if (req.query.sort === "rating")
            sort = { rating: -1 };
        if (req.query.sort === "price-asc")
            sort = { "price.perNight": 1 };
        if (req.query.sort === "price-desc")
            sort = { "price.perNight": -1 };
        const [properties, total] = await Promise.all([
            col.find(baseFilter).sort(sort).skip(skip).limit(limit).toArray(),
            col.countDocuments(baseFilter),
        ]);
        const summaryMatch = user.role === "admin"
            ? { status: { $ne: "deleted" } }
            : { hostId: toIdString(user._id), status: { $ne: "deleted" } };
        const statusSummary = await col.aggregate([
            { $match: summaryMatch },
            { $group: { _id: "$status", count: { $sum: 1 } } },
        ]).toArray();
        const totalPages = Math.ceil(total / limit);
        res.status(200).json({
            success: true,
            data: {
                properties: properties.map(buildPropertyResponse),
                pagination: { total, totalPages, currentPage: page, limit, hasNextPage: page < totalPages, hasPrevPage: page > 1 },
                statusSummary: statusSummary.reduce((acc, s) => ({ ...acc, [s._id]: s.count }), {}),
            },
        });
    }
    catch {
        res.status(500).json({ success: false, message: "Failed to fetch properties." });
    }
});
// POST upload images → Cloudinary
app.post("/api/properties/upload-images", verifyToken, verifyHostOrAdmin, upload.array("images", MAX_FILES), async (req, res) => {
    try {
        // ✅ Fix 4: cast req.files to array (multer attaches it)
        const files = req.files || [];
        if (files.length === 0) {
            res.status(400).json({ success: false, message: "No files uploaded." });
            return;
        }
        const userId = toIdString(req.user._id);
        const folder = `properties/${userId}`;
        const uploadedUrls = [];
        const errors = [];
        await Promise.all(files.map(async (file, idx) => {
            try {
                const filename = `img_${Date.now()}_${idx}`;
                const result = await uploadToCloudinary(file.buffer, folder, filename);
                uploadedUrls.push(result.url);
            }
            catch (err) {
                errors.push(`File ${file.originalname}: ${err.message}`);
            }
        }));
        if (uploadedUrls.length === 0) {
            res.status(500).json({ success: false, message: "All uploads failed.", errors });
            return;
        }
        res.status(200).json({
            success: true,
            message: `${uploadedUrls.length} image(s) uploaded successfully.`,
            data: { urls: uploadedUrls, count: uploadedUrls.length, ...(errors.length > 0 && { partialErrors: errors }) },
        });
    }
    catch (error) {
        // Multer-level errors
        if (error.code === "LIMIT_FILE_SIZE") {
            res.status(400).json({ success: false, message: `File too large. Max ${MAX_FILE_SIZE / 1024 / 1024}MB.` });
            return;
        }
        if (error.code === "LIMIT_FILE_COUNT") {
            res.status(400).json({ success: false, message: `Too many files. Max ${MAX_FILES}.` });
            return;
        }
        if (error.message?.includes("Invalid file type")) {
            res.status(400).json({ success: false, message: error.message });
            return;
        }
        console.error("Image upload error:", error);
        res.status(500).json({ success: false, message: "Failed to upload images." });
    }
});
// DELETE image from Cloudinary
app.delete("/api/properties/delete-image", verifyToken, verifyHostOrAdmin, async (req, res) => {
    try {
        const { imageUrl, propertyId } = req.body;
        if (!imageUrl || typeof imageUrl !== "string") {
            res.status(400).json({ success: false, message: "imageUrl is required." });
            return;
        }
        // Must be our Cloudinary account
        const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
        if (cloudName && !imageUrl.includes(`res.cloudinary.com/${cloudName}`)) {
            res.status(400).json({ success: false, message: "Invalid image URL." });
            return;
        }
        // Ownership check if propertyId provided
        if (propertyId) {
            const objectId = toObjectId(String(propertyId));
            if (objectId) {
                const db = await getDb();
                const property = await db.collection("properties").findOne({ _id: objectId });
                if (property && req.user.role !== "admin" && property.hostId !== toIdString(req.user._id)) {
                    res.status(403).json({ success: false, message: "Not authorized." });
                    return;
                }
            }
        }
        await deleteFromCloudinary(imageUrl);
        res.status(200).json({ success: true, message: "Image deleted successfully." });
    }
    catch {
        res.status(500).json({ success: false, message: "Failed to delete image." });
    }
});
// GET all active properties (public, filterable)
app.get("/api/properties", async (req, res) => {
    try {
        const db = await getDb();
        const col = db.collection("properties");
        const { page, limit, skip } = getPagination(req.query, 50, 12);
        const filter = { status: "active" };
        if (req.query.category && VALID_CATEGORIES.includes(req.query.category))
            filter.category = String(req.query.category);
        if (req.query.city)
            filter["location.city"] = { $regex: String(req.query.city).trim(), $options: "i" };
        if (req.query.country)
            filter["location.country"] = { $regex: String(req.query.country).trim(), $options: "i" };
        if (req.query.minPrice || req.query.maxPrice) {
            filter["price.perNight"] = {};
            if (req.query.minPrice) {
                const n = Number(req.query.minPrice);
                if (!isNaN(n) && n >= 0)
                    filter["price.perNight"].$gte = n;
            }
            if (req.query.maxPrice) {
                const n = Number(req.query.maxPrice);
                if (!isNaN(n) && n > 0)
                    filter["price.perNight"].$lte = n;
            }
        }
        if (req.query.minRating) {
            const n = Number(req.query.minRating);
            if (!isNaN(n) && n >= 0 && n <= 5)
                filter.rating = { $gte: n };
        }
        if (req.query.guests) {
            const n = Number(req.query.guests);
            if (!isNaN(n) && n > 0)
                filter["details.maxGuests"] = { $gte: n };
        }
        if (req.query.bedrooms) {
            const n = Number(req.query.bedrooms);
            if (!isNaN(n) && n >= 0)
                filter["details.bedrooms"] = { $gte: n };
        }
        if (req.query.bathrooms) {
            const n = Number(req.query.bathrooms);
            if (!isNaN(n) && n >= 0)
                filter["details.bathrooms"] = { $gte: n };
        }
        if (req.query.amenities) {
            const list = String(req.query.amenities).split(",").map((a) => a.trim()).filter((a) => VALID_AMENITIES.includes(a));
            if (list.length > 0)
                filter.amenities = { $all: list };
        }
        if (req.query.search) {
            const term = String(req.query.search).trim();
            if (term)
                filter.$or = [
                    { title: { $regex: term, $options: "i" } },
                    { description: { $regex: term, $options: "i" } },
                    { "location.city": { $regex: term, $options: "i" } },
                    { "location.country": { $regex: term, $options: "i" } },
                    { "location.address": { $regex: term, $options: "i" } },
                ];
        }
        if (req.query.featured === "true")
            filter.isFeatured = true;
        let sort = { createdAt: -1 };
        switch (req.query.sort) {
            case "price-asc":
                sort = { "price.perNight": 1 };
                break;
            case "price-desc":
                sort = { "price.perNight": -1 };
                break;
            case "rating-desc":
                sort = { rating: -1 };
                break;
            case "rating-asc":
                sort = { rating: 1 };
                break;
            case "oldest":
                sort = { createdAt: 1 };
                break;
            case "featured":
                sort = { isFeatured: -1, rating: -1 };
                break;
            case "popular":
                sort = { reviewCount: -1, rating: -1 };
                break;
        }
        const [properties, total] = await Promise.all([
            col.find(filter).sort(sort).skip(skip).limit(limit).toArray(),
            col.countDocuments(filter),
        ]);
        const totalPages = Math.ceil(total / limit);
        res.status(200).json({
            success: true,
            data: {
                properties: properties.map(buildPropertyResponse),
                pagination: { total, totalPages, currentPage: page, limit, hasNextPage: page < totalPages, hasPrevPage: page > 1 },
                filters: { applied: Object.keys(req.query).filter((k) => !["page", "limit", "sort"].includes(k)) },
            },
        });
    }
    catch (error) {
        console.error("Get properties error:", error);
        res.status(500).json({ success: false, message: "Failed to fetch properties." });
    }
});
// POST create property (host/admin)
app.post("/api/properties", verifyToken, verifyHostOrAdmin, async (req, res) => {
    try {
        const user = req.user;
        const validation = validatePropertyInput(req.body);
        if (!validation.valid) {
            res.status(400).json({ success: false, message: validation.error });
            return;
        }
        const db = await getDb();
        const col = db.collection("properties");
        // Max 50 properties per host
        if (user.role !== "admin") {
            const count = await col.countDocuments({ hostId: toIdString(user._id), status: { $ne: "deleted" } });
            if (count >= 50) {
                res.status(400).json({ success: false, message: "Maximum 50 properties allowed per host." });
                return;
            }
        }
        const now = new Date();
        const requestedStatus = req.body.status;
        const validDraftStatuses = ["draft", "pending"];
        const status = requestedStatus && validDraftStatuses.includes(requestedStatus)
            ? requestedStatus
            : user.role === "admin"
                ? "active"
                : "pending";
        const newProperty = {
            ...validation.data,
            hostId: toIdString(user._id),
            status,
            rating: 0,
            reviewCount: 0,
            isFeatured: false,
            availability: [],
            createdAt: now,
            updatedAt: now,
        };
        const result = await col.insertOne(newProperty);
        res.status(201).json({
            success: true,
            message: user.role === "admin" ? "Property published successfully." : "Property submitted for admin review.",
            data: buildPropertyResponse({ ...newProperty, _id: result.insertedId }),
        });
    }
    catch (error) {
        console.error("Create property error:", error);
        res.status(500).json({ success: false, message: "Failed to create property." });
    }
});
// ⚠️ /:id routes start here — must come AFTER all specific routes above
// GET single property detail (public)
app.get("/api/properties/:id", async (req, res) => {
    try {
        const id = parseId(req.params.id);
        const objectId = toObjectId(id);
        if (!objectId) {
            res.status(400).json({ success: false, message: "Invalid property ID." });
            return;
        }
        const db = await getDb();
        const col = db.collection("properties");
        const usersCol = db.collection("user");
        const property = await col.findOne({ _id: objectId, status: { $ne: "deleted" } });
        if (!property) {
            res.status(404).json({ success: false, message: "Property not found." });
            return;
        }
        // Host info
        let hostInfo = null;
        if (property.hostId) {
            const host = await findUserById(usersCol, String(property.hostId));
            if (host)
                hostInfo = { id: toIdString(host._id), name: host.name, image: host.image || null, createdAt: host.createdAt };
        }
        // Related: same category + city, max 4
        const related = await col.find({
            _id: { $ne: objectId }, status: "active",
            category: property.category, "location.city": property.location?.city,
        }).sort({ rating: -1 }).limit(4).toArray();
        res.status(200).json({
            success: true,
            data: { property: buildPropertyResponse(property), host: hostInfo, relatedProperties: related.map(buildPropertyResponse) },
        });
    }
    catch (error) {
        console.error("Get property detail error:", error);
        res.status(500).json({ success: false, message: "Failed to fetch property." });
    }
});
// PUT update property (host owner / admin)
app.put("/api/properties/:id", verifyToken, verifyHostOrAdmin, async (req, res) => {
    try {
        const id = parseId(req.params.id);
        const objectId = toObjectId(id);
        const user = req.user;
        if (!objectId) {
            res.status(400).json({ success: false, message: "Invalid property ID." });
            return;
        }
        const db = await getDb();
        const col = db.collection("properties");
        const existing = await col.findOne({ _id: objectId, status: { $ne: "deleted" } });
        if (!existing) {
            res.status(404).json({ success: false, message: "Property not found." });
            return;
        }
        if (user.role !== "admin" && existing.hostId !== toIdString(user._id)) {
            res.status(403).json({ success: false, message: "You can only update your own properties." });
            return;
        }
        const validation = validatePropertyInput(req.body);
        if (!validation.valid) {
            res.status(400).json({ success: false, message: validation.error });
            return;
        }
        const updates = { ...validation.data, updatedAt: new Date() };
        // Host editing rejected/inactive → reset to pending for re-review
        if (user.role !== "admin" && (existing.status === "rejected" || existing.status === "inactive")) {
            updates.status = "pending";
            updates.rejectionReason = null;
        }
        await col.updateOne({ _id: objectId }, { $set: updates });
        const updated = await col.findOne({ _id: objectId });
        res.status(200).json({ success: true, message: "Property updated successfully.", data: buildPropertyResponse(updated) });
    }
    catch (error) {
        console.error("Update property error:", error);
        res.status(500).json({ success: false, message: "Failed to update property." });
    }
});
// DELETE property - soft delete (host owner / admin)
app.delete("/api/properties/:id", verifyToken, verifyHostOrAdmin, async (req, res) => {
    try {
        const id = parseId(req.params.id);
        const objectId = toObjectId(id);
        const user = req.user;
        if (!objectId) {
            res.status(400).json({ success: false, message: "Invalid property ID." });
            return;
        }
        const db = await getDb();
        const col = db.collection("properties");
        const bookingsCol = db.collection("bookings");
        const existing = await col.findOne({ _id: objectId, status: { $ne: "deleted" } });
        if (!existing) {
            res.status(404).json({ success: false, message: "Property not found." });
            return;
        }
        if (user.role !== "admin" && existing.hostId !== toIdString(user._id)) {
            res.status(403).json({ success: false, message: "You can only delete your own properties." });
            return;
        }
        const activeBookings = await bookingsCol.countDocuments({ propertyId: id, status: { $in: ["confirmed", "pending", "checked-in"] } });
        if (activeBookings > 0) {
            res.status(400).json({ success: false, message: `Cannot delete. ${activeBookings} active booking(s) exist.` });
            return;
        }
        await col.updateOne({ _id: objectId }, { $set: { status: "deleted", deletedAt: new Date(), updatedAt: new Date() } });
        res.status(200).json({ success: true, message: "Property deleted successfully.", data: { id } });
    }
    catch (error) {
        console.error("Delete property error:", error);
        res.status(500).json({ success: false, message: "Failed to delete property." });
    }
});
// PUT toggle active/inactive status
app.put("/api/properties/:id/status", verifyToken, verifyHostOrAdmin, async (req, res) => {
    try {
        const id = parseId(req.params.id);
        const objectId = toObjectId(id);
        const { status } = req.body;
        const user = req.user;
        if (!objectId) {
            res.status(400).json({ success: false, message: "Invalid property ID." });
            return;
        }
        const allowed = user.role === "admin" ? ["active", "inactive", "draft"] : ["active", "inactive"];
        if (!status || !allowed.includes(status)) {
            res.status(400).json({ success: false, message: `Status must be: ${allowed.join(", ")}` });
            return;
        }
        const db = await getDb();
        const col = db.collection("properties");
        const existing = await col.findOne({ _id: objectId, status: { $ne: "deleted" } });
        if (!existing) {
            res.status(404).json({ success: false, message: "Property not found." });
            return;
        }
        if (user.role !== "admin" && existing.hostId !== toIdString(user._id)) {
            res.status(403).json({ success: false, message: "You can only update your own properties." });
            return;
        }
        if (user.role !== "admin" && existing.status === "pending") {
            res.status(400).json({ success: false, message: "Pending properties need admin approval first." });
            return;
        }
        await col.updateOne({ _id: objectId }, { $set: { status, updatedAt: new Date() } });
        res.status(200).json({ success: true, message: `Status updated to "${status}".`, data: { id, status } });
    }
    catch {
        res.status(500).json({ success: false, message: "Failed to update status." });
    }
});
// PUT update availability calendar
app.put("/api/properties/:id/availability", verifyToken, verifyHostOrAdmin, async (req, res) => {
    try {
        const id = parseId(req.params.id);
        const objectId = toObjectId(id);
        const { availability } = req.body;
        const user = req.user;
        if (!objectId) {
            res.status(400).json({ success: false, message: "Invalid property ID." });
            return;
        }
        if (!Array.isArray(availability)) {
            res.status(400).json({ success: false, message: "Availability must be an array." });
            return;
        }
        if (availability.length > 365) {
            res.status(400).json({ success: false, message: "Max 365 entries allowed." });
            return;
        }
        const dateRe = /^\d{4}-\d{2}-\d{2}$/;
        const validReasons = ["booked", "maintenance", "owner-use"];
        for (const item of availability) {
            if (!item.date || !dateRe.test(String(item.date))) {
                res.status(400).json({ success: false, message: `Invalid date: "${item.date}". Use YYYY-MM-DD.` });
                return;
            }
            if (typeof item.isBlocked !== "boolean") {
                res.status(400).json({ success: false, message: "isBlocked must be boolean." });
                return;
            }
            if (item.reason && !validReasons.includes(String(item.reason))) {
                res.status(400).json({ success: false, message: `Reason must be: ${validReasons.join(", ")}` });
                return;
            }
        }
        const db = await getDb();
        const col = db.collection("properties");
        const existing = await col.findOne({ _id: objectId, status: { $ne: "deleted" } });
        if (!existing) {
            res.status(404).json({ success: false, message: "Property not found." });
            return;
        }
        if (user.role !== "admin" && existing.hostId !== toIdString(user._id)) {
            res.status(403).json({ success: false, message: "You can only update your own properties." });
            return;
        }
        // Deduplicate by date — last entry wins
        const deduplicated = Object.values(availability.reduce((acc, item) => {
            acc[item.date] = item;
            return acc;
        }, {}));
        await col.updateOne({ _id: objectId }, { $set: { availability: deduplicated, updatedAt: new Date() } });
        res.status(200).json({ success: true, message: "Availability updated.", data: { id, availability: deduplicated } });
    }
    catch {
        res.status(500).json({ success: false, message: "Failed to update availability." });
    }
});
// POST duplicate/clone a property
app.post("/api/properties/:id/duplicate", verifyToken, verifyHostOrAdmin, async (req, res) => {
    try {
        const id = parseId(req.params.id);
        const objectId = toObjectId(id);
        const user = req.user;
        if (!objectId) {
            res.status(400).json({ success: false, message: "Invalid property ID." });
            return;
        }
        const db = await getDb();
        const col = db.collection("properties");
        if (user.role !== "admin") {
            const count = await col.countDocuments({ hostId: toIdString(user._id), status: { $ne: "deleted" } });
            if (count >= 50) {
                res.status(400).json({ success: false, message: "Maximum 50 properties allowed per host." });
                return;
            }
        }
        const existing = await col.findOne({ _id: objectId, status: { $ne: "deleted" } });
        if (!existing) {
            res.status(404).json({ success: false, message: "Property not found." });
            return;
        }
        if (user.role !== "admin" && existing.hostId !== toIdString(user._id)) {
            res.status(403).json({ success: false, message: "You can only duplicate your own properties." });
            return;
        }
        const now = new Date();
        // ✅ Fix 5: destructure _id out, then build complete PropertyDoc explicitly
        const { _id: _removed, createdAt: _ca, updatedAt: _ua, ...restFields } = existing;
        const duplicated = {
            // spread all fields from existing (hostId, title, desc, category, location, price, details, amenities, images, houseRules)
            hostId: restFields.hostId,
            title: `${restFields.title} (Copy)`,
            description: restFields.description,
            category: restFields.category,
            location: restFields.location,
            price: restFields.price,
            details: restFields.details,
            amenities: restFields.amenities || [],
            images: restFields.images || [],
            houseRules: restFields.houseRules,
            // reset system fields
            availability: [],
            status: "draft", // always draft for duplicates
            rating: 0,
            reviewCount: 0,
            isFeatured: false,
            rejectionReason: undefined,
            deletedAt: undefined,
            createdAt: now,
            updatedAt: now,
        };
        const result = await col.insertOne(duplicated);
        res.status(201).json({
            success: true,
            message: "Property duplicated. Edit and submit when ready.",
            data: buildPropertyResponse({ ...duplicated, _id: result.insertedId }),
        });
    }
    catch (error) {
        console.error("Duplicate property error:", error);
        res.status(500).json({ success: false, message: "Failed to duplicate property." });
    }
});
// ============================================================
// PROPERTY ROUTES — ADMIN ONLY
// ============================================================
// GET all properties with admin filters
app.get("/api/admin/properties", verifyToken, verifyAdmin, async (req, res) => {
    try {
        const db = await getDb();
        const col = db.collection("properties");
        const { page, limit, skip } = getPagination(req.query, 100, 20);
        const filter = {};
        if (req.query.status) {
            if (req.query.status !== "all" && VALID_STATUSES.includes(req.query.status))
                filter.status = String(req.query.status);
        }
        else {
            filter.status = { $ne: "deleted" };
        }
        if (req.query.category && VALID_CATEGORIES.includes(req.query.category))
            filter.category = String(req.query.category);
        if (req.query.hostId)
            filter.hostId = String(req.query.hostId);
        if (req.query.isFeatured === "true")
            filter.isFeatured = true;
        if (req.query.search) {
            const term = String(req.query.search).trim();
            if (term)
                filter.$or = [
                    { title: { $regex: term, $options: "i" } },
                    { "location.city": { $regex: term, $options: "i" } },
                    { "location.country": { $regex: term, $options: "i" } },
                ];
        }
        let sort = { createdAt: -1 };
        if (req.query.sort === "oldest")
            sort = { createdAt: 1 };
        if (req.query.sort === "rating")
            sort = { rating: -1 };
        if (req.query.sort === "price-asc")
            sort = { "price.perNight": 1 };
        if (req.query.sort === "price-desc")
            sort = { "price.perNight": -1 };
        if (req.query.sort === "popular")
            sort = { reviewCount: -1 };
        const [properties, total] = await Promise.all([
            col.find(filter).sort(sort).skip(skip).limit(limit).toArray(),
            col.countDocuments(filter),
        ]);
        const statsResult = await col.aggregate([{ $group: { _id: "$status", count: { $sum: 1 } } }]).toArray();
        const stats = statsResult.reduce((acc, s) => ({ ...acc, [s._id]: s.count }), {});
        const totalPages = Math.ceil(total / limit);
        res.status(200).json({
            success: true,
            data: {
                properties: properties.map(buildPropertyResponse),
                pagination: { total, totalPages, currentPage: page, limit, hasNextPage: page < totalPages, hasPrevPage: page > 1 },
                stats: {
                    total: Object.values(stats).reduce((a, b) => a + b, 0),
                    active: stats["active"] || 0,
                    pending: stats["pending"] || 0,
                    inactive: stats["inactive"] || 0,
                    draft: stats["draft"] || 0,
                    rejected: stats["rejected"] || 0,
                    deleted: stats["deleted"] || 0,
                },
            },
        });
    }
    catch {
        res.status(500).json({ success: false, message: "Failed to fetch properties." });
    }
});
// PUT approve pending property
app.put("/api/admin/properties/:id/approve", verifyToken, verifyAdmin, async (req, res) => {
    try {
        const id = parseId(req.params.id);
        const objectId = toObjectId(id);
        if (!objectId) {
            res.status(400).json({ success: false, message: "Invalid property ID." });
            return;
        }
        const db = await getDb();
        const col = db.collection("properties");
        const existing = await col.findOne({ _id: objectId, status: { $ne: "deleted" } });
        if (!existing) {
            res.status(404).json({ success: false, message: "Property not found." });
            return;
        }
        if (existing.status !== "pending") {
            res.status(400).json({ success: false, message: `Only pending properties can be approved. Current: "${existing.status}"` });
            return;
        }
        await col.updateOne({ _id: objectId }, { $set: { status: "active", rejectionReason: null, updatedAt: new Date() } });
        res.status(200).json({ success: true, message: "Property approved and published.", data: { id, status: "active" } });
    }
    catch {
        res.status(500).json({ success: false, message: "Failed to approve property." });
    }
});
// PUT reject pending property
app.put("/api/admin/properties/:id/reject", verifyToken, verifyAdmin, async (req, res) => {
    try {
        const id = parseId(req.params.id);
        const objectId = toObjectId(id);
        const { reason } = req.body;
        if (!objectId) {
            res.status(400).json({ success: false, message: "Invalid property ID." });
            return;
        }
        if (!reason || typeof reason !== "string" || reason.trim().length < 5) {
            res.status(400).json({ success: false, message: "Rejection reason required (min 5 chars)." });
            return;
        }
        if (reason.trim().length > 500) {
            res.status(400).json({ success: false, message: "Reason cannot exceed 500 characters." });
            return;
        }
        const db = await getDb();
        const col = db.collection("properties");
        const existing = await col.findOne({ _id: objectId, status: { $ne: "deleted" } });
        if (!existing) {
            res.status(404).json({ success: false, message: "Property not found." });
            return;
        }
        if (existing.status !== "pending") {
            res.status(400).json({ success: false, message: `Only pending properties can be rejected. Current: "${existing.status}"` });
            return;
        }
        await col.updateOne({ _id: objectId }, { $set: { status: "rejected", rejectionReason: reason.trim(), updatedAt: new Date() } });
        res.status(200).json({ success: true, message: "Property rejected.", data: { id, status: "rejected", rejectionReason: reason.trim() } });
    }
    catch {
        res.status(500).json({ success: false, message: "Failed to reject property." });
    }
});
// PUT toggle featured
app.put("/api/admin/properties/:id/feature", verifyToken, verifyAdmin, async (req, res) => {
    try {
        const id = parseId(req.params.id);
        const objectId = toObjectId(id);
        const { isFeatured } = req.body;
        if (!objectId) {
            res.status(400).json({ success: false, message: "Invalid property ID." });
            return;
        }
        if (typeof isFeatured !== "boolean") {
            res.status(400).json({ success: false, message: "isFeatured must be boolean." });
            return;
        }
        const db = await getDb();
        const col = db.collection("properties");
        const existing = await col.findOne({ _id: objectId, status: { $ne: "deleted" } });
        if (!existing) {
            res.status(404).json({ success: false, message: "Property not found." });
            return;
        }
        if (isFeatured && existing.status !== "active") {
            res.status(400).json({ success: false, message: "Only active properties can be featured." });
            return;
        }
        await col.updateOne({ _id: objectId }, { $set: { isFeatured, updatedAt: new Date() } });
        res.status(200).json({ success: true, message: isFeatured ? "Property featured." : "Property unfeatured.", data: { id, isFeatured } });
    }
    catch {
        res.status(500).json({ success: false, message: "Failed to update featured status." });
    }
});
// PUT update rating (called by review system)
app.put("/api/admin/properties/:id/rating", verifyToken, verifyAdmin, async (req, res) => {
    try {
        const id = parseId(req.params.id);
        const objectId = toObjectId(id);
        const { rating, reviewCount } = req.body;
        if (!objectId) {
            res.status(400).json({ success: false, message: "Invalid property ID." });
            return;
        }
        const ratingNum = Number(rating);
        if (isNaN(ratingNum) || ratingNum < 0 || ratingNum > 5) {
            res.status(400).json({ success: false, message: "Rating must be 0–5." });
            return;
        }
        const updates = { rating: parseFloat(ratingNum.toFixed(1)), updatedAt: new Date() };
        if (reviewCount !== undefined) {
            const n = Number(reviewCount);
            if (!isNaN(n) && n >= 0)
                updates.reviewCount = Math.floor(n);
        }
        const db = await getDb();
        const col = db.collection("properties");
        const existing = await col.findOne({ _id: objectId, status: { $ne: "deleted" } });
        if (!existing) {
            res.status(404).json({ success: false, message: "Property not found." });
            return;
        }
        await col.updateOne({ _id: objectId }, { $set: updates });
        res.status(200).json({ success: true, message: "Rating updated.", data: { id, ...updates } });
    }
    catch {
        res.status(500).json({ success: false, message: "Failed to update rating." });
    }
});
// DELETE hard delete (admin only, sparingly)
app.delete("/api/admin/properties/:id", verifyToken, verifyAdmin, async (req, res) => {
    try {
        const id = parseId(req.params.id);
        const objectId = toObjectId(id);
        if (!objectId) {
            res.status(400).json({ success: false, message: "Invalid property ID." });
            return;
        }
        const db = await getDb();
        const col = db.collection("properties");
        const bookingsCol = db.collection("bookings");
        const existing = await col.findOne({ _id: objectId });
        if (!existing) {
            res.status(404).json({ success: false, message: "Property not found." });
            return;
        }
        const activeBookings = await bookingsCol.countDocuments({ propertyId: id, status: { $in: ["confirmed", "pending", "checked-in"] } });
        if (activeBookings > 0) {
            res.status(400).json({ success: false, message: `Cannot delete. ${activeBookings} active booking(s) exist.` });
            return;
        }
        await col.deleteOne({ _id: objectId });
        res.status(200).json({ success: true, message: `Property "${existing.title}" permanently deleted.`, data: { id } });
    }
    catch {
        res.status(500).json({ success: false, message: "Failed to delete property." });
    }
});
// ============================================================
// GLOBAL ERROR HANDLER
// ============================================================
app.use((err, _req, res, _next) => {
    console.error("Unhandled error:", err);
    res.status(500).json({
        success: false,
        message: "Internal server error",
        error: process.env.NODE_ENV === "production" ? undefined : err.message,
    });
});
// Local dev only
if (process.env.NODE_ENV !== "production") {
    const port = Number(process.env.PORT) || 5000;
    app.listen(port, () => console.log(`🚀 Server running on port ${port}`));
}
exports.default = app;
//# sourceMappingURL=index.js.map