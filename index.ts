import express, { Request, Response, NextFunction } from "express";
import helmet from "helmet";
import cors from "cors";
import dotenv from "dotenv";
import {
    MongoClient,
    ServerApiVersion,
    ObjectId,
    Filter,
    Document,
} from "mongodb";
import bcrypt from "bcryptjs";
import { createRemoteJWKSet, jwtVerify } from "jose-cjs";
import multer, { FileFilterCallback } from "multer";
import {
    v2 as cloudinary,
    UploadApiResponse,
    UploadApiErrorResponse,
} from "cloudinary";
import { Readable } from "stream";
import Stripe from "stripe";

dotenv.config();

const app = express();

app.use(helmet());
app.use(
    cors({
        origin: process.env.FRONTEND_URL,
        credentials: true,
        methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization"],
    }),
);

// Stripe webhook MUST use raw body — register BEFORE express.json()
app.post("/api/webhooks/stripe", express.raw({ type: "application/json" }), stripeWebhookHandler);

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

const uri: string = process.env.MONGODB_URI || "";
const dbName: string = process.env.DB_NAME || "StayEase";
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:3000";

// ============================================================
// CLOUDINARY CONFIG
// ============================================================

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME || "",
    api_key: process.env.CLOUDINARY_API_KEY || "",
    api_secret: process.env.CLOUDINARY_API_SECRET || "",
});

// ============================================================
// STRIPE CONFIG
// ============================================================

const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const stripe = STRIPE_SECRET_KEY
    ? new Stripe(STRIPE_SECRET_KEY, { apiVersion: "2025-12-01" as any })
    : null;

// Stripe webhook handler — defined here so it's hoisted for route registration before express.json()
async function stripeWebhookHandler(req: Request, res: Response): Promise<void> {
    if (!stripe) {
        res.status(503).json({ success: false, message: "Stripe not configured." });
        return;
    }
    const sig = req.headers["stripe-signature"] as string;

    let event: Stripe.Event;
    try {
        event = stripe.webhooks.constructEvent(
            req.body,
            sig,
            process.env.STRIPE_WEBHOOK_SECRET || "",
        );
    } catch (err: any) {
        console.error("Webhook signature verification failed:", err.message);
        res.status(400).json({ success: false, message: `Webhook Error: ${err.message}` });
        return;
    }

    try {
        const db = await getDb();
        const bookingsCol = db.collection("bookings");
        const transactionsCol = db.collection("transactions");

        switch (event.type) {
            case "checkout.session.completed": {
                const session = event.data.object as Stripe.Checkout.Session;
                const bookingId = session.metadata?.bookingId;

                if (!bookingId) {
                    console.warn("Webhook: No bookingId in session metadata");
                    res.status(200).json({ received: true });
                    return;
                }

                const objectId = toObjectId(parseId(bookingId));
                if (!objectId) {
                    console.warn("Webhook: Invalid bookingId:", bookingId);
                    res.status(200).json({ received: true });
                    return;
                }

                const booking = await bookingsCol.findOne({ _id: objectId }) as any;
                if (!booking) {
                    console.warn("Webhook: Booking not found:", bookingId);
                    res.status(200).json({ received: true });
                    return;
                }

                // Idempotency check — prevent duplicate webhook processing
                const idempotencyKey = `stripe_${session.id}`;
                const existingTxn = await transactionsCol.findOne({ transactionId: idempotencyKey });
                if (existingTxn) {
                    console.log(`Webhook: Session ${session.id} already processed, skipping`);
                    res.status(200).json({ received: true });
                    return;
                }

                await bookingsCol.updateOne(
                    { _id: objectId },
                    { $set: { status: "confirmed", updatedAt: new Date() } },
                );

                const txnId = idempotencyKey;
                await transactionsCol.insertOne({
                    userId: booking.guestId,
                    bookingId,
                    type: "payment" as const,
                    amount: booking.totalAmount,
                    currency: (session.currency || process.env.STRIPE_CURRENCY || "usd").toUpperCase(),
                    method: "card" as const,
                    status: "success" as const,
                    transactionId: txnId,
                    description: `Payment for booking at ${booking.propertyTitle}`,
                    createdAt: new Date(),
                });

                console.log(`✅ Booking ${bookingId} confirmed via Stripe webhook (session: ${session.id})`);
                break;
            }

            case "checkout.session.expired": {
                const session = event.data.object as Stripe.Checkout.Session;
                const bookingId = session.metadata?.bookingId;

                if (bookingId) {
                    const objectId = toObjectId(parseId(bookingId));
                    if (objectId) {
                        await bookingsCol.updateOne(
                            { _id: objectId, status: "pending" },
                            {
                                $set: {
                                    status: "cancelled",
                                    cancelledBy: "guest" as const,
                                    cancellationReason: "Payment session expired",
                                    updatedAt: new Date(),
                                },
                            },
                        );
                        console.log(`Booking ${bookingId} cancelled due to expired payment session`);
                    }
                }
                break;
            }

            default:
                console.log(`Unhandled event type: ${event.type}`);
        }

        res.status(200).json({ received: true });
    } catch (error) {
        console.error("Webhook handler error:", error);
        res.status(200).json({ received: true });
    }
}

// ============================================================
// MULTER CONFIG - memory storage (buffer → Cloudinary)
// ============================================================

const ALLOWED_MIME_TYPES = [
    "image/jpeg",
    "image/jpg",
    "image/png",
    "image/webp",
];
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5 MB
const MAX_FILES = 10;

// ✅ Fix 1: FileFilterCallback imported from multer (not Express.Multer)
const multerFilter = (
    _req: Request,
    file: Express.Multer.File,
    cb: FileFilterCallback,
) => {
    if (ALLOWED_MIME_TYPES.includes(file.mimetype)) {
        cb(null, true);
    } else {
        // cast because multer's CB overloads are strict
        cb(
            new Error(
                `Invalid file type: ${file.mimetype}. Only JPEG, PNG, WebP allowed.`,
            ) as any,
            false,
        );
    }
};

const upload = multer({
    storage: multer.memoryStorage(),
    fileFilter: multerFilter,
    limits: { fileSize: MAX_FILE_SIZE, files: MAX_FILES },
});

// ============================================================
// TYPES & INTERFACES
// ============================================================

interface PropertyLocation {
    address: string;
    city: string;
    country: string;
    coordinates?: { lat: number; lng: number };
}

interface PropertyPrice {
    perNight: number;
    weeklyDiscount?: number;
    monthlyDiscount?: number;
    cleaningFee?: number;
    serviceFee?: number;
}

interface PropertyDetails {
    bedrooms: number;
    bathrooms: number;
    maxGuests: number;
    beds?: number;
    area?: number;
}

interface HouseRules {
    smokingAllowed: boolean;
    petsAllowed: boolean;
    partiesAllowed: boolean;
    checkInTime: string;
    checkOutTime: string;
    quietHoursStart?: string;
    quietHoursEnd?: string;
    additionalRules?: string[];
}

interface AvailabilityDate {
    date: string;
    isBlocked: boolean;
    reason?: string;
}

type PropertyCategory = "hotel" | "apartment" | "villa" | "event-space";
type PropertyStatus =
    | "active"
    | "inactive"
    | "draft"
    | "pending"
    | "rejected"
    | "deleted";
type AmenityType =
    | "wifi"
    | "pool"
    | "ac"
    | "parking"
    | "gym"
    | "kitchen"
    | "washer"
    | "dryer"
    | "tv"
    | "heating"
    | "workspace"
    | "elevator"
    | "balcony"
    | "garden"
    | "bbq"
    | "fireplace"
    | "security-camera"
    | "smoke-alarm"
    | "first-aid"
    | "fire-extinguisher";

interface PropertyDoc {
    _id?: ObjectId;
    hostId: string;
    title: string;
    description: string;
    category: PropertyCategory;
    location: PropertyLocation;
    price: PropertyPrice;
    details: PropertyDetails;
    amenities: AmenityType[];
    images: string[];
    houseRules: HouseRules;
    availability: AvailabilityDate[];
    status: PropertyStatus;
    rating: number;
    reviewCount: number;
    isFeatured: boolean;
    rejectionReason?: string;
    deletedAt?: Date;
    createdAt: Date;
    updatedAt: Date;
}

// ============================================================
// PAYOUT METHOD (host bank details for manual payouts)
// ============================================================

interface PayoutMethodDoc {
    _id?: ObjectId;
    userId: string;
    accountHolder: string;
    bankName: string;
    accountNumber: string;
    routingNumber: string;
    swiftCode: string;
    bankAddress?: string;
    createdAt: Date;
    updatedAt: Date;
}

// ============================================================
// TRANSACTION
// ============================================================

type TransactionType = "payment" | "payout" | "refund" | "commission";
type TransactionStatusType = "pending" | "success" | "failed" | "refunded";

interface TransactionDoc {
    _id?: ObjectId;
    userId: string;
    bookingId: string;
    type: TransactionType;
    amount: number;
    currency: string;
    method: "card" | "paypal" | "bkash" | "bank";
    status: TransactionStatusType;
    transactionId: string;
    description?: string;
    createdAt: Date;
}

// ============================================================
// BOOKING
// ============================================================

type BookingStatus = "pending" | "confirmed" | "cancelled" | "completed";

interface BookingDoc {
    _id?: ObjectId;
    guestId: string;
    hostId: string;
    propertyId: string;
    propertyTitle: string;
    propertyImage: string;
    checkIn: Date;
    checkOut: Date;
    numberOfGuests: number;
    numberOfNights: number;
    pricePerNight: number;
    totalAmount: number;
    platformFee: number;
    hostEarning: number;
    status: BookingStatus;
    specialRequest?: string;
    cancelledBy?: "guest" | "host" | "admin";
    cancellationReason?: string;
    createdAt: Date;
    updatedAt: Date;
}

type ValidatedPropertyData = {
    title: string;
    description: string;
    category: PropertyCategory;
    location: PropertyLocation;
    price: PropertyPrice;
    details: PropertyDetails;
    amenities: AmenityType[];
    images: string[];
    houseRules: HouseRules;
};

interface AuthUser {
    _id: ObjectId;
    name: string;
    email: string;
    emailVerified: boolean;
    image?: string | null;
    role: string;
    banned?: boolean;
    banReason?: string | null;
    createdAt: Date;
    updatedAt: Date;
}

interface JwtPayload {
    sub: string;
    email?: string;
    [key: string]: unknown;
}

// ✅ Fix 2: AuthRequest extends Request and adds files from multer
interface AuthRequest extends Request {
    user?: AuthUser;
    jwtPayload?: JwtPayload;
    files?:
        | Express.Multer.File[]
        | { [fieldname: string]: Express.Multer.File[] };
}

process.on("unhandledRejection", (reason) => {
    console.error("Unhandled rejection:", reason);
});

// ============================================================
// MONGODB CONNECTION
// ============================================================

const globalWithMongo = global as typeof globalThis & {
    _mongoClientPromise?: Promise<MongoClient>;
};

function escapeRegex(input: string): string {
    return input.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function getClientPromise(): Promise<MongoClient> {
    if (!uri) throw new Error("MONGODB_URI is not set");
    if (globalWithMongo._mongoClientPromise)
        return globalWithMongo._mongoClientPromise;

    const client = new MongoClient(uri, {
        serverApi: {
            version: ServerApiVersion.v1,
            strict: true,
            deprecationErrors: true,
        },
    });

    globalWithMongo._mongoClientPromise = client.connect().catch((err) => {
        globalWithMongo._mongoClientPromise = undefined;
        throw err;
    });
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
        await col.createIndex(
            {
                title: "text",
                description: "text",
                "location.city": "text",
                "location.country": "text",
                "location.address": "text",
            },
            {
                weights: {
                    title: 10,
                    "location.city": 8,
                    "location.country": 6,
                    description: 3,
                    "location.address": 2,
                },
                name: "property_text_search",
            },
        );

        // Compound
        await col.createIndex({ status: 1, category: 1 });
        await col.createIndex({ status: 1, "location.city": 1 });
        await col.createIndex({ status: 1, isFeatured: -1, rating: -1 });
        await col.createIndex({ status: 1, "price.perNight": 1, rating: -1 });
        await col.createIndex({ hostId: 1, status: 1, createdAt: -1 });

        console.log("✅ Property indexes created");
    } catch (error) {
        console.warn("⚠️ Index creation warning:", error);
    }
}

ensurePropertyIndexes().catch((err) =>
    console.error("❌ Failed to create indexes:", err),
);

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
    } catch (error) {
        console.warn("⚠️ User index creation warning:", error);
    }
}

ensureUserIndexes().catch((err) =>
    console.error("❌ Failed to create user indexes:", err),
);

// Payout methods indexes
async function ensurePayoutMethodIndexes() {
    try {
        const db = await getDb();
        const col = db.collection("payout_methods");
        await col.createIndex({ userId: 1 }, { unique: true });
        console.log("✅ Payout method indexes created");
    } catch (error) {
        console.warn("⚠️ Payout method index creation warning:", error);
    }
}

ensurePayoutMethodIndexes().catch((err) =>
    console.error("❌ Failed to create payout method indexes:", err),
);

// Booking indexes
async function ensureBookingIndexes() {
    try {
        const db = await getDb();
        const col = db.collection("bookings");
        await col.createIndex({ guestId: 1, status: 1 });
        await col.createIndex({ hostId: 1, status: 1 });
        await col.createIndex({ propertyId: 1, status: 1 });
        await col.createIndex({ propertyId: 1, checkIn: 1, checkOut: 1 });
        await col.createIndex({ status: 1, createdAt: -1 });
        console.log("✅ Booking indexes created");
    } catch (error) {
        console.warn("⚠️ Booking index creation warning:", error);
    }
}

ensureBookingIndexes().catch((err) =>
    console.error("❌ Failed to create booking indexes:", err),
);

// Transaction indexes
async function ensureTransactionIndexes() {
    try {
        const db = await getDb();
        const col = db.collection("transactions");
        await col.createIndex({ userId: 1, createdAt: -1 });
        await col.createIndex({ bookingId: 1 });
        await col.createIndex({ status: 1 });
        await col.createIndex({ transactionId: 1 }, { unique: true });
        await col.createIndex({ type: 1, status: 1 });
        console.log("✅ Transaction indexes created");
    } catch (error) {
        console.warn("⚠️ Transaction index creation warning:", error);
    }
}

ensureTransactionIndexes().catch((err) =>
    console.error("❌ Failed to create transaction indexes:", err),
);

// Wishlist indexes
async function ensureWishlistIndexes() {
    try {
        const db = await getDb();
        const col = db.collection("wishlist");
        await col.createIndex({ userId: 1, propertyId: 1 }, { unique: true });
        await col.createIndex({ userId: 1, listName: 1 });
        console.log("✅ Wishlist indexes created");
    } catch (error) {
        console.warn("⚠️ Wishlist index creation warning:", error);
    }
}

ensureWishlistIndexes().catch((err) =>
    console.error("❌ Failed to create wishlist indexes:", err),
);

// Review indexes
async function ensureReviewIndexes() {
    try {
        const db = await getDb();
        const col = db.collection("reviews");
        await col.createIndex({ propertyId: 1, createdAt: -1 });
        await col.createIndex({ guestId: 1 });
        await col.createIndex({ hostId: 1 });
        await col.createIndex({ bookingId: 1 }, { unique: true });
        await col.createIndex({ isReported: 1 });
        console.log("✅ Review indexes created");
    } catch (error) {
        console.warn("⚠️ Review index creation warning:", error);
    }
}

ensureReviewIndexes().catch((err) =>
    console.error("❌ Failed to create review indexes:", err),
);

// Message indexes
async function ensureMessageIndexes() {
    try {
        const db = await getDb();
        const conversationsCol = db.collection("conversations");
        await conversationsCol.createIndex({ participants: 1 });
        await conversationsCol.createIndex({ participants: 1, lastMessageAt: -1 });
        const messagesCol = db.collection("messages");
        await messagesCol.createIndex({ conversationId: 1, createdAt: 1 });
        await messagesCol.createIndex({ conversationId: 1, isRead: 1 });
        console.log("✅ Message indexes created");
    } catch (error) {
        console.warn("⚠️ Message index creation warning:", error);
    }
}

ensureMessageIndexes().catch((err) =>
    console.error("❌ Failed to create message indexes:", err),
);

// ============================================================
// HELPERS
// ============================================================

let JWKS: ReturnType<typeof createRemoteJWKSet> | null = null;

function getJWKS() {
    if (!JWKS)
        JWKS = createRemoteJWKSet(new URL(`${FRONTEND_URL}/api/auth/jwks`));
    return JWKS;
}

function userIdFilter(id: ObjectId): Filter<Document> {
    return { _id: id } as Filter<Document>;
}

function toIdString(id: ObjectId): string {
    return id.toString();
}

// Always string from Express params
function parseId(param: string | string[] | undefined): string {
    return String(param || "").trim();
}

// Safe ObjectId — null if invalid
function toObjectId(id: string): ObjectId | null {
    const s = String(id).trim();
    if (!s || !ObjectId.isValid(s)) return null;
    return new ObjectId(s);
}

async function findUserById(
    usersCol: any,
    userId: string,
): Promise<AuthUser | null> {
    const s = String(userId).trim();

    // ObjectId lookup first
    if (ObjectId.isValid(s) && s.length === 24) {
        try {
            const u = await usersCol.findOne({
                _id: new ObjectId(s),
            } as Filter<Document>);
            if (u) return u as unknown as AuthUser;
        } catch {}
    }

    // Fallback: string _id (social auth)
    try {
        const u = await usersCol.findOne({
            _id: s as unknown as ObjectId,
        } as Filter<Document>);
        if (u) return u as unknown as AuthUser;
    } catch {}

    return null;
}

// Batch user lookup — replaces N+1 pattern
async function findUsersMap(
    usersCol: any,
    userIds: string[],
): Promise<Map<string, any>> {
    const uniqueIds = [...new Set(userIds.map((id) => String(id).trim()))].filter(Boolean);
    if (uniqueIds.length === 0) return new Map();

    const objectIds = uniqueIds
        .filter((id) => ObjectId.isValid(id) && id.length === 24)
        .map((id) => new ObjectId(id));
    const stringIds = uniqueIds.filter(
        (id) => !ObjectId.isValid(id) || id.length !== 24,
    );

    const conditions: any[] = [];
    if (objectIds.length > 0) conditions.push({ _id: { $in: objectIds } });
    if (stringIds.length > 0) conditions.push({ _id: { $in: stringIds } });

    if (conditions.length === 0) return new Map();

    const users = await usersCol
        .find({ $or: conditions } as Filter<Document>)
        .toArray();

    return new Map(users.map((u: any) => [toIdString(u._id), u]));
}

function checkPassword(pw: string): string | null {
    if (!pw) return "Password is required.";
    if (pw.length < 8) return "Password must be at least 8 characters.";
    if (!/[A-Z]/.test(pw))
        return "Password must have at least one uppercase letter.";
    if (!/[0-9]/.test(pw)) return "Password must have at least one number.";
    return null;
}

function getPagination(
    query: Record<string, any>,
    maxLimit = 50,
    defaultLimit = 12,
) {
    const page = Math.max(1, parseInt(String(query.page || "1")));
    const limit = Math.min(
        maxLimit,
        Math.max(1, parseInt(String(query.limit || defaultLimit))),
    );
    const skip = (page - 1) * limit;
    return { page, limit, skip };
}

// ✅ Fix 3: explicit Cloudinary callback types (no implicit any)
async function uploadToCloudinary(
    buffer: Buffer,
    folder: string,
    filename: string,
): Promise<{ url: string; publicId: string }> {
    return new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
            {
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
            (
                error: UploadApiErrorResponse | undefined,
                result: UploadApiResponse | undefined,
            ) => {
                if (error || !result) {
                    reject(
                        new Error(error?.message || "Cloudinary upload failed"),
                    );
                    return;
                }
                resolve({ url: result.secure_url, publicId: result.public_id });
            },
        );

        const readable = new Readable();
        readable.push(buffer);
        readable.push(null);
        readable.pipe(stream);
    });
}

// Delete by Cloudinary URL
async function deleteFromCloudinary(imageUrl: string): Promise<void> {
    try {
        const parts = imageUrl.split("/");
        const uploadIndex = parts.indexOf("upload");
        if (uploadIndex === -1) return;

        const afterUpload = parts.slice(uploadIndex + 2).join("/"); // skip "upload/v{version}"
        const publicId = afterUpload.replace(/\.[^/.]+$/, ""); // remove extension

        if (publicId) await cloudinary.uploader.destroy(publicId);
    } catch (err) {
        console.warn("Cloudinary delete warning:", err); // non-critical
    }
}

// ============================================================
// WISHLIST
// ============================================================

interface WishlistDoc {
    _id?: ObjectId;
    userId: string;
    propertyId: string;
    listName?: string;
    createdAt: Date;
}

// ============================================================
// REVIEW
// ============================================================

interface ReviewDoc {
    _id?: ObjectId;
    guestId: string;
    hostId: string;
    propertyId: string;
    bookingId: string;
    rating: number;
    comment: string;
    hostReply?: string;
    hostReplyDate?: Date;
    isReported?: boolean;
    createdAt: Date;
}

// ============================================================
// MESSAGE
// ============================================================

interface ConversationDoc {
    _id?: ObjectId;
    participants: string[];
    bookingId?: string;
    propertyId?: string;
    lastMessage?: string;
    lastMessageAt?: Date;
    createdAt: Date;
    updatedAt: Date;
}

interface MessageDoc {
    _id?: ObjectId;
    conversationId: string;
    senderId: string;
    content: string;
    isRead: boolean;
    createdAt: Date;
}

// ============================================================
// BOOKING HELPERS
// ============================================================

function calculateNights(checkIn: Date, checkOut: Date): number {
    const diff = checkOut.getTime() - checkIn.getTime();
    return Math.max(1, Math.round(diff / (1000 * 60 * 60 * 24)));
}

function calculateFees(totalAmount: number): {
    platformFee: number;
    hostEarning: number;
} {
    const feePercent = Math.min(100, Math.max(0, Number(process.env.PLATFORM_FEE_PERCENT) || 10));
    const platformFee = Math.round(totalAmount * (feePercent / 100) * 100) / 100;
    const hostEarning = Math.round((totalAmount - platformFee) * 100) / 100;
    return { platformFee, hostEarning };
}

async function checkDateOverlap(
    bookingsCol: any,
    propertyId: string,
    checkIn: Date,
    checkOut: Date,
    excludeBookingId?: string,
): Promise<boolean> {
    const filter: Record<string, any> = {
        propertyId,
        status: { $in: ["pending", "confirmed"] },
        $or: [
            { checkIn: { $lt: checkOut, $gte: checkIn } },
            { checkOut: { $gt: checkIn, $lte: checkOut } },
            { checkIn: { $lte: checkIn }, checkOut: { $gte: checkOut } },
        ],
    };
    if (excludeBookingId) {
        const excludeOid = toObjectId(excludeBookingId);
        if (excludeOid) filter._id = { $ne: excludeOid };
    }
    const count = await bookingsCol.countDocuments(filter);
    return count > 0;
}

// ============================================================
// PROPERTY VALIDATION
// ============================================================

const VALID_CATEGORIES: PropertyCategory[] = [
    "hotel",
    "apartment",
    "villa",
    "event-space",
];
const VALID_STATUSES: PropertyStatus[] = [
    "active",
    "inactive",
    "draft",
    "pending",
    "rejected",
    "deleted",
];
const VALID_AMENITIES: AmenityType[] = [
    "wifi",
    "pool",
    "ac",
    "parking",
    "gym",
    "kitchen",
    "washer",
    "dryer",
    "tv",
    "heating",
    "workspace",
    "elevator",
    "balcony",
    "garden",
    "bbq",
    "fireplace",
    "security-camera",
    "smoke-alarm",
    "first-aid",
    "fire-extinguisher",
];

function validatePropertyInput(body: any): {
    valid: boolean;
    error?: string;
    data?: ValidatedPropertyData;
} {
    const {
        title,
        description,
        category,
        location,
        price,
        details,
        amenities,
        images,
        houseRules,
        status,
    } = body;

    if (!title || typeof title !== "string" || title.trim().length < 5)
        return { valid: false, error: "Title must be at least 5 characters." };
    if (title.trim().length > 150)
        return { valid: false, error: "Title cannot exceed 150 characters." };

    if (
        !description ||
        typeof description !== "string" ||
        description.trim().length < 20
    )
        return {
            valid: false,
            error: "Description must be at least 20 characters.",
        };
    if (description.trim().length > 5000)
        return {
            valid: false,
            error: "Description cannot exceed 5000 characters.",
        };

    if (!category || !VALID_CATEGORIES.includes(category))
        return {
            valid: false,
            error: `Category must be one of: ${VALID_CATEGORIES.join(", ")}`,
        };

    if (!location || typeof location !== "object")
        return { valid: false, error: "Location is required." };
    if (!location.address || String(location.address).trim().length < 3)
        return {
            valid: false,
            error: "Location address is required (min 3 chars).",
        };
    if (!location.city || String(location.city).trim().length < 2)
        return {
            valid: false,
            error: "Location city is required (min 2 chars).",
        };
    if (!location.country || String(location.country).trim().length < 2)
        return {
            valid: false,
            error: "Location country is required (min 2 chars).",
        };
    if (location.coordinates) {
        const { lat, lng } = location.coordinates;
        if (
            typeof lat !== "number" ||
            lat < -90 ||
            lat > 90 ||
            typeof lng !== "number" ||
            lng < -180 ||
            lng > 180
        )
            return {
                valid: false,
                error: "Invalid coordinates. Lat: -90~90, Lng: -180~180.",
            };
    }

    if (!price || typeof price !== "object")
        return { valid: false, error: "Price information is required." };
    const perNight = Number(price.perNight);
    if (!price.perNight || isNaN(perNight) || perNight <= 0)
        return {
            valid: false,
            error: "Price per night must be a positive number.",
        };
    if (perNight > 100000)
        return {
            valid: false,
            error: "Price per night cannot exceed 100,000.",
        };
    if (
        price.weeklyDiscount !== undefined &&
        (Number(price.weeklyDiscount) < 0 || Number(price.weeklyDiscount) > 90)
    )
        return { valid: false, error: "Weekly discount must be 0%–90%." };
    if (
        price.monthlyDiscount !== undefined &&
        (Number(price.monthlyDiscount) < 0 ||
            Number(price.monthlyDiscount) > 90)
    )
        return { valid: false, error: "Monthly discount must be 0%–90%." };
    if (
        price.cleaningFee !== undefined &&
        (Number(price.cleaningFee) < 0 || Number(price.cleaningFee) > 10000)
    )
        return { valid: false, error: "Cleaning fee must be 0–10,000." };
    if (
        price.serviceFee !== undefined &&
        (Number(price.serviceFee) < 0 || Number(price.serviceFee) > 10000)
    )
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
        const invalid = amenities.filter(
            (a: string) => !VALID_AMENITIES.includes(a as AmenityType),
        );
        if (invalid.length > 0)
            return {
                valid: false,
                error: `Invalid amenities: ${invalid.join(", ")}`,
            };
    }

    if (images !== undefined) {
        if (!Array.isArray(images))
            return { valid: false, error: "Images must be an array." };
        if (images.length > 20)
            return { valid: false, error: "Maximum 20 images allowed." };
        for (const img of images) {
            if (typeof img !== "string" || !img.trim())
                return {
                    valid: false,
                    error: "Each image must be a valid URL.",
                };
            try {
                new URL(img);
            } catch {
                return { valid: false, error: `Invalid image URL: ${img}` };
            }
        }
    }

    if (houseRules !== undefined && typeof houseRules !== "object")
        return { valid: false, error: "House rules must be an object." };
    if (houseRules) {
        const timeRe = /^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/;
        if (houseRules.checkInTime && !timeRe.test(houseRules.checkInTime))
            return {
                valid: false,
                error: "Check-in time must be HH:MM format.",
            };
        if (houseRules.checkOutTime && !timeRe.test(houseRules.checkOutTime))
            return {
                valid: false,
                error: "Check-out time must be HH:MM format.",
            };
    }

    if (status !== undefined && !VALID_STATUSES.includes(status))
        return {
            valid: false,
            error: `Status must be one of: ${VALID_STATUSES.join(", ")}`,
        };

    // Build clean validated object
    const data: ValidatedPropertyData = {
        title: title.trim(),
        description: description.trim(),
        category: category as PropertyCategory,
        location: {
            address: String(location.address).trim(),
            city: String(location.city).trim(),
            country: String(location.country).trim(),
            ...(location.coordinates && {
                coordinates: {
                    lat: Number(location.coordinates.lat),
                    lng: Number(location.coordinates.lng),
                },
            }),
        },
        price: {
            perNight,
            ...(price.weeklyDiscount !== undefined && {
                weeklyDiscount: Number(price.weeklyDiscount),
            }),
            ...(price.monthlyDiscount !== undefined && {
                monthlyDiscount: Number(price.monthlyDiscount),
            }),
            ...(price.cleaningFee !== undefined && {
                cleaningFee: Number(price.cleaningFee),
            }),
            ...(price.serviceFee !== undefined && {
                serviceFee: Number(price.serviceFee),
            }),
        },
        details: {
            bedrooms,
            bathrooms,
            maxGuests,
            ...(details.beds !== undefined && { beds: Number(details.beds) }),
            ...(details.area !== undefined && { area: Number(details.area) }),
        },
        amenities: Array.isArray(amenities) ? (amenities as AmenityType[]) : [],
        images: Array.isArray(images) ? (images as string[]) : [],
        houseRules: houseRules
            ? {
                  smokingAllowed: Boolean(houseRules.smokingAllowed),
                  petsAllowed: Boolean(houseRules.petsAllowed),
                  partiesAllowed: Boolean(houseRules.partiesAllowed),
                  checkInTime: String(houseRules.checkInTime || "14:00"),
                  checkOutTime: String(houseRules.checkOutTime || "11:00"),
                  ...(houseRules.quietHoursStart && {
                      quietHoursStart: String(houseRules.quietHoursStart),
                  }),
                  ...(houseRules.quietHoursEnd && {
                      quietHoursEnd: String(houseRules.quietHoursEnd),
                  }),
                  ...(Array.isArray(houseRules.additionalRules) && {
                      additionalRules: houseRules.additionalRules.filter(
                          (r: any) => typeof r === "string" && r.trim(),
                      ) as string[],
                  }),
              }
            : {
                  smokingAllowed: false,
                  petsAllowed: false,
                  partiesAllowed: false,
                  checkInTime: "14:00",
                  checkOutTime: "11:00",
              },
    };

    return { valid: true, data };
}

// Strips _id & internal fields for API response
function buildPropertyResponse(p: any) {
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

const verifyToken = async (
    req: AuthRequest,
    res: Response,
    next: NextFunction,
): Promise<void> => {
    const authHeader = req.headers.authorization;

    if (!authHeader?.startsWith("Bearer ")) {
        res.status(401).json({
            success: false,
            message: "Authorization header is required.",
        });
        return;
    }

    const token = authHeader.substring(7).trim();
    if (!token) {
        res.status(401).json({ success: false, message: "Token is required." });
        return;
    }

    try {
        const { payload } = await jwtVerify(token, getJWKS());
        const jwtPayload = payload as JwtPayload;

        if (!jwtPayload.sub) {
            res.status(401).json({
                success: false,
                message: "Invalid token payload.",
            });
            return;
        }

        const db = await getDb();
        const user = await findUserById(db.collection("user"), jwtPayload.sub);

        if (!user) {
            res.status(401).json({
                success: false,
                message: "User not found.",
            });
            return;
        }

        if (user.banned) {
            res.status(403).json({
                success: false,
                message: user.banReason || "Account suspended.",
            });
            return;
        }

        req.user = user;
        req.jwtPayload = jwtPayload;
        next();
    } catch (error: any) {
        if (error?.code === "ERR_JWT_EXPIRED") {
            res.status(401).json({
                success: false,
                message: "Token expired. Please login again.",
            });
            return;
        }
        if (
            error?.code === "ERR_JWS_INVALID" ||
            error?.code === "ERR_JWT_INVALID"
        ) {
            res.status(401).json({ success: false, message: "Invalid token." });
            return;
        }
        console.error("[verifyToken] error:", error);
        res.status(401).json({
            success: false,
            message: "Invalid or expired token.",
        });
    }
};

const verifyAdmin = (
    req: AuthRequest,
    res: Response,
    next: NextFunction,
): void => {
    if (req.user?.role !== "admin") {
        res.status(403).json({
            success: false,
            message: "Admin privileges required.",
        });
        return;
    }
    next();
};

const verifyHostOrAdmin = (
    req: AuthRequest,
    res: Response,
    next: NextFunction,
): void => {
    if (req.user?.role !== "host" && req.user?.role !== "admin") {
        res.status(403).json({
            success: false,
            message: "Host or Admin privileges required.",
        });
        return;
    }
    next();
};

// ============================================================
// HEALTH ROUTES
// ============================================================

app.get("/", (_req: Request, res: Response) => {
    res.status(200).json({
        success: true,
        message: "🏡 StayEase Server is Running!",
        version: "1.0.0",
        env: {
            hasMongoUri: !!process.env.MONGODB_URI,
            hasDbName: !!process.env.DB_NAME,
            hasFrontendUrl: !!process.env.FRONTEND_URL,
            hasCloudinary:
                !!process.env.CLOUDINARY_CLOUD_NAME &&
                !!process.env.CLOUDINARY_API_KEY,
            nodeEnv: process.env.NODE_ENV || "not set",
        },
    });
});

app.get("/api/health", async (_req: Request, res: Response) => {
    try {
        const db = await getDb();
        await db.command({ ping: 1 });
        const cloudinaryOk =
            !!process.env.CLOUDINARY_CLOUD_NAME &&
            !!process.env.CLOUDINARY_API_KEY &&
            !!process.env.CLOUDINARY_API_SECRET;

        res.status(200).json({
            success: true,
            message: "All systems operational",
            services: {
                mongodb: { status: "connected", database: dbName },
                cloudinary: {
                    status: cloudinaryOk ? "configured" : "not configured",
                },
                server: { status: "running" },
            },
        });
    } catch (error) {
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
app.get(
    "/api/users/profile",
    verifyToken,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const user = req.user!;
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
        } catch {
            res.status(500).json({
                success: false,
                message: "Failed to get profile.",
            });
        }
    },
);

// PUT update profile
app.put(
    "/api/users/profile",
    verifyToken,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const user = req.user!;
            const { name, image } = req.body;
            const updates: Record<string, unknown> = {};

            if (name !== undefined) {
                const trimmed = String(name).trim();
                if (!trimmed) {
                    res.status(400).json({
                        success: false,
                        message: "Name cannot be empty.",
                    });
                    return;
                }
                if (trimmed.length < 3) {
                    res.status(400).json({
                        success: false,
                        message: "Name must be at least 3 characters.",
                    });
                    return;
                }
                if (trimmed.length > 100) {
                    res.status(400).json({
                        success: false,
                        message: "Name cannot exceed 100 characters.",
                    });
                    return;
                }
                updates.name = trimmed;
            }

            if (image !== undefined) updates.image = image || null;
            if (Object.keys(updates).length === 0) {
                res.status(400).json({
                    success: false,
                    message: "Nothing to update.",
                });
                return;
            }

            const db = await getDb();
            const usersCol = db.collection("user");
            updates.updatedAt = new Date();
            await usersCol.updateOne(userIdFilter(user._id), { $set: updates });
            const updated = await usersCol.findOne(userIdFilter(user._id));
            if (!updated) {
                res.status(404).json({
                    success: false,
                    message: "User not found.",
                });
                return;
            }

            res.status(200).json({
                success: true,
                message: "Profile updated.",
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
        } catch {
            res.status(500).json({
                success: false,
                message: "Failed to update profile.",
            });
        }
    },
);

// PUT profile image
app.put(
    "/api/users/profile-image",
    verifyToken,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const user = req.user!;
            const { imageUrl } = req.body;

            if (!imageUrl || typeof imageUrl !== "string") {
                res.status(400).json({
                    success: false,
                    message: "Valid image URL required.",
                });
                return;
            }
            try {
                new URL(imageUrl);
            } catch {
                res.status(400).json({
                    success: false,
                    message: "Invalid URL format.",
                });
                return;
            }

            const db = await getDb();
            await db
                .collection("user")
                .updateOne(userIdFilter(user._id), {
                    $set: { image: imageUrl, updatedAt: new Date() },
                });
            res.status(200).json({
                success: true,
                message: "Profile image updated.",
                data: { image: imageUrl },
            });
        } catch {
            res.status(500).json({
                success: false,
                message: "Failed to update image.",
            });
        }
    },
);

// PUT change password
app.put(
    "/api/users/change-password",
    verifyToken,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const user = req.user!;
            const { currentPassword, newPassword, confirmNewPassword } =
                req.body;

            if (!currentPassword) {
                res.status(400).json({
                    success: false,
                    message: "Current password required.",
                });
                return;
            }
            if (!newPassword) {
                res.status(400).json({
                    success: false,
                    message: "New password required.",
                });
                return;
            }
            if (!confirmNewPassword) {
                res.status(400).json({
                    success: false,
                    message: "Confirm password required.",
                });
                return;
            }
            if (newPassword !== confirmNewPassword) {
                res.status(400).json({
                    success: false,
                    message: "Passwords do not match.",
                });
                return;
            }
            if (currentPassword === newPassword) {
                res.status(400).json({
                    success: false,
                    message: "New password must be different.",
                });
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
            const account = await accountsCol.findOne({
                userId,
                providerId: "credential",
            });

            if (!account?.password) {
                res.status(400).json({
                    success: false,
                    message: "No password account found.",
                });
                return;
            }

            const isMatch = await bcrypt.compare(
                currentPassword,
                account.password as string,
            );
            if (!isMatch) {
                res.status(400).json({
                    success: false,
                    message: "Current password is wrong.",
                });
                return;
            }

            const hashed = await bcrypt.hash(newPassword, 10);
            await accountsCol.updateOne(
                { userId, providerId: "credential" },
                { $set: { password: hashed, updatedAt: new Date() } },
            );
            await sessionsCol.deleteMany({ userId });

            res.status(200).json({
                success: true,
                message: "Password changed. Please login again.",
            });
        } catch {
            res.status(500).json({
                success: false,
                message: "Failed to change password.",
            });
        }
    },
);

// DELETE self account
app.delete(
    "/api/users/account",
    verifyToken,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const user = req.user!;
            const { password } = req.body;

            if (!password) {
                res.status(400).json({
                    success: false,
                    message: "Password required.",
                });
                return;
            }
            if (user.role === "admin") {
                res.status(403).json({
                    success: false,
                    message: "Admin cannot self-delete.",
                });
                return;
            }

            const db = await getDb();
            const usersCol = db.collection("user");
            const accountsCol = db.collection("account");
            const sessionsCol = db.collection("session");
            const propertiesCol = db.collection("properties");
            const bookingsCol = db.collection("bookings");
            const userId = toIdString(user._id);

            const account = await accountsCol.findOne({
                userId,
                providerId: "credential",
            });
            if (!account?.password) {
                res.status(400).json({
                    success: false,
                    message: "No password account found.",
                });
                return;
            }

            const isMatch = await bcrypt.compare(
                password,
                account.password as string,
            );
            if (!isMatch) {
                res.status(400).json({
                    success: false,
                    message: "Wrong password.",
                });
                return;
            }

            const bookingFilter =
                user.role === "host" ? { hostId: userId } : { guestId: userId };
            const activeCount = await bookingsCol.countDocuments({
                ...bookingFilter,
                status: { $in: ["confirmed", "pending", "checked-in"] },
            });
            if (activeCount > 0) {
                res.status(400).json({
                    success: false,
                    message: `You have ${activeCount} active booking(s).`,
                });
                return;
            }

            await sessionsCol.deleteMany({ userId });
            await accountsCol.deleteMany({ userId });
            if (user.role === "host")
                await propertiesCol.updateMany(
                    { hostId: userId },
                    { $set: { status: "deleted", deletedAt: new Date() } },
                );
            await usersCol.deleteOne(userIdFilter(user._id));

            res.status(200).json({
                success: true,
                message: "Account permanently deleted.",
            });
        } catch {
            res.status(500).json({
                success: false,
                message: "Failed to delete account.",
            });
        }
    },
);

// ============================================================
// ADMIN USER ROUTES
// ============================================================

// GET all users
app.get(
    "/api/admin/users",
    verifyToken,
    verifyAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const db = await getDb();
            const col = db.collection("user");
            const currentUserId = toIdString(req.user!._id);

            const { page, limit, skip } = getPagination(req.query, 100, 50);

            const filter: Record<string, any> = {};
            if (
                req.query.role &&
                ["guest", "host", "admin"].includes(String(req.query.role))
            )
                filter.role = String(req.query.role);
            if (req.query.banned === "true") filter.banned = true;
            if (req.query.banned === "false") filter.banned = { $ne: true };
            if (req.query.search) {
                const term = String(req.query.search).trim().slice(0, 100);
                if (term)
                    filter.$or = [
                        { name: { $regex: escapeRegex(term), $options: "i" } },
                        { email: { $regex: escapeRegex(term), $options: "i" } },
                    ];
            }

            const [users, total] = await Promise.all([
                col
                    .find(filter)
                    .sort({ createdAt: -1 })
                    .skip(skip)
                    .limit(limit)
                    .toArray(),
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
                col
                    .aggregate([
                        { $group: { _id: "$role", count: { $sum: 1 } } },
                    ])
                    .toArray(),
                col.countDocuments({ banned: true }),
            ]);

            const roleMap = roleStats.reduce(
                (acc, s) => ({ ...acc, [s._id]: s.count }),
                {} as Record<string, number>,
            );

            res.status(200).json({
                success: true,
                data: {
                    users: safeUsers,
                    currentUserId,
                    pagination: {
                        total,
                        totalPages,
                        currentPage: page,
                        limit,
                        hasNextPage: page < totalPages,
                        hasPrevPage: page > 1,
                    },
                    stats: {
                        total: Object.values(roleMap).reduce(
                            (a, b) => a + b,
                            0,
                        ),
                        admins: roleMap["admin"] || 0,
                        hosts: roleMap["host"] || 0,
                        guests: roleMap["guest"] || 0,
                        banned: bannedCount,
                    },
                },
            });
        } catch {
            res.status(500).json({
                success: false,
                message: "Failed to fetch users.",
            });
        }
    },
);

// GET single user
app.get(
    "/api/admin/users/:id",
    verifyToken,
    verifyAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const db = await getDb();
            const user = await findUserById(
                db.collection("user"),
                parseId(req.params.id),
            );
            if (!user) {
                res.status(404).json({
                    success: false,
                    message: "User not found.",
                });
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
        } catch {
            res.status(500).json({
                success: false,
                message: "Failed to fetch user.",
            });
        }
    },
);

// PUT update role
app.put(
    "/api/admin/users/:id/role",
    verifyToken,
    verifyAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const { role } = req.body;
            const validRoles = ["admin", "host", "guest"];
            if (!role || !validRoles.includes(role)) {
                res.status(400).json({
                    success: false,
                    message: `Role must be: ${validRoles.join(", ")}`,
                });
                return;
            }

            const db = await getDb();
            const usersCol = db.collection("user");
            const user = await findUserById(usersCol, parseId(req.params.id));
            if (!user) {
                res.status(404).json({
                    success: false,
                    message: "User not found.",
                });
                return;
            }

            const reqUserId = toIdString(req.user!._id);
            const targetUserId = toIdString(user._id);
            if (reqUserId === targetUserId && role !== "admin") {
                res.status(400).json({
                    success: false,
                    message: "Cannot change your own admin role.",
                });
                return;
            }

            await usersCol.updateOne(userIdFilter(user._id), {
                $set: { role, updatedAt: new Date() },
            });
            res.status(200).json({
                success: true,
                message: `Role updated to "${role}".`,
                data: {
                    id: targetUserId,
                    name: user.name,
                    email: user.email,
                    role,
                },
            });
        } catch {
            res.status(500).json({
                success: false,
                message: "Failed to update role.",
            });
        }
    },
);

// PUT ban/unban
app.put(
    "/api/admin/users/:id/status",
    verifyToken,
    verifyAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const { banned, banReason } = req.body;
            if (typeof banned !== "boolean") {
                res.status(400).json({
                    success: false,
                    message: "banned must be boolean.",
                });
                return;
            }

            const db = await getDb();
            const usersCol = db.collection("user");
            const sessionsCol = db.collection("session");
            const user = await findUserById(usersCol, parseId(req.params.id));
            if (!user) {
                res.status(404).json({
                    success: false,
                    message: "User not found.",
                });
                return;
            }

            const reqUserId = toIdString(req.user!._id);
            const targetUserId = toIdString(user._id);
            if (reqUserId === targetUserId) {
                res.status(400).json({
                    success: false,
                    message: "Cannot block yourself.",
                });
                return;
            }
            if (user.role === "admin") {
                res.status(400).json({
                    success: false,
                    message: "Cannot block admin.",
                });
                return;
            }

            const updateData: Record<string, unknown> = {
                banned,
                updatedAt: new Date(),
            };
            if (banned) {
                updateData.banReason = banReason || "Blocked by admin";
                await sessionsCol.deleteMany({ userId: targetUserId });
            } else {
                updateData.banReason = null;
            }

            await usersCol.updateOne(userIdFilter(user._id), {
                $set: updateData,
            });
            res.status(200).json({
                success: true,
                message: banned ? "User blocked." : "User unblocked.",
                data: {
                    id: targetUserId,
                    name: user.name,
                    email: user.email,
                    banned,
                    banReason: banned ? banReason || "Blocked by admin" : null,
                },
            });
        } catch {
            res.status(500).json({
                success: false,
                message: "Failed to update status.",
            });
        }
    },
);

// DELETE user (admin)
app.delete(
    "/api/admin/users/:id",
    verifyToken,
    verifyAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const db = await getDb();
            const usersCol = db.collection("user");
            const accountsCol = db.collection("account");
            const sessionsCol = db.collection("session");
            const propertiesCol = db.collection("properties");
            const bookingsCol = db.collection("bookings");

            const user = await findUserById(usersCol, parseId(req.params.id));
            if (!user) {
                res.status(404).json({
                    success: false,
                    message: "User not found.",
                });
                return;
            }

            const reqUserId = toIdString(req.user!._id);
            const targetUserId = toIdString(user._id);
            if (reqUserId === targetUserId) {
                res.status(400).json({
                    success: false,
                    message: "Cannot delete yourself.",
                });
                return;
            }

            const bookingFilter =
                user.role === "host"
                    ? { hostId: targetUserId }
                    : { guestId: targetUserId };
            const activeBookings = await bookingsCol.countDocuments({
                ...bookingFilter,
                status: { $in: ["confirmed", "pending", "checked-in"] },
            });
            if (activeBookings > 0) {
                res.status(400).json({
                    success: false,
                    message: `User has ${activeBookings} active booking(s).`,
                });
                return;
            }

            await sessionsCol.deleteMany({ userId: targetUserId });
            await accountsCol.deleteMany({ userId: targetUserId });
            if (user.role === "host")
                await propertiesCol.updateMany(
                    { hostId: targetUserId },
                    { $set: { status: "deleted", deletedAt: new Date() } },
                );
            await usersCol.deleteOne(userIdFilter(user._id));

            res.status(200).json({
                success: true,
                message: `User "${user.name}" deleted.`,
            });
        } catch {
            res.status(500).json({
                success: false,
                message: "Failed to delete user.",
            });
        }
    },
);

// ============================================================
// PROPERTY ROUTES — PUBLIC
// ⚠️ Specific routes MUST come before /:id parameterized routes
// ============================================================

// GET featured (homepage)
app.get(
    "/api/properties/featured",
    async (_req: Request, res: Response): Promise<void> => {
        try {
            const db = await getDb();
            const properties = await db
                .collection("properties")
                .find({ status: "active", isFeatured: true })
                .sort({ rating: -1, reviewCount: -1 })
                .limit(8)
                .toArray();

            res.status(200).json({
                success: true,
                data: properties.map(buildPropertyResponse),
            });
        } catch {
            res.status(500).json({
                success: false,
                message: "Failed to fetch featured properties.",
            });
        }
    },
);

// GET homepage stats
app.get(
    "/api/properties/stats",
    async (_req: Request, res: Response): Promise<void> => {
        try {
            const db = await getDb();
            const col = db.collection("properties");

            const [
                totalActive,
                totalFeatured,
                categoryStats,
                cityStats,
                avgRatingResult,
                priceStats,
            ] = await Promise.all([
                col.countDocuments({ status: "active" }),
                col.countDocuments({ status: "active", isFeatured: true }),
                col
                    .aggregate([
                        { $match: { status: "active" } },
                        {
                            $group: {
                                _id: "$category",
                                count: { $sum: 1 },
                                avgPrice: { $avg: "$price.perNight" },
                            },
                        },
                        { $sort: { count: -1 } },
                    ])
                    .toArray(),
                col
                    .aggregate([
                        { $match: { status: "active" } },
                        {
                            $group: {
                                _id: "$location.city",
                                count: { $sum: 1 },
                                avgPrice: { $avg: "$price.perNight" },
                                country: { $first: "$location.country" },
                            },
                        },
                        { $sort: { count: -1 } },
                        { $limit: 8 },
                    ])
                    .toArray(),
                col
                    .aggregate([
                        { $match: { status: "active", rating: { $gt: 0 } } },
                        {
                            $group: {
                                _id: null,
                                avgRating: { $avg: "$rating" },
                                totalReviews: { $sum: "$reviewCount" },
                            },
                        },
                    ])
                    .toArray(),
                col
                    .aggregate([
                        { $match: { status: "active" } },
                        {
                            $group: {
                                _id: null,
                                minPrice: { $min: "$price.perNight" },
                                maxPrice: { $max: "$price.perNight" },
                                avgPrice: { $avg: "$price.perNight" },
                            },
                        },
                    ])
                    .toArray(),
            ]);

            res.status(200).json({
                success: true,
                data: {
                    totalProperties: totalActive,
                    totalFeatured,
                    avgRating: avgRatingResult[0]?.avgRating
                        ? parseFloat(avgRatingResult[0].avgRating.toFixed(1))
                        : 0,
                    totalReviews: avgRatingResult[0]?.totalReviews || 0,
                    byCategory: categoryStats.map((c) => ({
                        category: c._id,
                        count: c.count,
                        avgPrice: Math.round(c.avgPrice || 0),
                    })),
                    topCities: cityStats.map((c) => ({
                        city: c._id,
                        country: c.country,
                        count: c.count,
                        avgPrice: Math.round(c.avgPrice || 0),
                    })),
                    priceRange: priceStats[0]
                        ? {
                              min: Math.round(priceStats[0].minPrice || 0),
                              max: Math.round(priceStats[0].maxPrice || 0),
                              avg: Math.round(priceStats[0].avgPrice || 0),
                          }
                        : { min: 0, max: 0, avg: 0 },
                },
            });
        } catch {
            res.status(500).json({
                success: false,
                message: "Failed to fetch stats.",
            });
        }
    },
);

// GET host's own properties
app.get(
    "/api/properties/host/my-properties",
    verifyToken,
    verifyHostOrAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const user = req.user!;
            const db = await getDb();
            const col = db.collection("properties");

            const { page, limit, skip } = getPagination(req.query, 50, 10);

            // Admin sees all, host sees own
            const baseFilter: Record<string, any> =
                user.role === "admin"
                    ? { status: { $ne: "deleted" } }
                    : {
                          hostId: toIdString(user._id),
                          status: { $ne: "deleted" },
                      };

            if (
                req.query.status &&
                VALID_STATUSES.includes(req.query.status as PropertyStatus) &&
                req.query.status !== "deleted"
            )
                baseFilter.status = String(req.query.status);

                        if (req.query.search) {
                const term = String(req.query.search).trim().slice(0, 100);
                if (term)
                    baseFilter.$or = [
                        { title: { $regex: escapeRegex(term), $options: "i" } },
                        { "location.city": { $regex: escapeRegex(term), $options: "i" } },
                    ];
            }

            if (
                req.query.category &&
                VALID_CATEGORIES.includes(
                    req.query.category as PropertyCategory,
                )
            )
                baseFilter.category = String(req.query.category);

            type SortOrder = 1 | -1;
            let sort: Record<string, SortOrder> = { createdAt: -1 };
            if (req.query.sort === "oldest") sort = { createdAt: 1 };
            if (req.query.sort === "rating") sort = { rating: -1 };
            if (req.query.sort === "price-asc") sort = { "price.perNight": 1 };
            if (req.query.sort === "price-desc")

            
                sort = { "price.perNight": -1 };

            const [properties, total] = await Promise.all([
                col
                    .find(baseFilter)
                    .sort(sort)
                    .skip(skip)
                    .limit(limit)
                    .toArray(),
                col.countDocuments(baseFilter),
            ]);

            const summaryMatch =
                user.role === "admin"
                    ? { status: { $ne: "deleted" } }
                    : {
                          hostId: toIdString(user._id),
                          status: { $ne: "deleted" },
                      };

            const statusSummary = await col
                .aggregate([
                    { $match: summaryMatch },
                    { $group: { _id: "$status", count: { $sum: 1 } } },
                ])
                .toArray();

            const totalPages = Math.ceil(total / limit);

            res.status(200).json({
                success: true,
                data: {
                    properties: properties.map(buildPropertyResponse),
                    pagination: {
                        total,
                        totalPages,
                        currentPage: page,
                        limit,
                        hasNextPage: page < totalPages,
                        hasPrevPage: page > 1,
                    },
                    statusSummary: statusSummary.reduce(
                        (acc, s) => ({ ...acc, [s._id]: s.count }),
                        {} as Record<string, number>,
                    ),
                },
            });
        } catch {
            res.status(500).json({
                success: false,
                message: "Failed to fetch properties.",
            });
        }
    },
);

// POST upload images → Cloudinary
app.post(
    "/api/properties/upload-images",
    verifyToken,
    verifyHostOrAdmin,
    upload.array("images", MAX_FILES),
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            // ✅ Fix 4: cast req.files to array (multer attaches it)
            const files = (req.files as Express.Multer.File[]) || [];

            if (files.length === 0) {
                res.status(400).json({
                    success: false,
                    message: "No files uploaded.",
                });
                return;
            }

            const userId = toIdString(req.user!._id);
            const folder = `properties/${userId}`;
            const uploadedUrls: string[] = [];
            const errors: string[] = [];

            await Promise.all(
                files.map(async (file, idx) => {
                    try {
                        const filename = `img_${Date.now()}_${idx}`;
                        const result = await uploadToCloudinary(
                            file.buffer,
                            folder,
                            filename,
                        );
                        uploadedUrls.push(result.url);
                    } catch (err: any) {
                        errors.push(
                            `File ${file.originalname}: ${err.message}`,
                        );
                    }
                }),
            );

            if (uploadedUrls.length === 0) {
                res.status(500).json({
                    success: false,
                    message: "All uploads failed.",
                    errors,
                });
                return;
            }

            res.status(200).json({
                success: true,
                message: `${uploadedUrls.length} image(s) uploaded successfully.`,
                data: {
                    urls: uploadedUrls,
                    count: uploadedUrls.length,
                    ...(errors.length > 0 && { partialErrors: errors }),
                },
            });
        } catch (error: any) {
            // Multer-level errors
            if (error.code === "LIMIT_FILE_SIZE") {
                res.status(400).json({
                    success: false,
                    message: `File too large. Max ${MAX_FILE_SIZE / 1024 / 1024}MB.`,
                });
                return;
            }
            if (error.code === "LIMIT_FILE_COUNT") {
                res.status(400).json({
                    success: false,
                    message: `Too many files. Max ${MAX_FILES}.`,
                });
                return;
            }
            if (error.message?.includes("Invalid file type")) {
                res.status(400).json({
                    success: false,
                    message: error.message,
                });
                return;
            }
            console.error("Image upload error:", error);
            res.status(500).json({
                success: false,
                message: "Failed to upload images.",
            });
        }
    },
);

// DELETE image from Cloudinary
app.delete(
    "/api/properties/delete-image",
    verifyToken,
    verifyHostOrAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const { imageUrl, propertyId } = req.body;

            if (!imageUrl || typeof imageUrl !== "string") {
                res.status(400).json({
                    success: false,
                    message: "imageUrl is required.",
                });
                return;
            }

            // Must be our Cloudinary account
            const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
            if (
                cloudName &&
                !imageUrl.includes(`res.cloudinary.com/${cloudName}`)
            ) {
                res.status(400).json({
                    success: false,
                    message: "Invalid image URL.",
                });
                return;
            }

            // Ownership check if propertyId provided
            if (propertyId) {
                const objectId = toObjectId(String(propertyId));
                if (!objectId) {
                    res.status(400).json({
                        success: false,
                        message: "Invalid property ID.",
                    });
                    return;
                }
                const db = await getDb();
                const property = await db
                    .collection("properties")
                    .findOne({ _id: objectId });
                if (
                    property &&
                    req.user!.role !== "admin" &&
                    property.hostId !== toIdString(req.user!._id)
                ) {
                    res.status(403).json({
                        success: false,
                        message: "Not authorized.",
                    });
                    return;
                }
            }

            await deleteFromCloudinary(imageUrl);
            res.status(200).json({
                success: true,
                message: "Image deleted successfully.",
            });
        } catch {
            res.status(500).json({
                success: false,
                message: "Failed to delete image.",
            });
        }
    },
);

// GET all active properties (public, filterable)
app.get(
    "/api/properties",
    async (req: Request, res: Response): Promise<void> => {
        try {
            const db = await getDb();
            const col = db.collection("properties");

            const { page, limit, skip } = getPagination(req.query, 50, 12);

            const filter: Record<string, any> = { status: "active" };

            if (
                req.query.category &&
                VALID_CATEGORIES.includes(
                    req.query.category as PropertyCategory,
                )
            )
                filter.category = String(req.query.category);
            if (req.query.city)
                filter["location.city"] = {
                    $regex: escapeRegex(String(req.query.city).trim().slice(0, 100)),
                    $options: "i",
                };
            if (req.query.country)
                filter["location.country"] = {
                    $regex: escapeRegex(String(req.query.country).trim().slice(0, 100)),
                    $options: "i",
                };

            if (req.query.minPrice || req.query.maxPrice) {
                filter["price.perNight"] = {};
                if (req.query.minPrice) {
                    const n = Number(req.query.minPrice);
                    if (!isNaN(n) && n >= 0) filter["price.perNight"].$gte = n;
                }
                if (req.query.maxPrice) {
                    const n = Number(req.query.maxPrice);
                    if (!isNaN(n) && n > 0) filter["price.perNight"].$lte = n;
                }
            }

            if (req.query.minRating) {
                const n = Number(req.query.minRating);
                if (!isNaN(n) && n >= 0 && n <= 5) filter.rating = { $gte: n };
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
                const list = String(req.query.amenities)
                    .split(",")
                    .map((a) => a.trim())
                    .filter((a) => VALID_AMENITIES.includes(a as AmenityType));
                if (list.length > 0) filter.amenities = { $all: list };
            }

            if (req.query.search) {
                const term = String(req.query.search).trim().slice(0, 100);
                if (term)
                    filter.$or = [
                        { title: { $regex: escapeRegex(term), $options: "i" } },
                        { description: { $regex: escapeRegex(term), $options: "i" } },
                        { "location.city": { $regex: escapeRegex(term), $options: "i" } },
                        { "location.country": { $regex: escapeRegex(term), $options: "i" } },
                        { "location.address": { $regex: escapeRegex(term), $options: "i" } },
                    ];
            }

            if (req.query.featured === "true") filter.isFeatured = true;

            type SortOrder = 1 | -1;
            let sort: Record<string, SortOrder> = { createdAt: -1 };
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
                    pagination: {
                        total,
                        totalPages,
                        currentPage: page,
                        limit,
                        hasNextPage: page < totalPages,
                        hasPrevPage: page > 1,
                    },
                    filters: {
                        applied: Object.keys(req.query).filter(
                            (k) => !["page", "limit", "sort"].includes(k),
                        ),
                    },
                },
            });
        } catch (error) {
            console.error("Get properties error:", error);
            res.status(500).json({
                success: false,
                message: "Failed to fetch properties.",
            });
        }
    },
);

// POST create property (host/admin)
app.post(
    "/api/properties",
    verifyToken,
    verifyHostOrAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const user = req.user!;
            const validation = validatePropertyInput(req.body);
            if (!validation.valid) {
                res.status(400).json({
                    success: false,
                    message: validation.error,
                });
                return;
            }

            const db = await getDb();
            const col = db.collection("properties");

            // Max 50 properties per host
            if (user.role !== "admin") {
                const count = await col.countDocuments({
                    hostId: toIdString(user._id),
                    status: { $ne: "deleted" },
                });
                if (count >= 50) {
                    res.status(400).json({
                        success: false,
                        message: "Maximum 50 properties allowed per host.",
                    });
                    return;
                }
            }

            const now: Date = new Date();
            const requestedStatus = req.body.status as string | undefined;
            const validDraftStatuses: PropertyStatus[] = ["draft", "pending"];
            const status: PropertyStatus =
                requestedStatus &&
                validDraftStatuses.includes(requestedStatus as PropertyStatus)
                    ? (requestedStatus as PropertyStatus)
                    : user.role === "admin"
                      ? "active"
                      : "pending";

            const newProperty: PropertyDoc = {
                ...validation.data!,
                hostId: toIdString(user._id),
                status,
                rating: 0,
                reviewCount: 0,
                isFeatured: false,
                availability: [],
                createdAt: now,
                updatedAt: now,
            };

            const result = await col.insertOne(newProperty as PropertyDoc);

            res.status(201).json({
                success: true,
                message:
                    user.role === "admin"
                        ? "Property published successfully."
                        : "Property submitted for admin review.",
                data: buildPropertyResponse({
                    ...newProperty,
                    _id: result.insertedId,
                }),
            });
        } catch (error) {
            console.error("Create property error:", error);
            res.status(500).json({
                success: false,
                message: "Failed to create property.",
            });
        }
    },
);

// ⚠️ /:id routes start here — must come AFTER all specific routes above

// GET single property detail (public)
app.get(
    "/api/properties/:id",
    async (req: Request, res: Response): Promise<void> => {
        try {
            const id = parseId(req.params.id);
            const objectId = toObjectId(id);
            if (!objectId) {
                res.status(400).json({
                    success: false,
                    message: "Invalid property ID.",
                });
                return;
            }

            const db = await getDb();
            const col = db.collection("properties");
            const usersCol = db.collection("user");

            const property = await col.findOne({
                _id: objectId,
                status: { $ne: "deleted" },
            });
            if (!property) {
                res.status(404).json({
                    success: false,
                    message: "Property not found.",
                });
                return;
            }

            // Host info
            let hostInfo = null;
            if (property.hostId) {
                const host = await findUserById(
                    usersCol,
                    String(property.hostId),
                );
                if (host)
                    hostInfo = {
                        id: toIdString(host._id),
                        name: host.name,
                        image: host.image || null,
                        createdAt: host.createdAt,
                    };
            }

            // Related: same category + city, max 4
            const related = await col
                .find({
                    _id: { $ne: objectId },
                    status: "active",
                    category: property.category,
                    "location.city": property.location?.city,
                })
                .sort({ rating: -1 })
                .limit(4)
                .toArray();

            res.status(200).json({
                success: true,
                data: {
                    property: buildPropertyResponse(property),
                    host: hostInfo,
                    relatedProperties: related.map(buildPropertyResponse),
                },
            });
        } catch (error) {
            console.error("Get property detail error:", error);
            res.status(500).json({
                success: false,
                message: "Failed to fetch property.",
            });
        }
    },
);

// PUT update property (host owner / admin)
app.put(
    "/api/properties/:id",
    verifyToken,
    verifyHostOrAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const id = parseId(req.params.id);
            const objectId = toObjectId(id);
            const user = req.user!;
            if (!objectId) {
                res.status(400).json({
                    success: false,
                    message: "Invalid property ID.",
                });
                return;
            }

            const db = await getDb();
            const col = db.collection("properties");
            const existing = await col.findOne({
                _id: objectId,
                status: { $ne: "deleted" },
            });
            if (!existing) {
                res.status(404).json({
                    success: false,
                    message: "Property not found.",
                });
                return;
            }

            if (
                user.role !== "admin" &&
                existing.hostId !== toIdString(user._id)
            ) {
                res.status(403).json({
                    success: false,
                    message: "You can only update your own properties.",
                });
                return;
            }

            const validation = validatePropertyInput(req.body);
            if (!validation.valid) {
                res.status(400).json({
                    success: false,
                    message: validation.error,
                });
                return;
            }

            const updates: Record<string, any> = {
                ...validation.data,
                updatedAt: new Date(),
            };

            // Host editing rejected/inactive → reset to pending for re-review
            if (
                user.role !== "admin" &&
                (existing.status === "rejected" ||
                    existing.status === "inactive")
            ) {
                updates.status = "pending";
                updates.rejectionReason = null;
            }

            await col.updateOne({ _id: objectId }, { $set: updates });
            const updated = await col.findOne({ _id: objectId });

            res.status(200).json({
                success: true,
                message: "Property updated successfully.",
                data: buildPropertyResponse(updated),
            });
        } catch (error) {
            console.error("Update property error:", error);
            res.status(500).json({
                success: false,
                message: "Failed to update property.",
            });
        }
    },
);

// DELETE property - soft delete (host owner / admin)
app.delete(
    "/api/properties/:id",
    verifyToken,
    verifyHostOrAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const id = parseId(req.params.id);
            const objectId = toObjectId(id);
            const user = req.user!;
            if (!objectId) {
                res.status(400).json({
                    success: false,
                    message: "Invalid property ID.",
                });
                return;
            }

            const db = await getDb();
            const col = db.collection("properties");
            const bookingsCol = db.collection("bookings");

            const existing = await col.findOne({
                _id: objectId,
                status: { $ne: "deleted" },
            });
            if (!existing) {
                res.status(404).json({
                    success: false,
                    message: "Property not found.",
                });
                return;
            }

            if (
                user.role !== "admin" &&
                existing.hostId !== toIdString(user._id)
            ) {
                res.status(403).json({
                    success: false,
                    message: "You can only delete your own properties.",
                });
                return;
            }

            const activeBookings = await bookingsCol.countDocuments({
                propertyId: id,
                status: { $in: ["confirmed", "pending", "checked-in"] },
            });
            if (activeBookings > 0) {
                res.status(400).json({
                    success: false,
                    message: `Cannot delete. ${activeBookings} active booking(s) exist.`,
                });
                return;
            }

            await col.updateOne(
                { _id: objectId },
                {
                    $set: {
                        status: "deleted",
                        deletedAt: new Date(),
                        updatedAt: new Date(),
                    },
                },
            );
            res.status(200).json({
                success: true,
                message: "Property deleted successfully.",
                data: { id },
            });
        } catch (error) {
            console.error("Delete property error:", error);
            res.status(500).json({
                success: false,
                message: "Failed to delete property.",
            });
        }
    },
);

// PUT toggle active/inactive status
app.put(
    "/api/properties/:id/status",
    verifyToken,
    verifyHostOrAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const id = parseId(req.params.id);
            const objectId = toObjectId(id);
            const { status } = req.body;
            const user = req.user!;
            if (!objectId) {
                res.status(400).json({
                    success: false,
                    message: "Invalid property ID.",
                });
                return;
            }

            const allowed =
                user.role === "admin"
                    ? ["active", "inactive", "draft"]
                    : ["active", "inactive"];
            if (!status || !allowed.includes(status)) {
                res.status(400).json({
                    success: false,
                    message: `Status must be: ${allowed.join(", ")}`,
                });
                return;
            }

            const db = await getDb();
            const col = db.collection("properties");
            const existing = await col.findOne({
                _id: objectId,
                status: { $ne: "deleted" },
            });
            if (!existing) {
                res.status(404).json({
                    success: false,
                    message: "Property not found.",
                });
                return;
            }

            if (
                user.role !== "admin" &&
                existing.hostId !== toIdString(user._id)
            ) {
                res.status(403).json({
                    success: false,
                    message: "You can only update your own properties.",
                });
                return;
            }
            if (user.role !== "admin" && existing.status === "pending") {
                res.status(400).json({
                    success: false,
                    message: "Pending properties need admin approval first.",
                });
                return;
            }

            await col.updateOne(
                { _id: objectId },
                { $set: { status, updatedAt: new Date() } },
            );
            res.status(200).json({
                success: true,
                message: `Status updated to "${status}".`,
                data: { id, status },
            });
        } catch {
            res.status(500).json({
                success: false,
                message: "Failed to update status.",
            });
        }
    },
);

// PUT update availability calendar
app.put(
    "/api/properties/:id/availability",
    verifyToken,
    verifyHostOrAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const id = parseId(req.params.id);
            const objectId = toObjectId(id);
            const { availability } = req.body;
            const user = req.user!;
            if (!objectId) {
                res.status(400).json({
                    success: false,
                    message: "Invalid property ID.",
                });
                return;
            }
            if (!Array.isArray(availability)) {
                res.status(400).json({
                    success: false,
                    message: "Availability must be an array.",
                });
                return;
            }
            if (availability.length > 365) {
                res.status(400).json({
                    success: false,
                    message: "Max 365 entries allowed.",
                });
                return;
            }

            const dateRe = /^\d{4}-\d{2}-\d{2}$/;
            const validReasons = ["booked", "maintenance", "owner-use"];

            for (const item of availability) {
                if (!item.date || !dateRe.test(String(item.date))) {
                    res.status(400).json({
                        success: false,
                        message: `Invalid date: "${item.date}". Use YYYY-MM-DD.`,
                    });
                    return;
                }
                if (typeof item.isBlocked !== "boolean") {
                    res.status(400).json({
                        success: false,
                        message: "isBlocked must be boolean.",
                    });
                    return;
                }
                if (
                    item.reason &&
                    !validReasons.includes(String(item.reason))
                ) {
                    res.status(400).json({
                        success: false,
                        message: `Reason must be: ${validReasons.join(", ")}`,
                    });
                    return;
                }
            }

            const db = await getDb();
            const col = db.collection("properties");
            const existing = await col.findOne({
                _id: objectId,
                status: { $ne: "deleted" },
            });
            if (!existing) {
                res.status(404).json({
                    success: false,
                    message: "Property not found.",
                });
                return;
            }

            if (
                user.role !== "admin" &&
                existing.hostId !== toIdString(user._id)
            ) {
                res.status(403).json({
                    success: false,
                    message: "You can only update your own properties.",
                });
                return;
            }

            // Deduplicate by date — last entry wins
            const deduplicated = Object.values(
                availability.reduce(
                    (
                        acc: Record<string, AvailabilityDate>,
                        item: AvailabilityDate,
                    ) => {
                        acc[item.date] = item;
                        return acc;
                    },
                    {},
                ),
            );

            await col.updateOne(
                { _id: objectId },
                { $set: { availability: deduplicated, updatedAt: new Date() } },
            );
            res.status(200).json({
                success: true,
                message: "Availability updated.",
                data: { id, availability: deduplicated },
            });
        } catch {
            res.status(500).json({
                success: false,
                message: "Failed to update availability.",
            });
        }
    },
);

// POST duplicate/clone a property
app.post(
    "/api/properties/:id/duplicate",
    verifyToken,
    verifyHostOrAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const id = parseId(req.params.id);
            const objectId = toObjectId(id);
            const user = req.user!;
            if (!objectId) {
                res.status(400).json({
                    success: false,
                    message: "Invalid property ID.",
                });
                return;
            }

            const db = await getDb();
            const col = db.collection("properties");

            if (user.role !== "admin") {
                const count = await col.countDocuments({
                    hostId: toIdString(user._id),
                    status: { $ne: "deleted" },
                });
                if (count >= 50) {
                    res.status(400).json({
                        success: false,
                        message: "Maximum 50 properties allowed per host.",
                    });
                    return;
                }
            }

            const existing = await col.findOne({
                _id: objectId,
                status: { $ne: "deleted" },
            });
            if (!existing) {
                res.status(404).json({
                    success: false,
                    message: "Property not found.",
                });
                return;
            }

            if (
                user.role !== "admin" &&
                existing.hostId !== toIdString(user._id)
            ) {
                res.status(403).json({
                    success: false,
                    message: "You can only duplicate your own properties.",
                });
                return;
            }

            const now = new Date();

            // ✅ Fix 5: destructure _id out, then build complete PropertyDoc explicitly
            const {
                _id: _removed,
                createdAt: _ca,
                updatedAt: _ua,
                ...restFields
            } = existing;

            const duplicated: PropertyDoc = {
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

            const result = await col.insertOne(duplicated as PropertyDoc);

            res.status(201).json({
                success: true,
                message: "Property duplicated. Edit and submit when ready.",
                data: buildPropertyResponse({
                    ...duplicated,
                    _id: result.insertedId,
                }),
            });
        } catch (error) {
            console.error("Duplicate property error:", error);
            res.status(500).json({
                success: false,
                message: "Failed to duplicate property.",
            });
        }
    },
);

// ============================================================
// PROPERTY ROUTES — ADMIN ONLY
// ============================================================

// GET all properties with admin filters
app.get(
    "/api/admin/properties",
    verifyToken,
    verifyAdmin,
    async (req: Request, res: Response): Promise<void> => {
        try {
            const db = await getDb();
            const col = db.collection("properties");

            const { page, limit, skip } = getPagination(req.query, 100, 20);

            const filter: Record<string, any> = {};

            if (req.query.status) {
                if (
                    req.query.status !== "all" &&
                    VALID_STATUSES.includes(req.query.status as PropertyStatus)
                )
                    filter.status = String(req.query.status);
            } else {
                filter.status = { $ne: "deleted" };
            }

            if (
                req.query.category &&
                VALID_CATEGORIES.includes(
                    req.query.category as PropertyCategory,
                )
            )
                filter.category = String(req.query.category);
            if (req.query.hostId) filter.hostId = String(req.query.hostId);
            if (req.query.isFeatured === "true") filter.isFeatured = true;

            if (req.query.search) {
                const term = String(req.query.search).trim().slice(0, 100);
                if (term)
                    filter.$or = [
                        { title: { $regex: escapeRegex(term), $options: "i" } },
                        { "location.city": { $regex: escapeRegex(term), $options: "i" } },
                        { "location.country": { $regex: escapeRegex(term), $options: "i" } },
                    ];
            }

            type SortOrder = 1 | -1;
            let sort: Record<string, SortOrder> = { createdAt: -1 };
            if (req.query.sort === "oldest") sort = { createdAt: 1 };
            if (req.query.sort === "rating") sort = { rating: -1 };
            if (req.query.sort === "price-asc") sort = { "price.perNight": 1 };
            if (req.query.sort === "price-desc")
                sort = { "price.perNight": -1 };
            if (req.query.sort === "popular") sort = { reviewCount: -1 };

            const [properties, total] = await Promise.all([
                col.find(filter).sort(sort).skip(skip).limit(limit).toArray(),
                col.countDocuments(filter),
            ]);

            const statsResult = await col
                .aggregate([{ $group: { _id: "$status", count: { $sum: 1 } } }])
                .toArray();
            const stats = statsResult.reduce(
                (acc, s) => ({ ...acc, [s._id]: s.count }),
                {} as Record<string, number>,
            );
            const totalPages = Math.ceil(total / limit);

            res.status(200).json({
                success: true,
                data: {
                    properties: properties.map(buildPropertyResponse),
                    pagination: {
                        total,
                        totalPages,
                        currentPage: page,
                        limit,
                        hasNextPage: page < totalPages,
                        hasPrevPage: page > 1,
                    },
                    stats: {
                        total: Object.values(stats).reduce(
                            (a, b) => a + (b as number),
                            0,
                        ),
                        active: stats["active"] || 0,
                        pending: stats["pending"] || 0,
                        inactive: stats["inactive"] || 0,
                        draft: stats["draft"] || 0,
                        rejected: stats["rejected"] || 0,
                        deleted: stats["deleted"] || 0,
                    },
                },
            });
        } catch {
            res.status(500).json({
                success: false,
                message: "Failed to fetch properties.",
            });
        }
    },
);

// PUT approve pending property
app.put(
    "/api/admin/properties/:id/approve",
    verifyToken,
    verifyAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const id = parseId(req.params.id);
            const objectId = toObjectId(id);
            if (!objectId) {
                res.status(400).json({
                    success: false,
                    message: "Invalid property ID.",
                });
                return;
            }

            const db = await getDb();
            const col = db.collection("properties");
            const existing = await col.findOne({
                _id: objectId,
                status: { $ne: "deleted" },
            });
            if (!existing) {
                res.status(404).json({
                    success: false,
                    message: "Property not found.",
                });
                return;
            }

            if (existing.status !== "pending") {
                res.status(400).json({
                    success: false,
                    message: `Only pending properties can be approved. Current: "${existing.status}"`,
                });
                return;
            }

            await col.updateOne(
                { _id: objectId },
                {
                    $set: {
                        status: "active",
                        rejectionReason: null,
                        updatedAt: new Date(),
                    },
                },
            );
            res.status(200).json({
                success: true,
                message: "Property approved and published.",
                data: { id, status: "active" },
            });
        } catch {
            res.status(500).json({
                success: false,
                message: "Failed to approve property.",
            });
        }
    },
);

// PUT reject pending property
app.put(
    "/api/admin/properties/:id/reject",
    verifyToken,
    verifyAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const id = parseId(req.params.id);
            const objectId = toObjectId(id);
            const { reason } = req.body;
            if (!objectId) {
                res.status(400).json({
                    success: false,
                    message: "Invalid property ID.",
                });
                return;
            }
            if (
                !reason ||
                typeof reason !== "string" ||
                reason.trim().length < 5
            ) {
                res.status(400).json({
                    success: false,
                    message: "Rejection reason required (min 5 chars).",
                });
                return;
            }
            if (reason.trim().length > 500) {
                res.status(400).json({
                    success: false,
                    message: "Reason cannot exceed 500 characters.",
                });
                return;
            }

            const db = await getDb();
            const col = db.collection("properties");
            const existing = await col.findOne({
                _id: objectId,
                status: { $ne: "deleted" },
            });
            if (!existing) {
                res.status(404).json({
                    success: false,
                    message: "Property not found.",
                });
                return;
            }

            if (existing.status !== "pending") {
                res.status(400).json({
                    success: false,
                    message: `Only pending properties can be rejected. Current: "${existing.status}"`,
                });
                return;
            }

            await col.updateOne(
                { _id: objectId },
                {
                    $set: {
                        status: "rejected",
                        rejectionReason: reason.trim(),
                        updatedAt: new Date(),
                    },
                },
            );
            res.status(200).json({
                success: true,
                message: "Property rejected.",
                data: {
                    id,
                    status: "rejected",
                    rejectionReason: reason.trim(),
                },
            });
        } catch {
            res.status(500).json({
                success: false,
                message: "Failed to reject property.",
            });
        }
    },
);

// PUT toggle featured
app.put(
    "/api/admin/properties/:id/feature",
    verifyToken,
    verifyAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const id = parseId(req.params.id);
            const objectId = toObjectId(id);
            const { isFeatured } = req.body;
            if (!objectId) {
                res.status(400).json({
                    success: false,
                    message: "Invalid property ID.",
                });
                return;
            }
            if (typeof isFeatured !== "boolean") {
                res.status(400).json({
                    success: false,
                    message: "isFeatured must be boolean.",
                });
                return;
            }

            const db = await getDb();
            const col = db.collection("properties");
            const existing = await col.findOne({
                _id: objectId,
                status: { $ne: "deleted" },
            });
            if (!existing) {
                res.status(404).json({
                    success: false,
                    message: "Property not found.",
                });
                return;
            }

            if (isFeatured && existing.status !== "active") {
                res.status(400).json({
                    success: false,
                    message: "Only active properties can be featured.",
                });
                return;
            }

            await col.updateOne(
                { _id: objectId },
                { $set: { isFeatured, updatedAt: new Date() } },
            );
            res.status(200).json({
                success: true,
                message: isFeatured
                    ? "Property featured."
                    : "Property unfeatured.",
                data: { id, isFeatured },
            });
        } catch {
            res.status(500).json({
                success: false,
                message: "Failed to update featured status.",
            });
        }
    },
);

// PUT update rating (called by review system)
app.put(
    "/api/admin/properties/:id/rating",
    verifyToken,
    verifyAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const id = parseId(req.params.id);
            const objectId = toObjectId(id);
            const { rating, reviewCount } = req.body;
            if (!objectId) {
                res.status(400).json({
                    success: false,
                    message: "Invalid property ID.",
                });
                return;
            }

            const ratingNum = Number(rating);
            if (isNaN(ratingNum) || ratingNum < 0 || ratingNum > 5) {
                res.status(400).json({
                    success: false,
                    message: "Rating must be 0–5.",
                });
                return;
            }

            const updates: Record<string, any> = {
                rating: parseFloat(ratingNum.toFixed(1)),
                updatedAt: new Date(),
            };
            if (reviewCount !== undefined) {
                const n = Number(reviewCount);
                if (!isNaN(n) && n >= 0) updates.reviewCount = Math.floor(n);
            }

            const db = await getDb();
            const col = db.collection("properties");
            const existing = await col.findOne({
                _id: objectId,
                status: { $ne: "deleted" },
            });
            if (!existing) {
                res.status(404).json({
                    success: false,
                    message: "Property not found.",
                });
                return;
            }

            await col.updateOne({ _id: objectId }, { $set: updates });
            res.status(200).json({
                success: true,
                message: "Rating updated.",
                data: { id, ...updates },
            });
        } catch {
            res.status(500).json({
                success: false,
                message: "Failed to update rating.",
            });
        }
    },
);

// DELETE hard delete (admin only, sparingly)
app.delete(
    "/api/admin/properties/:id",
    verifyToken,
    verifyAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const id = parseId(req.params.id);
            const objectId = toObjectId(id);
            if (!objectId) {
                res.status(400).json({
                    success: false,
                    message: "Invalid property ID.",
                });
                return;
            }

            const db = await getDb();
            const col = db.collection("properties");
            const bookingsCol = db.collection("bookings");

            const existing = await col.findOne({ _id: objectId });
            if (!existing) {
                res.status(404).json({
                    success: false,
                    message: "Property not found.",
                });
                return;
            }

            const activeBookings = await bookingsCol.countDocuments({
                propertyId: id,
                status: { $in: ["confirmed", "pending", "checked-in"] },
            });
            if (activeBookings > 0) {
                res.status(400).json({
                    success: false,
                    message: `Cannot delete. ${activeBookings} active booking(s) exist.`,
                });
                return;
            }

            await col.deleteOne({ _id: objectId });
            res.status(200).json({
                success: true,
                message: `Property "${existing.title}" permanently deleted.`,
                data: { id },
            });
        } catch {
            res.status(500).json({
                success: false,
                message: "Failed to delete property.",
            });
        }
    },
);

// ============================================================
// BOOKING ROUTES
// ============================================================

// POST create booking (guest)
app.post(
    "/api/bookings",
    verifyToken,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const user = req.user!;
            if (user.role !== "guest" && user.role !== "admin") {
                res.status(403).json({
                    success: false,
                    message: "Only guests can create bookings.",
                });
                return;
            }

            const { propertyId, checkIn, checkOut, numberOfGuests, specialRequest } = req.body;

            if (!propertyId || !checkIn || !checkOut || !numberOfGuests) {
                res.status(400).json({
                    success: false,
                    message: "propertyId, checkIn, checkOut, numberOfGuests are required.",
                });
                return;
            }

            const checkInDate = new Date(checkIn);
            const checkOutDate = new Date(checkOut);
            const today = new Date();
            today.setHours(0, 0, 0, 0);

            if (checkInDate < today) {
                res.status(400).json({ success: false, message: "Check-in cannot be in the past." });
                return;
            }
            if (checkOutDate <= checkInDate) {
                res.status(400).json({ success: false, message: "Check-out must be after check-in." });
                return;
            }

            const db = await getDb();
            const propertiesCol = db.collection("properties");
            const bookingsCol = db.collection("bookings");

            const propertyOid = toObjectId(parseId(propertyId));
            if (!propertyOid) {
                res.status(400).json({ success: false, message: "Invalid property ID." });
                return;
            }
            const property = await propertiesCol.findOne({
                _id: propertyOid,
                status: "active",
            });
            if (!property) {
                res.status(404).json({ success: false, message: "Property not found or not active." });
                return;
            }

            if (numberOfGuests > (property.details?.maxGuests || 99)) {
                res.status(400).json({
                    success: false,
                    message: `Maximum ${property.details.maxGuests} guests allowed.`,
                });
                return;
            }

            const hasOverlap = await checkDateOverlap(
                bookingsCol, propertyId, checkInDate, checkOutDate
            );
            if (hasOverlap) {
                res.status(409).json({
                    success: false,
                    message: "This property is already booked for the selected dates.",
                });
                return;
            }

            const nights = calculateNights(checkInDate, checkOutDate);
            const pricePerNight = property.price?.perNight || 0;
            const totalAmount = Math.round(pricePerNight * nights * 100) / 100;
            const { platformFee, hostEarning } = calculateFees(totalAmount);

            const hostId = property.hostId;

            const now = new Date();
            const booking: BookingDoc = {
                guestId: toIdString(user._id),
                hostId,
                propertyId,
                propertyTitle: property.title || "",
                propertyImage: Array.isArray(property.images) && property.images.length > 0
                    ? property.images[0] : "",
                checkIn: checkInDate,
                checkOut: checkOutDate,
                numberOfGuests: Number(numberOfGuests),
                numberOfNights: nights,
                pricePerNight,
                totalAmount,
                platformFee,
                hostEarning,
                status: "pending",
                specialRequest: specialRequest || undefined,
                createdAt: now,
                updatedAt: now,
            };

            const result = await bookingsCol.insertOne(booking as BookingDoc);

            res.status(201).json({
                success: true,
                message: "Booking created. Proceed to payment.",
                data: {
                    booking: { ...booking, _id: result.insertedId },
                },
            });
        } catch (error) {
            console.error("Create booking error:", error);
            res.status(500).json({ success: false, message: "Failed to create booking." });
        }
    },
);

// GET my bookings (guest)
app.get(
    "/api/bookings/my-bookings",
    verifyToken,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const user = req.user!;
            const db = await getDb();
            const col = db.collection("bookings");

            const { page, limit, skip } = getPagination(req.query, 50, 10);

            const filter: Record<string, any> = { guestId: toIdString(user._id) };

            if (req.query.status && ["pending", "confirmed", "cancelled", "completed"].includes(String(req.query.status))) {
                filter.status = String(req.query.status);
            }
            if (req.query.search) {
                filter.propertyTitle = { $regex: escapeRegex(String(req.query.search)), $options: "i" };
            }

            const [bookings, total] = await Promise.all([
                col.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
                col.countDocuments(filter),
            ]);

            res.status(200).json({
                success: true,
                data: {
                    bookings,
                    pagination: {
                        total,
                        totalPages: Math.ceil(total / limit),
                        currentPage: page,
                        limit,
                    },
                },
            });
        } catch {
            res.status(500).json({ success: false, message: "Failed to fetch bookings." });
        }
    },
);

// GET host reservations
app.get(
    "/api/bookings/host-reservations",
    verifyToken,
    verifyHostOrAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const user = req.user!;
            const db = await getDb();
            const col = db.collection("bookings");

            const { page, limit, skip } = getPagination(req.query, 50, 10);

            const filter: Record<string, any> = { hostId: toIdString(user._id) };

            if (req.query.status && ["pending", "confirmed", "cancelled", "completed"].includes(String(req.query.status))) {
                filter.status = String(req.query.status);
            }
            if (req.query.propertyId) {
                filter.propertyId = String(req.query.propertyId);
            }

            const [bookings, total] = await Promise.all([
                col.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
                col.countDocuments(filter),
            ]);

            // Attach guest info (batched)
            const usersCol = db.collection("user");
            const usersMap = await findUsersMap(usersCol, (bookings as any[]).map((b: any) => b.guestId));
            const bookingsWithGuests = (bookings as any[]).map((b: any) => {
                const guest = usersMap.get(b.guestId);
                return {
                    ...b,
                    guest: guest
                        ? { id: toIdString(guest._id), name: guest.name, image: guest.image }
                        : null,
                };
            });

            res.status(200).json({
                success: true,
                data: {
                    bookings: bookingsWithGuests,
                    pagination: {
                        total,
                        totalPages: Math.ceil(total / limit),
                        currentPage: page,
                        limit,
                    },
                },
            });
        } catch {
            res.status(500).json({ success: false, message: "Failed to fetch reservations." });
        }
    },
);

// GET single booking detail
app.get(
    "/api/bookings/:id",
    verifyToken,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const id = parseId(req.params.id);
            const objectId = toObjectId(id);
            if (!objectId) {
                res.status(400).json({ success: false, message: "Invalid booking ID." });
                return;
            }

            const db = await getDb();
            const col = db.collection("bookings");
            const booking = await col.findOne({ _id: objectId }) as any;

            if (!booking) {
                res.status(404).json({ success: false, message: "Booking not found." });
                return;
            }

            const userId = toIdString(req.user!._id);
            const isGuest = booking.guestId === userId;
            const isHost = booking.hostId === userId;
            const isAdmin = req.user!.role === "admin";

            if (!isGuest && !isHost && !isAdmin) {
                res.status(403).json({ success: false, message: "Access denied." });
                return;
            }

            // Attach guest, host, property info
            const usersCol = db.collection("user");
            const propertiesCol = db.collection("properties");

            const [guest, host, property] = await Promise.all([
                findUserById(usersCol, booking.guestId),
                findUserById(usersCol, booking.hostId),
                propertiesCol.findOne({ _id: toObjectId(parseId(booking.propertyId))! }),
            ]);

            res.status(200).json({
                success: true,
                data: {
                    ...booking,
                    guest: guest ? { id: toIdString(guest._id), name: guest.name, image: guest.image } : null,
                    host: host ? { id: toIdString(host._id), name: host.name, image: host.image } : null,
                    property: property ? {
                        id: toIdString(property._id),
                        title: property.title,
                        images: property.images,
                        location: property.location,
                        category: property.category,
                    } : null,
                },
            });
        } catch {
            res.status(500).json({ success: false, message: "Failed to fetch booking." });
        }
    },
);

// PUT confirm booking (host)
app.put(
    "/api/bookings/:id/confirm",
    verifyToken,
    verifyHostOrAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const id = parseId(req.params.id);
            const objectId = toObjectId(id);
            if (!objectId) {
                res.status(400).json({ success: false, message: "Invalid booking ID." });
                return;
            }

            const db = await getDb();
            const col = db.collection("bookings");
            const booking = await col.findOne({ _id: objectId }) as any;

            if (!booking) {
                res.status(404).json({ success: false, message: "Booking not found." });
                return;
            }

            const userId = toIdString(req.user!._id);
            if (booking.hostId !== userId && req.user!.role !== "admin") {
                res.status(403).json({ success: false, message: "You are not the host of this property." });
                return;
            }

            if (booking.status !== "pending") {
                res.status(400).json({ success: false, message: "Only pending bookings can be confirmed." });
                return;
            }

            await col.updateOne(
                { _id: objectId },
                { $set: { status: "confirmed", updatedAt: new Date() } },
            );

            res.status(200).json({
                success: true,
                message: "Booking confirmed.",
                data: { id, status: "confirmed" },
            });
        } catch {
            res.status(500).json({ success: false, message: "Failed to confirm booking." });
        }
    },
);

// PUT cancel booking (guest/host/admin)
app.put(
    "/api/bookings/:id/cancel",
    verifyToken,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const id = parseId(req.params.id);
            const objectId = toObjectId(id);
            if (!objectId) {
                res.status(400).json({ success: false, message: "Invalid booking ID." });
                return;
            }

            const { reason } = req.body;

            const db = await getDb();
            const col = db.collection("bookings");
            const booking = await col.findOne({ _id: objectId }) as any;

            if (!booking) {
                res.status(404).json({ success: false, message: "Booking not found." });
                return;
            }

            const userId = toIdString(req.user!._id);
            const isGuest = booking.guestId === userId;
            const isHost = booking.hostId === userId;
            const isAdmin = req.user!.role === "admin";

            if (!isGuest && !isHost && !isAdmin) {
                res.status(403).json({ success: false, message: "Access denied." });
                return;
            }

            if (booking.status !== "pending" && booking.status !== "confirmed") {
                res.status(400).json({ success: false, message: "Booking cannot be cancelled in its current state." });
                return;
            }

            let cancelledBy: "guest" | "host" | "admin" = "guest";
            if (isAdmin) cancelledBy = "admin";
            else if (isHost) cancelledBy = "host";

            await col.updateOne(
                { _id: objectId },
                {
                    $set: {
                        status: "cancelled",
                        cancelledBy,
                        cancellationReason: reason || undefined,
                        updatedAt: new Date(),
                    },
                },
            );

            res.status(200).json({
                success: true,
                message: "Booking cancelled.",
                data: { id, status: "cancelled", cancelledBy },
            });
        } catch {
            res.status(500).json({ success: false, message: "Failed to cancel booking." });
        }
    },
);

// PUT complete booking (host)
app.put(
    "/api/bookings/:id/complete",
    verifyToken,
    verifyHostOrAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const id = parseId(req.params.id);
            const objectId = toObjectId(id);
            if (!objectId) {
                res.status(400).json({ success: false, message: "Invalid booking ID." });
                return;
            }

            const db = await getDb();
            const col = db.collection("bookings");
            const booking = await col.findOne({ _id: objectId }) as any;

            if (!booking) {
                res.status(404).json({ success: false, message: "Booking not found." });
                return;
            }

            const userId = toIdString(req.user!._id);
            if (booking.hostId !== userId && req.user!.role !== "admin") {
                res.status(403).json({ success: false, message: "You are not the host of this property." });
                return;
            }

            if (booking.status !== "confirmed") {
                res.status(400).json({ success: false, message: "Only confirmed bookings can be completed." });
                return;
            }

            await col.updateOne(
                { _id: objectId },
                { $set: { status: "completed", updatedAt: new Date() } },
            );

            res.status(200).json({
                success: true,
                message: "Booking marked as completed.",
                data: { id, status: "completed" },
            });
        } catch {
            res.status(500).json({ success: false, message: "Failed to complete booking." });
        }
    },
);

// GET admin all bookings
app.get(
    "/api/admin/bookings",
    verifyToken,
    verifyAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const db = await getDb();
            const col = db.collection("bookings");

            const { page, limit, skip } = getPagination(req.query, 100, 20);

            const filter: Record<string, any> = {};

            if (req.query.status && ["pending", "confirmed", "cancelled", "completed"].includes(String(req.query.status))) {
                filter.status = String(req.query.status);
            }
            if (req.query.guestId) filter.guestId = String(req.query.guestId);
            if (req.query.hostId) filter.hostId = String(req.query.hostId);
            if (req.query.propertyId) filter.propertyId = String(req.query.propertyId);
            if (req.query.search) {
                filter.propertyTitle = { $regex: escapeRegex(String(req.query.search)), $options: "i" };
            }

            const [bookings, total] = await Promise.all([
                col.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
                col.countDocuments(filter),
            ]);

            res.status(200).json({
                success: true,
                data: {
                    bookings,
                    pagination: {
                        total,
                        totalPages: Math.ceil(total / limit),
                        currentPage: page,
                        limit,
                    },
                },
            });
        } catch {
            res.status(500).json({ success: false, message: "Failed to fetch bookings." });
        }
    },
);

// PUT admin force cancel booking
app.put(
    "/api/admin/bookings/:id/force-cancel",
    verifyToken,
    verifyAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const id = parseId(req.params.id);
            const objectId = toObjectId(id);
            if (!objectId) {
                res.status(400).json({ success: false, message: "Invalid booking ID." });
                return;
            }

            const { reason } = req.body;

            const db = await getDb();
            const col = db.collection("bookings");
            const booking = await col.findOne({ _id: objectId }) as any;

            if (!booking) {
                res.status(404).json({ success: false, message: "Booking not found." });
                return;
            }

            await col.updateOne(
                { _id: objectId },
                {
                    $set: {
                        status: "cancelled",
                        cancelledBy: "admin",
                        cancellationReason: reason || "Force cancelled by admin",
                        updatedAt: new Date(),
                    },
                },
            );

            res.status(200).json({
                success: true,
                message: "Booking force cancelled by admin.",
                data: { id, status: "cancelled" },
            });
        } catch {
            res.status(500).json({ success: false, message: "Failed to force cancel booking." });
        }
    },
);

// ============================================================
// PAYOUT ROUTES (host bank details, manual payouts)
// ============================================================

// PUT save payout method (host bank details)
app.put(
    "/api/payments/payout-method",
    verifyToken,
    verifyHostOrAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const user = req.user!;
            const { accountHolder, bankName, accountNumber, routingNumber, swiftCode, bankAddress } = req.body;

            if (!accountHolder || !bankName || !accountNumber) {
                res.status(400).json({ success: false, message: "accountHolder, bankName, accountNumber are required." });
                return;
            }

            const db = await getDb();
            const col = db.collection("payout_methods");
            const userId = toIdString(user._id);

            const existing = await col.findOne({ userId });
            const now = new Date();
            const data = {
                userId,
                accountHolder: String(accountHolder).trim(),
                bankName: String(bankName).trim(),
                accountNumber: String(accountNumber).trim(),
                routingNumber: String(routingNumber || "").trim(),
                swiftCode: String(swiftCode || "").trim(),
                bankAddress: String(bankAddress || "").trim(),
                updatedAt: now,
            };

            if (existing) {
                await col.updateOne({ userId }, { $set: data });
            } else {
                await col.insertOne({ ...data, createdAt: now });
            }

            res.status(200).json({
                success: true,
                message: existing ? "Payout method updated." : "Payout method saved.",
            });
        } catch {
            res.status(500).json({ success: false, message: "Failed to save payout method." });
        }
    },
);

// GET payout method (masked)
app.get(
    "/api/payments/payout-method",
    verifyToken,
    verifyHostOrAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const db = await getDb();
            const col = db.collection("payout_methods");
            const method = await col.findOne({ userId: toIdString(req.user!._id) }) as any;

            if (!method) {
                res.status(200).json({ success: true, data: null });
                return;
            }

            // Mask account number
            const accNum = method.accountNumber || "";
            const masked = accNum.length > 4
                ? "****" + accNum.slice(-4)
                : "****";

            res.status(200).json({
                success: true,
                data: {
                    id: toIdString(method._id),
                    accountHolder: method.accountHolder,
                    bankName: method.bankName,
                    accountNumber: masked,
                    routingNumber: method.routingNumber,
                    swiftCode: method.swiftCode,
                    bankAddress: method.bankAddress,
                    createdAt: method.createdAt,
                    updatedAt: method.updatedAt,
                },
            });
        } catch {
            res.status(500).json({ success: false, message: "Failed to get payout method." });
        }
    },
);

// POST request payout (host)
app.post(
    "/api/payments/request-payout",
    verifyToken,
    verifyHostOrAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const user = req.user!;
            const { amount } = req.body;

            if (!amount || amount <= 0) {
                res.status(400).json({ success: false, message: "Valid amount is required." });
                return;
            }

            const db = await getDb();
            const transactionsCol = db.collection("transactions");
            const payoutMethodsCol = db.collection("payout_methods");

            // Check they have a payout method
            const method = await payoutMethodsCol.findOne({ userId: toIdString(user._id) });
            if (!method) {
                res.status(400).json({ success: false, message: "Please save a payout method first." });
                return;
            }

            // Check available balance
            const earnings = await transactionsCol.aggregate([
                { $match: { userId: toIdString(user._id), type: "payment", status: "success" } },
                { $group: { _id: null, total: { $sum: "$amount" } } },
            ]).toArray();

            const paidOut = await transactionsCol.aggregate([
                { $match: { userId: toIdString(user._id), type: "payout", status: "success" } },
                { $group: { _id: null, total: { $sum: "$amount" } } },
            ]).toArray();

            const totalEarnings = (earnings[0] as any)?.total || 0;
            const totalPaidOut = (paidOut[0] as any)?.total || 0;
            const available = totalEarnings - totalPaidOut;

            if (Number(amount) > available) {
                res.status(400).json({
                    success: false,
                    message: `Insufficient balance. Available: $${available.toFixed(2)}`,
                });
                return;
            }

            const transactionId = `payout_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
            await transactionsCol.insertOne({
                userId: toIdString(user._id),
                bookingId: "",
                type: "payout",
                amount: Math.round(Number(amount) * 100) / 100,
                currency: (process.env.STRIPE_CURRENCY || "usd").toUpperCase(),
                method: "bank",
                status: "pending",
                transactionId,
                description: "Payout withdrawal request",
                createdAt: new Date(),
            });

            res.status(200).json({
                success: true,
                message: "Payout requested. Admin will process it shortly.",
                data: { transactionId, amount, status: "pending" },
            });
        } catch {
            res.status(500).json({ success: false, message: "Failed to request payout." });
        }
    },
);

// GET payout history (host)
app.get(
    "/api/payments/payout-history",
    verifyToken,
    verifyHostOrAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const db = await getDb();
            const col = db.collection("transactions");
            const { page, limit, skip } = getPagination(req.query, 50, 10);

            const filter: Record<string, any> = {
                userId: toIdString(req.user!._id),
                type: "payout",
            };

            const [transactions, total] = await Promise.all([
                col.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
                col.countDocuments(filter),
            ]);

            res.status(200).json({
                success: true,
                data: {
                    transactions,
                    pagination: {
                        total,
                        totalPages: Math.ceil(total / limit),
                        currentPage: page,
                        limit,
                    },
                },
            });
        } catch {
            res.status(500).json({ success: false, message: "Failed to fetch payout history." });
        }
    },
);

// ============================================================
// TRANSACTION ROUTES
// ============================================================

// GET my transactions (guest)
app.get(
    "/api/transactions/my-transactions",
    verifyToken,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const db = await getDb();
            const col = db.collection("transactions");
            const { page, limit, skip } = getPagination(req.query, 50, 10);

            const filter: Record<string, any> = {
                userId: toIdString(req.user!._id),
                type: { $in: ["payment", "refund"] },
            };

            if (req.query.status) filter.status = String(req.query.status);
            if (req.query.method) filter.method = String(req.query.method);

            const [transactions, total] = await Promise.all([
                col.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
                col.countDocuments(filter),
            ]);

            res.status(200).json({
                success: true,
                data: {
                    transactions,
                    pagination: {
                        total,
                        totalPages: Math.ceil(total / limit),
                        currentPage: page,
                        limit,
                    },
                },
            });
        } catch {
            res.status(500).json({ success: false, message: "Failed to fetch transactions." });
        }
    },
);

// GET host transactions
app.get(
    "/api/transactions/host-transactions",
    verifyToken,
    verifyHostOrAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const db = await getDb();
            const col = db.collection("transactions");
            const { page, limit, skip } = getPagination(req.query, 50, 10);

            const filter: Record<string, any> = {
                userId: toIdString(req.user!._id),
                type: { $in: ["payout", "commission"] },
            };

            if (req.query.status) filter.status = String(req.query.status);
            if (req.query.type) filter.type = String(req.query.type);

            const [transactions, total] = await Promise.all([
                col.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
                col.countDocuments(filter),
            ]);

            res.status(200).json({
                success: true,
                data: {
                    transactions,
                    pagination: {
                        total,
                        totalPages: Math.ceil(total / limit),
                        currentPage: page,
                        limit,
                    },
                },
            });
        } catch {
            res.status(500).json({ success: false, message: "Failed to fetch host transactions." });
        }
    },
);

// GET single transaction
app.get(
    "/api/transactions/:id",
    verifyToken,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const id = parseId(req.params.id);
            const objectId = toObjectId(id);
            if (!objectId) {
                res.status(400).json({ success: false, message: "Invalid transaction ID." });
                return;
            }

            const db = await getDb();
            const col = db.collection("transactions");
            const transaction = await col.findOne({ _id: objectId });

            if (!transaction) {
                res.status(404).json({ success: false, message: "Transaction not found." });
                return;
            }

            const userId = toIdString(req.user!._id);
            if ((transaction as any).userId !== userId && req.user!.role !== "admin") {
                res.status(403).json({ success: false, message: "Access denied." });
                return;
            }

            res.status(200).json({ success: true, data: transaction });
        } catch {
            res.status(500).json({ success: false, message: "Failed to fetch transaction." });
        }
    },
);

// POST refund (admin)
app.post(
    "/api/transactions/refund/:bookingId",
    verifyToken,
    verifyAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const bookingId = parseId(req.params.bookingId);

            const db = await getDb();
            const bookingsCol = db.collection("bookings");
            const transactionsCol = db.collection("transactions");

            const objectId = toObjectId(bookingId);
            if (!objectId) {
                res.status(400).json({ success: false, message: "Invalid booking ID." });
                return;
            }

            const booking = await bookingsCol.findOne({ _id: objectId }) as any;
            if (!booking) {
                res.status(404).json({ success: false, message: "Booking not found." });
                return;
            }

            // Find the original payment transaction
            const payment = await transactionsCol.findOne({
                bookingId,
                type: "payment",
                status: "success",
            });

            if (!payment) {
                res.status(400).json({ success: false, message: "No successful payment found for this booking." });
                return;
            }

            const refundAmount = (payment as any).amount;
            const transactionId = `refund_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;

            await transactionsCol.insertOne({
                userId: booking.guestId,
                bookingId,
                type: "refund",
                amount: refundAmount,
                currency: (payment as any).currency || "USD",
                method: (payment as any).method || "card",
                status: "success",
                transactionId,
                description: `Refund for booking at ${booking.propertyTitle}`,
                createdAt: new Date(),
            });

            // Update original payment to refunded
            await transactionsCol.updateOne(
                { _id: payment._id },
                { $set: { status: "refunded" } },
            );

            res.status(200).json({
                success: true,
                message: `Refund of $${refundAmount} processed.`,
                data: { transactionId, amount: refundAmount },
            });
        } catch {
            res.status(500).json({ success: false, message: "Failed to process refund." });
        }
    },
);

// GET admin all transactions
app.get(
    "/api/admin/transactions",
    verifyToken,
    verifyAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const db = await getDb();
            const col = db.collection("transactions");
            const { page, limit, skip } = getPagination(req.query, 100, 20);

            const filter: Record<string, any> = {};

            if (req.query.type) filter.type = String(req.query.type);
            if (req.query.status) filter.status = String(req.query.status);
            if (req.query.method) filter.method = String(req.query.method);
            if (req.query.userId) filter.userId = String(req.query.userId);

            const [transactions, total] = await Promise.all([
                col.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
                col.countDocuments(filter),
            ]);

            res.status(200).json({
                success: true,
                data: {
                    transactions,
                    pagination: {
                        total,
                        totalPages: Math.ceil(total / limit),
                        currentPage: page,
                        limit,
                    },
                },
            });
        } catch {
            res.status(500).json({ success: false, message: "Failed to fetch transactions." });
        }
    },
);

// GET transaction stats
app.get(
    "/api/transactions/stats",
    verifyToken,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const db = await getDb();
            const col = db.collection("transactions");
            const userId = toIdString(req.user!._id);
            const isAdmin = req.user!.role === "admin";

            let matchFilter: Record<string, any> = {};
            if (!isAdmin) {
                matchFilter = { userId };
            }

            // Total spend (guest payments)
            const totalSpendArr = await col.aggregate([
                { $match: { ...matchFilter, type: "payment", status: "success" } },
                { $group: { _id: null, total: { $sum: "$amount" } } },
            ]).toArray();
            const totalSpend = (totalSpendArr[0] as any)?.total || 0;

            // Total earned (host earnings)
            const totalEarnArr = await col.aggregate([
                { $match: { ...matchFilter, type: "payout", status: "success" } },
                { $group: { _id: null, total: { $sum: "$amount" } } },
            ]).toArray();
            const totalEarned = (totalEarnArr[0] as any)?.total || 0;

            // Platform commission earned (admin only)
            let commissionEarned = 0;
            let pendingPayouts = 0;
            if (isAdmin) {
                const commissionArr = await col.aggregate([
                    { $match: { type: "commission", status: "success" } },
                    { $group: { _id: null, total: { $sum: "$amount" } } },
                ]).toArray();
                commissionEarned = (commissionArr[0] as any)?.total || 0;

                const pendingArr = await col.aggregate([
                    { $match: { type: "payout", status: "pending" } },
                    { $group: { _id: null, total: { $sum: "$amount" } } },
                ]).toArray();
                pendingPayouts = (pendingArr[0] as any)?.total || 0;
            }

            res.status(200).json({
                success: true,
                data: {
                    totalSpend: Math.round(totalSpend * 100) / 100,
                    totalEarned: Math.round(totalEarned * 100) / 100,
                    ...(isAdmin ? {
                        commissionEarned: Math.round(commissionEarned * 100) / 100,
                        pendingPayouts: Math.round(pendingPayouts * 100) / 100,
                    } : {}),
                },
            });
        } catch {
            res.status(500).json({ success: false, message: "Failed to fetch transaction stats." });
        }
    },
);

// POST admin process payout
app.post(
    "/api/admin/payments/process-payout",
    verifyToken,
    verifyAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const { transactionId } = req.body;

            if (!transactionId) {
                res.status(400).json({ success: false, message: "transactionId is required." });
                return;
            }

            const db = await getDb();
            const col = db.collection("transactions");

            // Find by transactionId string (not _id)
            const txn = await col.findOne({ transactionId }) as any;
            if (!txn) {
                res.status(404).json({ success: false, message: "Transaction not found." });
                return;
            }

            if (txn.type !== "payout") {
                res.status(400).json({ success: false, message: "Only payout transactions can be processed." });
                return;
            }

            if (txn.status !== "pending") {
                res.status(400).json({ success: false, message: "Only pending payouts can be processed." });
                return;
            }

            await col.updateOne(
                { _id: txn._id },
                { $set: { status: "success" } },
            );

            res.status(200).json({
                success: true,
                message: "Payout processed successfully.",
                data: { transactionId, status: "success" },
            });
        } catch {
            res.status(500).json({ success: false, message: "Failed to process payout." });
        }
    },
);

// ============================================================
// WISHLIST ROUTES
// ============================================================

// POST toggle wishlist
app.post(
    "/api/wishlist/toggle",
    verifyToken,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const { propertyId, listName } = req.body;
            if (!propertyId) {
                res.status(400).json({ success: false, message: "propertyId is required." });
                return;
            }

            const db = await getDb();
            const col = db.collection("wishlist");
            const userId = toIdString(req.user!._id);

            const existing = await col.findOne({ userId, propertyId });

            if (existing) {
                await col.deleteOne({ _id: existing._id });
                res.status(200).json({ success: true, data: { action: "removed", propertyId } });
            } else {
                await col.insertOne({
                    userId,
                    propertyId,
                    listName: listName || undefined,
                    createdAt: new Date(),
                });
                res.status(201).json({ success: true, data: { action: "added", propertyId } });
            }
        } catch {
            res.status(500).json({ success: false, message: "Failed to toggle wishlist." });
        }
    },
);

// GET wishlist
app.get(
    "/api/wishlist",
    verifyToken,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const db = await getDb();
            const col = db.collection("wishlist");
            const propertiesCol = db.collection("properties");
            const userId = toIdString(req.user!._id);

            const { page, limit, skip } = getPagination(req.query, 50, 12);

            const filter: Record<string, any> = { userId };
            if (req.query.listName) filter.listName = String(req.query.listName);

            const [items, total] = await Promise.all([
                col.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
                col.countDocuments(filter),
            ]);

            // Join property data (batched)
            const propIds = (items as any[]).map((i: any) => parseId(i.propertyId)).filter((id): id is string => id !== null);
            const propOids = propIds.map((id: string) => toObjectId(id)).filter((id): id is ObjectId => id !== null);
            let propertyMap = new Map<string, any>();
            if (propOids.length > 0) {
                const props = await propertiesCol
                    .find({ _id: { $in: propOids }, status: { $ne: "deleted" } })
                    .toArray();
                propertyMap = new Map(
                    (props as any[]).map((p: any) => [toIdString(p._id), p]),
                );
            }
            const itemsWithProperties = (items as any[]).map((item: any) => {
                const prop = propertyMap.get(item.propertyId);
                return {
                    _id: item._id,
                    propertyId: item.propertyId,
                    listName: item.listName,
                    createdAt: item.createdAt,
                    property: prop
                        ? {
                            id: toIdString(prop._id),
                            title: prop.title,
                            images: prop.images,
                            price: prop.price,
                            location: prop.location,
                            category: prop.category,
                            rating: prop.rating,
                        }
                        : null,
                };
            });

            res.status(200).json({
                success: true,
                data: {
                    items: itemsWithProperties,
                    pagination: {
                        total,
                        totalPages: Math.ceil(total / limit),
                        currentPage: page,
                        limit,
                    },
                },
            });
        } catch {
            res.status(500).json({ success: false, message: "Failed to fetch wishlist." });
        }
    },
);

// GET check wishlist
app.get(
    "/api/wishlist/check/:propertyId",
    verifyToken,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const db = await getDb();
            const col = db.collection("wishlist");
            const userId = toIdString(req.user!._id);
            const propertyId = parseId(req.params.propertyId);

            const existing = await col.findOne({ userId, propertyId });
            res.status(200).json({ success: true, data: { isSaved: !!existing } });
        } catch {
            res.status(500).json({ success: false, message: "Failed to check wishlist." });
        }
    },
);

// PUT update wishlist list name
app.put(
    "/api/wishlist/:id/list",
    verifyToken,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const id = parseId(req.params.id);
            const objectId = toObjectId(id);
            if (!objectId) {
                res.status(400).json({ success: false, message: "Invalid wishlist ID." });
                return;
            }

            const { listName } = req.body;
            const db = await getDb();
            const col = db.collection("wishlist");

            const item = await col.findOne({ _id: objectId });
            if (!item) {
                res.status(404).json({ success: false, message: "Wishlist item not found." });
                return;
            }

            const userId = toIdString(req.user!._id);
            if ((item as any).userId !== userId) {
                res.status(403).json({ success: false, message: "Access denied." });
                return;
            }

            await col.updateOne({ _id: objectId }, { $set: { listName: listName || "" } });
            res.status(200).json({ success: true, message: "List name updated." });
        } catch {
            res.status(500).json({ success: false, message: "Failed to update list name." });
        }
    },
);

// DELETE wishlist item
app.delete(
    "/api/wishlist/:id",
    verifyToken,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const id = parseId(req.params.id);
            const objectId = toObjectId(id);
            if (!objectId) {
                res.status(400).json({ success: false, message: "Invalid wishlist ID." });
                return;
            }

            const db = await getDb();
            const col = db.collection("wishlist");

            const item = await col.findOne({ _id: objectId });
            if (!item) {
                res.status(404).json({ success: false, message: "Wishlist item not found." });
                return;
            }

            const userId = toIdString(req.user!._id);
            if ((item as any).userId !== userId) {
                res.status(403).json({ success: false, message: "Access denied." });
                return;
            }

            await col.deleteOne({ _id: objectId });
            res.status(200).json({ success: true, message: "Removed from wishlist." });
        } catch {
            res.status(500).json({ success: false, message: "Failed to remove from wishlist." });
        }
    },
);

// GET wishlist lists
app.get(
    "/api/wishlist/lists",
    verifyToken,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const db = await getDb();
            const col = db.collection("wishlist");
            const userId = toIdString(req.user!._id);

            const lists = await col.distinct("listName", { userId, listName: { $ne: "" } });
            res.status(200).json({ success: true, data: { lists: lists.filter(Boolean) } });
        } catch {
            res.status(500).json({ success: false, message: "Failed to fetch lists." });
        }
    },
);

// ============================================================
// REVIEW ROUTES
// ============================================================

// Helper: update property rating
async function updatePropertyRating(propertiesCol: any, propertyId: string): Promise<void> {
    try {
        const reviewsCol = propertiesCol.db.collection("reviews");
        const stats = await reviewsCol.aggregate([
            { $match: { propertyId, isReported: { $ne: true } } },
            { $group: { _id: null, avgRating: { $avg: "$rating" }, count: { $sum: 1 } } },
        ]).toArray();
        const avg = stats.length > 0 ? Math.round(((stats[0] as any).avgRating || 0) * 10) / 10 : 0;
        const cnt = stats.length > 0 ? (stats[0] as any).count || 0 : 0;
        const propOid = toObjectId(parseId(propertyId));
        if (propOid) {
            await propertiesCol.updateOne(
                { _id: propOid },
                { $set: { rating: avg, reviewCount: cnt } },
            );
        }
    } catch (err) {
        console.warn("Failed to update property rating:", err);
    }
}

// POST create review (guest)
app.post(
    "/api/reviews",
    verifyToken,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const user = req.user!;
            const { bookingId, rating, comment } = req.body;

            if (!bookingId || !rating || !comment) {
                res.status(400).json({ success: false, message: "bookingId, rating, comment are required." });
                return;
            }

            const ratingNum = Number(rating);
            if (ratingNum < 1 || ratingNum > 5 || !Number.isInteger(ratingNum)) {
                res.status(400).json({ success: false, message: "Rating must be an integer between 1 and 5." });
                return;
            }

            const db = await getDb();
            const bookingsCol = db.collection("bookings");
            const reviewsCol = db.collection("reviews");
            const propertiesCol = db.collection("properties");

            const bookingOid = toObjectId(parseId(bookingId));
            if (!bookingOid) {
                res.status(400).json({ success: false, message: "Invalid booking ID." });
                return;
            }

            const booking = await bookingsCol.findOne({ _id: bookingOid }) as any;
            if (!booking) {
                res.status(404).json({ success: false, message: "Booking not found." });
                return;
            }

            if (booking.guestId !== toIdString(user._id)) {
                res.status(403).json({ success: false, message: "You can only review your own bookings." });
                return;
            }

            if (booking.status !== "completed") {
                res.status(400).json({ success: false, message: "You can only review completed bookings." });
                return;
            }

            const existingReview = await reviewsCol.findOne({ bookingId });
            if (existingReview) {
                res.status(400).json({ success: false, message: "You have already reviewed this booking." });
                return;
            }

            const now = new Date();
            const review: ReviewDoc = {
                guestId: toIdString(user._id),
                hostId: booking.hostId,
                propertyId: booking.propertyId,
                bookingId,
                rating: ratingNum,
                comment: String(comment).trim(),
                createdAt: now,
            };

            const result = await reviewsCol.insertOne(review as ReviewDoc);
            await updatePropertyRating(propertiesCol, booking.propertyId);

            res.status(201).json({
                success: true,
                message: "Review submitted.",
                data: { ...review, _id: result.insertedId },
            });
        } catch {
            res.status(500).json({ success: false, message: "Failed to submit review." });
        }
    },
);

// GET property reviews (public)
app.get(
    "/api/reviews/property/:id",
    async (req: Request, res: Response): Promise<void> => {
        try {
            const propertyId = parseId(req.params.id);
            const db = await getDb();
            const reviewsCol = db.collection("reviews");
            const usersCol = db.collection("user");

            const { page, limit, skip } = getPagination(req.query, 50, 10);

            const filter: Record<string, any> = { propertyId, isReported: { $ne: true } };

            const [reviews, total] = await Promise.all([
                reviewsCol.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
                reviewsCol.countDocuments(filter),
            ]);

            const reviewsWithGuests = await Promise.all(
                (reviews as any[]).map(async (r) => {
                    const guest = await findUserById(usersCol, r.guestId);
                    return {
                        ...r,
                        guest: guest
                            ? { id: toIdString(guest._id), name: guest.name, image: guest.image }
                            : null,
                    };
                }),
            );

            res.status(200).json({
                success: true,
                data: {
                    reviews: reviewsWithGuests,
                    pagination: {
                        total,
                        totalPages: Math.ceil(total / limit),
                        currentPage: page,
                        limit,
                    },
                },
            });
        } catch {
            res.status(500).json({ success: false, message: "Failed to fetch reviews." });
        }
    },
);

// GET my reviews (guest)
app.get(
    "/api/reviews/my-reviews",
    verifyToken,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const db = await getDb();
            const reviewsCol = db.collection("reviews");
            const bookingsCol = db.collection("bookings");
            const userId = toIdString(req.user!._id);

            const { page, limit, skip } = getPagination(req.query, 50, 10);

            const [reviews, total] = await Promise.all([
                reviewsCol.find({ guestId: userId }).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
                reviewsCol.countDocuments({ guestId: userId }),
            ]);

            // Attach property info from bookings (batched)
            const reviewBookingIds = (reviews as any[]).map((r: any) => parseId(r.bookingId)).filter(Boolean);
            const reviewBookingOids = reviewBookingIds.map((id: string) => toObjectId(id)).filter((id): id is ObjectId => id !== null);
            let reviewBookingMap = new Map<string, any>();
            if (reviewBookingOids.length > 0) {
                const reviewBookings = await bookingsCol
                    .find({ _id: { $in: reviewBookingOids } })
                    .toArray();
                reviewBookingMap = new Map(
                    (reviewBookings as any[]).map((b: any) => [toIdString(b._id), b]),
                );
            }
            const reviewsWithProperty = (reviews as any[]).map((r: any) => {
                const booking = reviewBookingMap.get(r.bookingId);
                return {
                    ...r,
                    propertyTitle: booking?.propertyTitle || "Unknown Property",
                    propertyImage: booking?.propertyImage || "",
                };
            });

            // Get pending reviews (completed bookings without review)
            const allBookings = await bookingsCol.find({
                guestId: userId,
                status: "completed",
            }).toArray();

            const reviewedBookingIds = new Set((reviews as any[]).map((r) => r.bookingId));
            const pendingBookings = (allBookings as any[])
                .filter((b) => !reviewedBookingIds.has(toIdString(b._id)))
                .map((b) => ({
                    _id: toIdString(b._id),
                    propertyTitle: b.propertyTitle,
                    propertyImage: b.propertyImage,
                    checkIn: b.checkIn,
                    checkOut: b.checkOut,
                }));

            res.status(200).json({
                success: true,
                data: {
                    reviews: reviewsWithProperty,
                    pending: pendingBookings,
                    pagination: {
                        total,
                        totalPages: Math.ceil(total / limit),
                        currentPage: page,
                        limit,
                    },
                },
            });
        } catch {
            res.status(500).json({ success: false, message: "Failed to fetch reviews." });
        }
    },
);

// GET host reviews
app.get(
    "/api/reviews/host-reviews",
    verifyToken,
    verifyHostOrAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const db = await getDb();
            const reviewsCol = db.collection("reviews");
            const propertiesCol = db.collection("properties");
            const usersCol = db.collection("user");
            const userId = toIdString(req.user!._id);

            const { page, limit, skip } = getPagination(req.query, 50, 10);

            const filter: Record<string, any> = { hostId: userId };
            if (req.query.propertyId) filter.propertyId = String(req.query.propertyId);
            if (req.query.rating) filter.rating = Number(req.query.rating);

            const [reviews, total] = await Promise.all([
                reviewsCol.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
                reviewsCol.countDocuments(filter),
            ]);

            // Enrich reviews (batched)
            const enrichedItems = reviews as any[];
            const guestMap = await findUsersMap(usersCol, enrichedItems.map((r: any) => r.guestId));
            const hostPropIds = enrichedItems
                .map((r: any) => parseId(r.propertyId))
                .filter((id): id is string => id !== null);
            const hostPropOids = hostPropIds.map((id: string) => toObjectId(id)).filter((id): id is ObjectId => id !== null);
            let hostPropMap = new Map<string, any>();
            if (hostPropOids.length > 0) {
                const hostProps = await propertiesCol
                    .find({ _id: { $in: hostPropOids } })
                    .toArray();
                hostPropMap = new Map(
                    (hostProps as any[]).map((p: any) => [toIdString(p._id), p]),
                );
            }
            const enriched = enrichedItems.map((r: any) => {
                const guest = guestMap.get(r.guestId);
                const prop = hostPropMap.get(r.propertyId);
                return {
                    ...r,
                    guest: guest ? { id: toIdString(guest._id), name: guest.name, image: guest.image } : null,
                    propertyTitle: prop?.title || "Unknown",
                };
            });

            // Rating breakdown
            const breakdown = await reviewsCol.aggregate([
                { $match: { hostId: userId } },
                { $group: { _id: "$rating", count: { $sum: 1 } } },
                { $sort: { _id: -1 } },
            ]).toArray();

            const ratingBreakdown: Record<number, number> = { 5: 0, 4: 0, 3: 0, 2: 0, 1: 0 };
            breakdown.forEach((b: any) => { ratingBreakdown[b._id] = b.count; });

            // Average
            const avgResult = await reviewsCol.aggregate([
                { $match: { hostId: userId } },
                { $group: { _id: null, avg: { $avg: "$rating" } } },
            ]).toArray();
            const averageRating = avgResult.length > 0
                ? Math.round(((avgResult[0] as any).avg || 0) * 10) / 10
                : 0;

            res.status(200).json({
                success: true,
                data: {
                    reviews: enriched,
                    stats: { averageRating, totalReviews: total, breakdown: ratingBreakdown },
                    pagination: {
                        total,
                        totalPages: Math.ceil(total / limit),
                        currentPage: page,
                        limit,
                    },
                },
            });
        } catch {
            res.status(500).json({ success: false, message: "Failed to fetch host reviews." });
        }
    },
);

// PUT edit review (guest)
app.put(
    "/api/reviews/:id",
    verifyToken,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const id = parseId(req.params.id);
            const objectId = toObjectId(id);
            if (!objectId) {
                res.status(400).json({ success: false, message: "Invalid review ID." });
                return;
            }

            const db = await getDb();
            const col = db.collection("reviews");
            const review = await col.findOne({ _id: objectId }) as any;

            if (!review) {
                res.status(404).json({ success: false, message: "Review not found." });
                return;
            }

            if (review.guestId !== toIdString(req.user!._id)) {
                res.status(403).json({ success: false, message: "You can only edit your own reviews." });
                return;
            }

            const updates: Record<string, any> = {};
            if (req.body.rating !== undefined) {
                const n = Number(req.body.rating);
                if (n < 1 || n > 5 || !Number.isInteger(n)) {
                    res.status(400).json({ success: false, message: "Rating must be 1-5." });
                    return;
                }
                updates.rating = n;
            }
            if (req.body.comment !== undefined) updates.comment = String(req.body.comment).trim();

            if (Object.keys(updates).length === 0) {
                res.status(400).json({ success: false, message: "Nothing to update." });
                return;
            }

            await col.updateOne({ _id: objectId }, { $set: updates });

            const propertiesCol = db.collection("properties");
            await updatePropertyRating(propertiesCol, review.propertyId);

            res.status(200).json({ success: true, message: "Review updated." });
        } catch {
            res.status(500).json({ success: false, message: "Failed to update review." });
        }
    },
);

// PUT reply to review (host)
app.put(
    "/api/reviews/:id/reply",
    verifyToken,
    verifyHostOrAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const id = parseId(req.params.id);
            const objectId = toObjectId(id);
            if (!objectId) {
                res.status(400).json({ success: false, message: "Invalid review ID." });
                return;
            }

            const { reply } = req.body;
            if (!reply) {
                res.status(400).json({ success: false, message: "Reply text is required." });
                return;
            }

            const db = await getDb();
            const col = db.collection("reviews");
            const review = await col.findOne({ _id: objectId }) as any;

            if (!review) {
                res.status(404).json({ success: false, message: "Review not found." });
                return;
            }

            const userId = toIdString(req.user!._id);
            if (review.hostId !== userId && req.user!.role !== "admin") {
                res.status(403).json({ success: false, message: "You are not the host of this property." });
                return;
            }

            await col.updateOne(
                { _id: objectId },
                { $set: { hostReply: String(reply).trim(), hostReplyDate: new Date() } },
            );

            res.status(200).json({ success: true, message: "Reply posted." });
        } catch {
            res.status(500).json({ success: false, message: "Failed to post reply." });
        }
    },
);

// DELETE review (guest or admin)
app.delete(
    "/api/reviews/:id",
    verifyToken,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const id = parseId(req.params.id);
            const objectId = toObjectId(id);
            if (!objectId) {
                res.status(400).json({ success: false, message: "Invalid review ID." });
                return;
            }

            const db = await getDb();
            const col = db.collection("reviews");
            const review = await col.findOne({ _id: objectId }) as any;

            if (!review) {
                res.status(404).json({ success: false, message: "Review not found." });
                return;
            }

            const userId = toIdString(req.user!._id);
            if (review.guestId !== userId && req.user!.role !== "admin") {
                res.status(403).json({ success: false, message: "Access denied." });
                return;
            }

            await col.deleteOne({ _id: objectId });

            const propertiesCol = db.collection("properties");
            await updatePropertyRating(propertiesCol, review.propertyId);

            res.status(200).json({ success: true, message: "Review deleted." });
        } catch {
            res.status(500).json({ success: false, message: "Failed to delete review." });
        }
    },
);

// PUT report review
app.put(
    "/api/reviews/:id/report",
    verifyToken,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const id = parseId(req.params.id);
            const objectId = toObjectId(id);
            if (!objectId) {
                res.status(400).json({ success: false, message: "Invalid review ID." });
                return;
            }

            const db = await getDb();
            const col = db.collection("reviews");
            const review = await col.findOne({ _id: objectId }) as any;

            if (!review) {
                res.status(404).json({ success: false, message: "Review not found." });
                return;
            }

            if (review.guestId === toIdString(req.user!._id)) {
                res.status(400).json({ success: false, message: "You cannot report your own review." });
                return;
            }

            await col.updateOne({ _id: objectId }, { $set: { isReported: true } });
            res.status(200).json({ success: true, message: "Review reported for moderation." });
        } catch {
            res.status(500).json({ success: false, message: "Failed to report review." });
        }
    },
);

// GET admin reviews
app.get(
    "/api/admin/reviews",
    verifyToken,
    verifyAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const db = await getDb();
            const col = db.collection("reviews");
            const { page, limit, skip } = getPagination(req.query, 100, 20);

            const filter: Record<string, any> = {};
            if (req.query.reported === "true") filter.isReported = true;
            if (req.query.rating) filter.rating = Number(req.query.rating);
            if (req.query.propertyId) filter.propertyId = String(req.query.propertyId);

            const [reviews, total] = await Promise.all([
                col.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
                col.countDocuments(filter),
            ]);

            res.status(200).json({
                success: true,
                data: {
                    reviews,
                    pagination: {
                        total,
                        totalPages: Math.ceil(total / limit),
                        currentPage: page,
                        limit,
                    },
                },
            });
        } catch {
            res.status(500).json({ success: false, message: "Failed to fetch reviews." });
        }
    },
);

// ============================================================
// MESSAGE ROUTES
// ============================================================

// POST start conversation
app.post(
    "/api/conversations",
    verifyToken,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const { participantId, bookingId, propertyId } = req.body;
            const userId = toIdString(req.user!._id);

            if (!participantId) {
                res.status(400).json({ success: false, message: "participantId is required." });
                return;
            }
            if (participantId === userId) {
                res.status(400).json({ success: false, message: "Cannot start conversation with yourself." });
                return;
            }

            const db = await getDb();
            const col = db.collection("conversations");

            // Check for existing conversation between these two participants
            const participants = [userId, participantId].sort();
            const existing = await col.findOne({ participants }) as any;
            if (existing) {
                res.status(200).json({ success: true, data: { ...existing, _id: toIdString(existing._id) } });
                return;
            }

            const doc: ConversationDoc = {
                participants,
                bookingId: bookingId || undefined,
                propertyId: propertyId || undefined,
                lastMessage: undefined,
                lastMessageAt: undefined,
                createdAt: new Date(),
                updatedAt: new Date(),
            };
            const result = await col.insertOne(doc);
            res.status(201).json({
                success: true,
                data: { ...doc, _id: toIdString(result.insertedId) },
            });
        } catch {
            res.status(500).json({ success: false, message: "Failed to start conversation." });
        }
    },
);

// GET conversations list
app.get(
    "/api/conversations",
    verifyToken,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const userId = toIdString(req.user!._id);
            const db = await getDb();
            const col = db.collection("conversations");
            const { page, limit, skip } = getPagination(req.query, 50, 20);

            const [conversations, total] = await Promise.all([
                col.find({ participants: userId })
                    .sort({ lastMessageAt: -1, updatedAt: -1 })
                    .skip(skip)
                    .limit(limit)
                    .toArray(),
                col.countDocuments({ participants: userId }),
            ]);

            // Enrich with the other participant's basic info
            const otherIds = (conversations as any[]).map((c: any) =>
                c.participants.find((p: string) => p !== userId),
            ).filter(Boolean);
            const localUsersCol = db.collection("user");
            const otherUserMap = await findUsersMap(localUsersCol, otherIds);

            const enriched = (conversations as any[]).map((c: any) => {
                const otherId = c.participants.find((p: string) => p !== userId);
                const otherUser = otherId ? otherUserMap.get(otherId) : null;
                return {
                    _id: toIdString(c._id),
                    participants: c.participants,
                    bookingId: c.bookingId,
                    propertyId: c.propertyId,
                    lastMessage: c.lastMessage,
                    lastMessageAt: c.lastMessageAt,
                    createdAt: c.createdAt,
                    updatedAt: c.updatedAt,
                    otherUser: otherUser
                        ? { id: toIdString(otherUser._id), name: otherUser.name, image: otherUser.image }
                        : null,
                };
            });

            res.status(200).json({
                success: true,
                data: enriched,
                pagination: { total, totalPages: Math.ceil(total / limit), currentPage: page, limit },
            });
        } catch {
            res.status(500).json({ success: false, message: "Failed to fetch conversations." });
        }
    },
);

// POST send message
app.post(
    "/api/messages",
    verifyToken,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const { conversationId, content } = req.body;
            const userId = toIdString(req.user!._id);

            if (!conversationId || !content) {
                res.status(400).json({ success: false, message: "conversationId and content are required." });
                return;
            }

            const db = await getDb();
            const convCol = db.collection("conversations");
            const msgCol = db.collection("messages");

            const convOid = toObjectId(parseId(conversationId));
            if (!convOid) {
                res.status(400).json({ success: false, message: "Invalid conversation ID." });
                return;
            }

            const conversation = await convCol.findOne({ _id: convOid }) as any;
            if (!conversation) {
                res.status(404).json({ success: false, message: "Conversation not found." });
                return;
            }
            if (!conversation.participants.includes(userId)) {
                res.status(403).json({ success: false, message: "You are not a participant in this conversation." });
                return;
            }

            const msgDoc: MessageDoc = {
                conversationId,
                senderId: userId,
                content,
                isRead: false,
                createdAt: new Date(),
            };
            const result = await msgCol.insertOne(msgDoc);

            await convCol.updateOne(
                { _id: convOid },
                { $set: { lastMessage: content, lastMessageAt: new Date(), updatedAt: new Date() } },
            );

            res.status(201).json({ success: true, data: { ...msgDoc, _id: toIdString(result.insertedId) } });
        } catch {
            res.status(500).json({ success: false, message: "Failed to send message." });
        }
    },
);

// GET unread count (must be before :conversationId)
app.get(
    "/api/messages/unread-count",
    verifyToken,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const userId = toIdString(req.user!._id);
            const db = await getDb();
            const convCol = db.collection("conversations");
            const msgCol = db.collection("messages");

            const conversations = await convCol.find({ participants: userId }).toArray();
            const convIds = (conversations as any[]).map((c: any) => toIdString(c._id));

            if (convIds.length === 0) {
                res.status(200).json({ success: true, data: { unreadCount: 0 } });
                return;
            }

            const unreadCount = await msgCol.countDocuments({
                conversationId: { $in: convIds },
                senderId: { $ne: userId },
                isRead: false,
            });

            res.status(200).json({ success: true, data: { unreadCount } });
        } catch {
            res.status(500).json({ success: false, message: "Failed to get unread count." });
        }
    },
);

// GET messages for a conversation (paginated)
app.get(
    "/api/messages/:conversationId",
    verifyToken,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const { conversationId } = req.params;
            const userId = toIdString(req.user!._id);
            const db = await getDb();
            const convCol = db.collection("conversations");
            const msgCol = db.collection("messages");
            const { page, limit, skip } = getPagination(req.query, 50, 50);

            // Verify participant
            const convOid = toObjectId(parseId(conversationId));
            if (!convOid) {
                res.status(400).json({ success: false, message: "Invalid conversation ID." });
                return;
            }
            const conversation = await convCol.findOne({ _id: convOid, participants: userId }) as any;
            if (!conversation) {
                res.status(404).json({ success: false, message: "Conversation not found." });
                return;
            }

            const [messages, total] = await Promise.all([
                msgCol.find({ conversationId })
                    .sort({ createdAt: 1 })
                    .skip(skip)
                    .limit(limit)
                    .toArray(),
                msgCol.countDocuments({ conversationId }),
            ]);

            res.status(200).json({
                success: true,
                data: (messages as any[]).map((m: any) => ({ ...m, _id: toIdString(m._id) })),
                pagination: { total, totalPages: Math.ceil(total / limit), currentPage: page, limit },
            });
        } catch {
            res.status(500).json({ success: false, message: "Failed to fetch messages." });
        }
    },
);

// PUT mark single message as read
app.put(
    "/api/messages/:id/read",
    verifyToken,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const messageId = req.params.id;
            const userId = toIdString(req.user!._id);
            const db = await getDb();
            const msgCol = db.collection("messages");

            const msgOid = toObjectId(parseId(messageId));
            if (!msgOid) {
                res.status(400).json({ success: false, message: "Invalid message ID." });
                return;
            }

            const message = await msgCol.findOne({ _id: msgOid }) as any;
            if (!message) {
                res.status(404).json({ success: false, message: "Message not found." });
                return;
            }
            if (message.senderId === userId) {
                res.status(400).json({ success: false, message: "Cannot mark your own message as read." });
                return;
            }

            // Verify the user is a participant in the conversation
            const db2 = await getDb();
            const convCol = db2.collection("conversations");
            const convOid = toObjectId(parseId(message.conversationId));
            const isParticipant = convOid
                ? await convCol.findOne({ _id: convOid, participants: userId })
                : null;
            if (!isParticipant) {
                res.status(403).json({ success: false, message: "Not a participant." });
                return;
            }

            await msgCol.updateOne({ _id: msgOid }, { $set: { isRead: true } });
            res.status(200).json({ success: true, message: "Message marked as read." });
        } catch {
            res.status(500).json({ success: false, message: "Failed to mark message as read." });
        }
    },
);

// PUT mark all messages in conversation as read
app.put(
    "/api/conversations/:id/read-all",
    verifyToken,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const conversationId = req.params.id;
            const userId = toIdString(req.user!._id);
            const db = await getDb();
            const convCol = db.collection("conversations");
            const msgCol = db.collection("messages");

            const convOid = toObjectId(parseId(conversationId));
            if (!convOid) {
                res.status(400).json({ success: false, message: "Invalid conversation ID." });
                return;
            }

            const isParticipant = await convCol.findOne({ _id: convOid, participants: userId }) as any;
            if (!isParticipant) {
                res.status(404).json({ success: false, message: "Conversation not found." });
                return;
            }

            await msgCol.updateMany(
                { conversationId, senderId: { $ne: userId }, isRead: false },
                { $set: { isRead: true } },
            );

            res.status(200).json({ success: true, message: "All messages marked as read." });
        } catch {
            res.status(500).json({ success: false, message: "Failed to mark messages as read." });
        }
    },
);

// ============================================================
// GLOBAL ERROR HANDLER
// ============================================================

app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
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

export default app;
