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
import fs from "fs";
import path from "path";
import Stripe from "stripe";
import Groq from "groq-sdk";
import { registerAiRoutes } from "./ai";

dotenv.config();

const app = express();

const allowedOrigins = [
    process.env.FRONTEND_URL,
    "http://localhost:3000",
    "http://localhost:3001",
    "https://aura-space-ochre.vercel.app",
].filter(Boolean) as string[];

app.use(
    helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                connectSrc: ["'self'", ...allowedOrigins],
                imgSrc: ["'self'", "data:", "https://res.cloudinary.com", "https://images.unsplash.com", "https://i.ibb.co"],
                scriptSrc: ["'self'"],
                styleSrc: ["'self'", "'unsafe-inline'"],
                fontSrc: ["'self'"],
                objectSrc: ["'none'"],
                frameSrc: ["'none'"],
            },
        },
    }),
);

app.use(
    cors({
        origin: (origin, callback) => {
            if (!origin || allowedOrigins.includes(origin) || origin.startsWith("http://localhost:")) {
                callback(null, true);
            } else {
                callback(new Error("Not allowed by CORS"));
            }
        },
        credentials: true,
        methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization"],
    }),
);

// Stripe webhook MUST use raw body — register BEFORE express.json()
app.post("/api/webhooks/stripe", express.raw({ type: "application/json" }), stripeWebhookHandler);

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// Local file storage for image uploads (legacy — kept for static serving)
const UPLOAD_DIR = path.join(__dirname, "..", "uploads");
if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}
app.use("/uploads", express.static(UPLOAD_DIR));

const uri: string = process.env.MONGODB_URI || "";
const dbName: string = process.env.DB_NAME || "StayEase";
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:3000";

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
        const client = await getClientPromise();
        const bookingsCol = db.collection("bookings");
        const transactionsCol = db.collection("transactions");

        switch (event.type) {
            case "checkout.session.completed": {
                const stripeSession = event.data.object as Stripe.Checkout.Session;
                const bookingId = stripeSession.metadata?.bookingId;

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

                const idempotencyKey = `stripe_${stripeSession.id}`;
                await confirmBookingAndCreateTransaction(
                    bookingsCol, transactionsCol, client,
                    bookingId, booking, idempotencyKey,
                    stripeSession.currency || process.env.STRIPE_CURRENCY || "usd",
                );

                console.log(`✅ Booking ${bookingId} confirmed via Stripe webhook (session: ${stripeSession.id})`);
                break;
            }

            case "payment_intent.succeeded": {
                const paymentIntent = event.data.object as Stripe.PaymentIntent;
                const bookingId = paymentIntent.metadata?.bookingId;

                if (!bookingId) {
                    console.warn("Webhook: No bookingId in payment_intent metadata");
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

                const idempotencyKey = `pi_${paymentIntent.id}`;
                await confirmBookingAndCreateTransaction(
                    bookingsCol, transactionsCol, client,
                    bookingId, booking, idempotencyKey,
                    paymentIntent.currency || process.env.STRIPE_CURRENCY || "usd",
                );

                console.log(`✅ Booking ${bookingId} confirmed via PaymentIntent (pi: ${paymentIntent.id})`);
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
        res.status(500).json({ received: false, message: "Internal server error" });
    }
}

async function confirmBookingAndCreateTransaction(
    bookingsCol: any,
    transactionsCol: any,
    client: any,
    bookingId: string,
    booking: any,
    idempotencyKey: string,
    currency: string,
): Promise<void> {
    const objectId = toObjectId(parseId(bookingId));
    if (!objectId) return;

    const existingTxn = await transactionsCol.findOne({ transactionId: idempotencyKey });
    if (existingTxn) return;

    const mongoSession = client.startSession();
    try {
        await mongoSession.withTransaction(async () => {
            await bookingsCol.updateOne(
                { _id: objectId },
                { $set: { status: "confirmed", updatedAt: new Date() } },
                { session: mongoSession },
            );

            await transactionsCol.insertOne({
                userId: booking.guestId,
                bookingId,
                type: "payment" as const,
                amount: booking.totalAmount,
                currency: currency.toUpperCase(),
                method: "card" as const,
                status: "success" as const,
                transactionId: idempotencyKey,
                description: `Payment for booking at ${booking.propertyTitle}`,
                createdAt: new Date(),
            }, { session: mongoSession });
        });
    } finally {
        await mongoSession.endSession();
    }
}

// ============================================================
// MULTER CONFIG - memory storage
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
    state?: string;
    country: string;
    zipCode?: string;
    coordinates?: { lat: number; lng: number };
}

interface PropertyPrice {
    perNight: number;
    currency?: string;
    weeklyDiscount?: number;
    monthlyDiscount?: number;
    cleaningFee?: number;
    serviceFee?: number;
}

interface AvailabilitySettings {
    minStay: number;
    maxStay: number;
    advanceNotice: number;
    availableFrom: string;
    availableTo: string;
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

type PropertyCategory = "hotel" | "apartment" | "villa" | "suite" | "cabin" | "event" | "event-space" | "estate" | "resort";
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
    | "fire-extinguisher"
    | "hot-water"
    | "refrigerator"
    | "lock"
    | "pet-friendly"
    | "baby-friendly"
    | "wheelchair-accessible";

interface PropertyDoc {
    _id?: ObjectId;
    hostId: string;
    title: string;
    description: string;
    category: PropertyCategory;
    placeType?: string;
    location: PropertyLocation;
    price: PropertyPrice;
    details: PropertyDetails;
    amenities: AmenityType[];
    images: string[];
    houseRules: HouseRules;
    availability: AvailabilityDate[];
    availabilitySettings?: AvailabilitySettings;
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

type BookingStatus = "pending" | "confirmed" | "cancelled" | "completed" | "checked-in";

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
    placeType?: string;
    location: PropertyLocation;
    price: PropertyPrice;
    details: PropertyDetails;
    amenities: AmenityType[];
    images: string[];
    houseRules: HouseRules;
    availabilitySettings?: AvailabilitySettings;
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

// AI conversation indexes
async function ensureAIIndexes() {
    try {
        const db = await getDb();
        const aiCol = db.collection("ai_conversations");
        await aiCol.createIndex({ userId: 1, updatedAt: -1 });
        await aiCol.createIndex({ userId: 1 });
        console.log("✅ AI conversation indexes created");
    } catch (error) {
        console.warn("⚠️ AI index creation warning:", error);
    }
}

ensureAIIndexes().catch((err) =>
    console.error("❌ Failed to create AI indexes:", err),
);

// ============================================================
// HELPERS
// ============================================================

let JWKS: ReturnType<typeof createRemoteJWKSet> | null = null;
let JWKSGeneratedAt = 0;
const JWKS_TTL_MS = 60 * 60 * 1000; // 1 hour

function getJWKS() {
    const now = Date.now();
    if (!JWKS || (now - JWKSGeneratedAt) > JWKS_TTL_MS) {
        JWKS = createRemoteJWKSet(new URL(`${FRONTEND_URL}/api/auth/jwks`));
        JWKSGeneratedAt = now;
    }
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

function buildPaginationResponse(total: number, page: number, limit: number) {
    const totalPages = Math.ceil(total / limit);
    return {
        total,
        totalPages,
        currentPage: page,
        limit,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1,
    };
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
// AI
// ============================================================

let _groq: Groq | null = null;

function getGroq(): Groq {
    if (!_groq) {
        const key = process.env.GROQ_API_KEY;
        if (key) {
            _groq = new Groq({ apiKey: key });
        }
    }
    return _groq!;
}

const AI_MODEL = "llama-3.3-70b-versatile";
const AI_MODEL_FALLBACKS = ["llama-3.1-8b-instant", "gemma2-9b-it", "llama-3.1-8b-versatile"];

interface AIConversationDoc {
    _id?: ObjectId;
    userId: string;
    messages: Array<{
        role: "user" | "assistant";
        content: string;
        createdAt: Date;
    }>;
    createdAt: Date;
    updatedAt: Date;
}

interface AIAuthReq extends Request {
    user?: {
        _id: ObjectId;
        name: string;
        email: string;
        role: string;
        image?: string | null;
    };
}

function generateSuggestions(userMessage: string, aiReply: string): string[] {
    const lower = userMessage.toLowerCase();
    const suggestions: string[] = [];

    if (lower.includes("property") || lower.includes("find") || lower.includes("search") || lower.includes("apartment") || lower.includes("villa")) {
        suggestions.push("Show cheaper options");
        suggestions.push("Find highly rated properties");
        suggestions.push("Compare similar properties");
    }

    if (lower.includes("book") || lower.includes("cancel") || lower.includes("refund")) {
        suggestions.push("How to manage bookings");
        suggestions.push("Contact property host");
        suggestions.push("View booking policies");
    }

    if (lower.includes("host") || lower.includes("list") || lower.includes("add property")) {
        suggestions.push("How to become a host");
        suggestions.push("Add a new property");
        suggestions.push("Manage your listings");
    }

    if (suggestions.length === 0) {
        suggestions.push("Find properties in Dhaka");
        suggestions.push("Search budget-friendly stays");
        suggestions.push("How to book a property");
    }

    return suggestions.slice(0, 3);
}

// ============================================================
// BLOG
// ============================================================

interface BlogDoc {
    _id?: ObjectId;
    title: string;
    slug: string;
    content: string;
    excerpt: string;
    coverImage: string | null;
    tags: string[];
    authorId: string;
    authorName: string;
    authorImage: string | null;
    status: "published" | "draft";
    isFeatured: boolean;
    viewCount: number;
    readingTime: number;
    createdAt: Date;
    updatedAt: Date;
}

function stripHtml(html: string): string {
    return html.replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim();
}

function calculateReadingTime(content: string): number {
    const words = stripHtml(content).split(/\s+/).length;
    return Math.max(1, Math.ceil(words / 200));
}

function generateSlug(title: string): string {
    return title
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-+|-+$/g, "")
        .slice(0, 80);
}

function buildBlogResponse(blog: BlogDoc) {
    return {
        id: blog._id?.toString() || "",
        title: blog.title,
        slug: blog.slug,
        content: blog.content,
        excerpt: blog.excerpt,
        coverImage: blog.coverImage,
        tags: blog.tags,
        authorId: blog.authorId,
        authorName: blog.authorName,
        authorImage: blog.authorImage,
        status: blog.status,
        isFeatured: blog.isFeatured,
        viewCount: blog.viewCount,
        readingTime: blog.readingTime,
        createdAt: blog.createdAt,
        updatedAt: blog.updatedAt,
    };
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
    "suite",
    "cabin",
    "event",
    "event-space",
    "estate",
    "resort",
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
    "hot-water",
    "refrigerator",
    "lock",
    "pet-friendly",
    "baby-friendly",
    "wheelchair-accessible",
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
        placeType,
        location,
        price,
        details,
        amenities,
        images,
        houseRules,
        availabilitySettings,
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
        ...(placeType !== undefined && {
            placeType: String(placeType).trim(),
        }),
        location: {
            address: String(location.address).trim(),
            city: String(location.city).trim(),
            ...(location.state !== undefined && {
                state: String(location.state).trim(),
            }),
            country: String(location.country).trim(),
            ...(location.zipCode !== undefined && {
                zipCode: String(location.zipCode).trim(),
            }),
            ...(location.coordinates && {
                coordinates: {
                    lat: Number(location.coordinates.lat),
                    lng: Number(location.coordinates.lng),
                },
            }),
        },
        price: {
            perNight,
            ...(price.currency !== undefined && {
                currency: String(price.currency).trim(),
            }),
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
        ...(availabilitySettings !== undefined && {
            availabilitySettings: {
                minStay: Number(availabilitySettings.minStay) || 1,
                maxStay: Number(availabilitySettings.maxStay) || 30,
                advanceNotice: Number(availabilitySettings.advanceNotice) || 1,
                availableFrom: String(availabilitySettings.availableFrom || ""),
                availableTo: String(availabilitySettings.availableTo || ""),
            },
        }),
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
        placeType: p.placeType || null,
        location: p.location,
        price: p.price,
        details: p.details,
        amenities: p.amenities || [],
        images: p.images || [],
        houseRules: p.houseRules,
        availability: p.availability || [],
        availabilitySettings: p.availabilitySettings || null,
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
        if (error?.code === "ERR_JWKS_NO_MATCHING_KEY") {
            res.status(401).json({
                success: false,
                message: "Authentication service unavailable (key mismatch).",
            });
            return;
        }
        if (error?.code === "ERR_JWKS_MULTIPLE_MATCHING_KEYS") {
            res.status(401).json({
                success: false,
                message: "Authentication service error (multiple keys).",
            });
            return;
        }
        if (
            error?.message?.includes("fetch") ||
            error?.message?.includes("ECONNREFUSED") ||
            error?.message?.includes("ENOTFOUND")
        ) {
            console.error("[verifyToken] JWKS fetch failed:", error.message);
            res.status(503).json({
                success: false,
                message: "Authentication service unreachable. Try again later.",
            });
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
        message: "🏡 AuraSpace Server is Running!",
        version: "1.0.0",
        env: {
            hasMongoUri: !!process.env.MONGODB_URI,
            hasDbName: !!process.env.DB_NAME,
            hasFrontendUrl: !!process.env.FRONTEND_URL,
            storage: "local",
            uploadsDir: UPLOAD_DIR,
            nodeEnv: process.env.NODE_ENV || "not set",
        },
    });
});

app.get("/api/health", async (_req: Request, res: Response) => {
    try {
        const db = await getDb();
        await db.command({ ping: 1 });

        res.status(200).json({
            success: true,
            message: "All systems operational",
            services: {
                mongodb: { status: "connected", database: dbName },
                storage: {
                    type: "local",
                    path: UPLOAD_DIR,
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

// POST upload images → imgbb
app.post(
    "/api/properties/upload-images",
    verifyToken,
    verifyHostOrAdmin,
    upload.array("images", MAX_FILES),
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const files = (req.files as Express.Multer.File[]) || [];

            if (files.length === 0) {
                res.status(400).json({
                    success: false,
                    message: "No files uploaded.",
                });
                return;
            }

            const uploadedUrls: string[] = [];
            const errors: string[] = [];

            await Promise.all(
                files.map(async (file) => {
                    try {
                        const key = process.env.IMGBB_API_KEY;
                        let url: string;
                        if (key) {
                            try {
                                url = await uploadToImgbb(file.buffer, file.originalname);
                            } catch (err: any) {
                                console.warn("[Properties] imgbb failed, local fallback:", err.message);
                                url = await saveFileLocally(file.buffer, file.originalname);
                            }
                        } else {
                            url = await saveFileLocally(file.buffer, file.originalname);
                        }
                        uploadedUrls.push(url);
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

// DELETE image from imgbb
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

            // imgbb images can't be deleted without the delete_url from upload response
            // The delete_url is returned during upload but not stored server-side
            res.status(200).json({
                success: true,
                message: "Image removed from property (imgbb image will remain hosted).",
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

// GET popular destinations (city aggregation with first property image)
app.get(
    "/api/properties/cities",
    async (_req: Request, res: Response): Promise<void> => {
        try {
            const db = await getDb();
            const col = db.collection("properties");

            const pipeline = [
                { $match: { status: "active", "location.city": { $exists: true, $ne: "" } } },
                {
                    $group: {
                        _id: { $trim: { input: { $toLower: "$location.city" } } },
                        country: { $first: "$location.country" },
                        count: { $sum: 1 },
                        image: {
                            $first: {
                                $cond: {
                                    if: { $gt: [{ $size: { $ifNull: ["$images", []] } }, 0] },
                                    then: { $arrayElemAt: ["$images", 0] },
                                    else: null,
                                },
                            },
                        },
                    },
                },
                { $sort: { count: -1 } },
                { $limit: 8 },
                {
                    $project: {
                        _id: 0,
                        city: { $concat: [{ $toUpper: { $substrCP: ["$_id", 0, 1] } }, { $substrCP: ["$_id", 1, { $subtract: [{ $strLenCP: "$_id" }, 1] }] }] },
                        country: 1,
                        count: 1,
                        image: 1,
                    },
                },
            ];

            const cities = await col.aggregate(pipeline).toArray();

            res.status(200).json({ success: true, data: cities });
        } catch (error) {
            console.error("Cities aggregation error:", error);
            res.status(500).json({ success: false, message: "Failed to fetch destinations." });
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
            const client = await getClientPromise();
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

            // Check for existing pending booking by same guest, property, dates — idempotent
            const existingBooking = await bookingsCol.findOne({
                guestId: toIdString(user._id),
                propertyId,
                checkIn: checkInDate,
                checkOut: checkOutDate,
                status: "pending",
            }) as any;
            if (existingBooking) {
                res.status(200).json({
                    success: true,
                    message: "Existing pending booking found.",
                    data: {
                        booking: existingBooking,
                    },
                });
                return;
            }

            // Atomic transaction — prevents double-booking race condition with OTHER guests
            const session = client.startSession();
            let result;
            try {
                await session.withTransaction(async () => {
                    const hasOverlap = await checkDateOverlap(
                        bookingsCol, propertyId, checkInDate, checkOutDate
                    );
                    if (hasOverlap) {
                        throw new Error("OVERLAP_CONFLICT");
                    }

                    result = await bookingsCol.insertOne(booking as BookingDoc, { session });
                });
            } finally {
                await session.endSession();
            }

            res.status(201).json({
                success: true,
                message: "Booking created. Proceed to payment.",
                data: {
                    booking: { ...booking, _id: result!.insertedId },
                },
            });
        } catch (error: any) {
            if (error?.message === "OVERLAP_CONFLICT") {
                res.status(409).json({
                    success: false,
                    message: "This property is already booked for the selected dates. If you already have a pending booking, please check your bookings page.",
                });
                return;
            }
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
                (() => {
                    const propId = toObjectId(parseId(booking.propertyId));
                    return propId ? propertiesCol.findOne({ _id: propId }) : Promise.resolve(null);
                })(),
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
// PAYMENT INTENT ROUTE (embedded Elements flow)
// ============================================================

// POST create Checkout Session for Stripe Embedded Checkout
app.post(
    "/api/payments/create-checkout-session",
    verifyToken,
    async (req: AuthRequest, res: Response): Promise<void> => {
        if (!stripe) {
            res.status(503).json({ success: false, message: "Stripe not configured." });
            return;
        }

        try {
            const user = req.user!;
            const { bookingId } = req.body;

            if (!bookingId) {
                res.status(400).json({ success: false, message: "bookingId is required." });
                return;
            }

            const db = await getDb();
            const bookingsCol = db.collection("bookings");
            const objectId = toObjectId(parseId(bookingId));

            if (!objectId) {
                res.status(400).json({ success: false, message: "Invalid booking ID." });
                return;
            }

            const booking = await bookingsCol.findOne({ _id: objectId }) as any;
            if (!booking) {
                res.status(404).json({ success: false, message: "Booking not found." });
                return;
            }

            const userId = toIdString(user._id);
            if (booking.guestId !== userId) {
                res.status(403).json({ success: false, message: "This booking does not belong to you." });
                return;
            }

            if (booking.status !== "pending") {
                res.status(400).json({ success: false, message: "Only pending bookings can be paid." });
                return;
            }

            const currency = (process.env.STRIPE_CURRENCY || "usd").toLowerCase();

            const session = await stripe.checkout.sessions.create({
                ui_mode: "embedded_page",
                line_items: [
                    {
                        price_data: {
                            currency,
                            product_data: {
                                name: booking.propertyTitle || "AuraSpace Booking",
                                images: booking.propertyImage ? [booking.propertyImage] : [],
                            },
                            unit_amount: Math.round(booking.totalAmount * 100),
                        },
                        quantity: 1,
                    },
                ],
                mode: "payment",
                return_url: `${FRONTEND_URL}/checkout/return?session_id={CHECKOUT_SESSION_ID}`,
                metadata: {
                    bookingId,
                    propertyId: booking.propertyId,
                    guestId: userId,
                },
            });

            if (!session.client_secret) {
                res.status(500).json({ success: false, message: "Failed to get client secret from Stripe." });
                return;
            }

            res.status(200).json({
                success: true,
                data: {
                    clientSecret: session.client_secret,
                },
            });
        } catch (error: any) {
            console.error("Create checkout session error:", error);
            res.status(500).json({ success: false, message: "Failed to create checkout session." });
        }
    },
);

// GET retrieve Checkout Session status
app.get(
    "/api/payments/session-status",
    async (req: Request, res: Response): Promise<void> => {
        if (!stripe) {
            res.status(503).json({ success: false, message: "Stripe not configured." });
            return;
        }

        try {
            const { session_id } = req.query;

            if (!session_id || typeof session_id !== "string") {
                res.status(400).json({ success: false, message: "session_id is required." });
                return;
            }

            const session = await stripe.checkout.sessions.retrieve(session_id, {
                expand: ["line_items", "payment_intent"],
            });

            res.status(200).json({
                success: true,
                data: {
                    status: session.status,
                    customer_email: session.customer_details?.email || null,
                    payment_status: session.payment_status,
                    amount_total: session.amount_total,
                    currency: session.currency,
                    bookingId: session.metadata?.bookingId || null,
                },
            });
        } catch (error: any) {
            console.error("Session status error:", error);
            res.status(500).json({ success: false, message: "Failed to retrieve session status." });
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

            // Mask sensitive fields
            const accNum = method.accountNumber || "";
            const maskedAccount = accNum.length > 4
                ? "****" + accNum.slice(-4)
                : "****";
            const rtNum = method.routingNumber || "";
            const maskedRouting = rtNum.length > 4
                ? "****" + rtNum.slice(-4)
                : "****";
            const swCode = method.swiftCode || "";
            const maskedSwift = swCode.length > 4
                ? "****" + swCode.slice(-4)
                : "****";

            res.status(200).json({
                success: true,
                data: {
                    id: toIdString(method._id),
                    accountHolder: method.accountHolder,
                    bankName: method.bankName,
                    accountNumber: maskedAccount,
                    routingNumber: maskedRouting,
                    swiftCode: maskedSwift,
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

// GET transaction stats (MUST be before /:id — Express matches in order)
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

            const totalSpendArr = await col.aggregate([
                { $match: { ...matchFilter, type: "payment", status: "success" } },
                { $group: { _id: null, total: { $sum: "$amount" } } },
            ]).toArray();
            const totalSpend = (totalSpendArr[0] as any)?.total || 0;

            const totalEarnArr = await col.aggregate([
                { $match: { ...matchFilter, type: "payout", status: "success" } },
                { $group: { _id: null, total: { $sum: "$amount" } } },
            ]).toArray();
            const totalEarned = (totalEarnArr[0] as any)?.total || 0;

            // Monthly aggregation for current month
            const now = new Date();
            const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
            const monthEnd = new Date(now.getFullYear(), now.getMonth() + 1, 1);
            const thisMonthArr = await col.aggregate([
                { $match: { ...matchFilter, type: "payment", status: "success", createdAt: { $gte: monthStart, $lt: monthEnd } } },
                { $group: { _id: null, total: { $sum: "$amount" } } },
            ]).toArray();
            const thisMonthSpend = (thisMonthArr[0] as any)?.total || 0;

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

            const platformFeePercent = Math.min(100, Math.max(0, Number(process.env.PLATFORM_FEE_PERCENT) || 10));

            res.status(200).json({
                success: true,
                data: {
                    totalSpend: Math.round(totalSpend * 100) / 100,
                    totalEarned: Math.round(totalEarned * 100) / 100,
                    thisMonthSpend: Math.round(thisMonthSpend * 100) / 100,
                    platformFeePercent,
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

// GET single transaction (must be after specific routes)
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
            if (req.query.search) {
                const s = String(req.query.search);
                filter.$or = [
                    { transactionId: { $regex: s, $options: "i" } },
                    { userId: { $regex: s, $options: "i" } },
                    { description: { $regex: s, $options: "i" } },
                ];
            }

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

// GET /api/admin/revenue — dedicated revenue analytics endpoint
app.get(
    "/api/admin/revenue",
    verifyToken,
    verifyAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const db = await getDb();
            const transactionsCol = db.collection("transactions");
            const usersCol = db.collection("user");
            const propertiesCol = db.collection("properties");

            const now = new Date();
            const startOfYear = new Date(now.getFullYear(), 0, 1);
            const currentMonth = now.getMonth();
            const currentYear = now.getFullYear();

            const [
                monthlyRevenue,
                commissionTotalResult,
                pendingPayoutsResult,
                allSuccessPayments,
                allCommissions,
            ] = await Promise.all([
                transactionsCol.aggregate([
                    { $match: { type: "payment", status: "success", createdAt: { $gte: startOfYear } } },
                    { $group: { _id: { $month: "$createdAt" }, revenue: { $sum: "$amount" }, count: { $sum: 1 } } },
                    { $sort: { _id: 1 } },
                ]).toArray(),
                transactionsCol.aggregate([
                    { $match: { type: "commission", status: "success" } },
                    { $group: { _id: null, total: { $sum: "$amount" } } },
                ]).toArray(),
                transactionsCol.aggregate([
                    { $match: { type: "payout", status: "pending" } },
                    { $group: { _id: null, total: { $sum: "$amount" } } },
                ]).toArray(),
                transactionsCol.aggregate([
                    { $match: { type: "payment", status: "success" } },
                    { $sort: { amount: -1 } },
                    { $limit: 50 },
                ]).toArray(),
                transactionsCol.aggregate([
                    { $match: { type: "commission", status: "success" } },
                    { $sort: { amount: -1 } },
                    { $limit: 50 },
                ]).toArray(),
            ]);

            const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
            const revenueByMonth = Array.from({ length: 12 }, (_, i) => ({
                month: MONTHS[i],
                revenue: 0,
                bookings: 0,
            }));
            monthlyRevenue.forEach((r: any) => {
                if (r._id >= 1 && r._id <= 12) {
                    revenueByMonth[r._id - 1].revenue = Math.round(r.revenue * 100) / 100;
                    revenueByMonth[r._id - 1].bookings = r.count;
                }
            });

            const thisMonthRevenue = revenueByMonth[currentMonth].revenue;
            const prevMonthRevenue = currentMonth > 0 ? revenueByMonth[currentMonth - 1].revenue : 0;
            const revenueGrowth = prevMonthRevenue > 0
                ? Math.round(((thisMonthRevenue - prevMonthRevenue) / prevMonthRevenue) * 100)
                : thisMonthRevenue > 0 ? 100 : 0;

            // Build top hosts from payments
            const userIds = [...new Set(allSuccessPayments.map((p: any) => p.userId).filter(Boolean))];
            const userIdsObj = userIds.map((id: string) => toObjectId(id)).filter((id): id is ObjectId => id !== null);
            const userDocs = userIdsObj.length > 0 ? await usersCol.find({ _id: { $in: userIdsObj } }).toArray() : [];
            const userMap = new Map(userDocs.map((u: any) => [toIdString(u._id), u.name || u.email || "Unknown"]));

            const hostEarnings: Record<string, { userId: string; name: string; earnings: number; count: number }> = {};
            allSuccessPayments.forEach((p: any) => {
                if (p.userId) {
                    if (!hostEarnings[p.userId]) {
                        hostEarnings[p.userId] = { userId: p.userId, name: userMap.get(p.userId) || "Unknown", earnings: 0, count: 0 };
                    }
                    hostEarnings[p.userId].earnings += p.amount;
                    hostEarnings[p.userId].count++;
                }
            });
            const topHosts = Object.values(hostEarnings)
                .sort((a, b) => b.earnings - a.earnings)
                .slice(0, 5)
                .map((h) => ({ ...h, earnings: Math.round(h.earnings * 100) / 100 }));

            // Build top properties from commission records with description
            const propEarnings: Record<string, { name: string; earnings: number }> = {};
            allCommissions.forEach((c: any) => {
                if (c.description) {
                    const name = c.description;
                    if (!propEarnings[name]) propEarnings[name] = { name, earnings: 0 };
                    propEarnings[name].earnings += c.amount;
                }
            });
            const topProperties = Object.values(propEarnings)
                .sort((a, b) => b.earnings - a.earnings)
                .slice(0, 5)
                .map((p) => ({ ...p, earnings: Math.round(p.earnings * 100) / 100 }));

            // Revenue breakdown by type
            const paymentTotal = allSuccessPayments.reduce((s: number, p: any) => s + p.amount, 0);
            const commissionTotal = commissionTotalResult.length > 0 ? commissionTotalResult[0].total : 0;
            const pendingPayouts = pendingPayoutsResult.length > 0 ? pendingPayoutsResult[0].total : 0;
            const netRevenue = paymentTotal - pendingPayouts;

            res.status(200).json({
                success: true,
                data: {
                    summary: {
                        totalRevenue: Math.round(paymentTotal * 100) / 100,
                        commissionEarned: Math.round(commissionTotal * 100) / 100,
                        pendingPayouts: Math.round(pendingPayouts * 100) / 100,
                        netRevenue: Math.round(netRevenue * 100) / 100,
                        thisMonthRevenue: Math.round(thisMonthRevenue * 100) / 100,
                        revenueGrowth,
                    },
                    revenueByMonth,
                    topHosts,
                    topProperties,
                },
            });
        } catch (err) {
            console.error("Admin revenue error:", err);
            res.status(500).json({ success: false, message: "Failed to fetch revenue data." });
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

            const filter: Record<string, any> = { userId, listType: { $ne: "folder" } };
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

// POST create a new list (folder) for the user
app.post(
    "/api/wishlist/lists",
    verifyToken,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const { listName } = req.body;
            if (!listName || !listName.trim()) {
                res.status(400).json({ success: false, message: "listName is required." });
                return;
            }
            const db = await getDb();
            const col = db.collection("wishlist");
            const userId = toIdString(req.user!._id);
            const trimmed = listName.trim();

            // Ensure listName doesn't already exist for this user
            const existing = await col.findOne({ userId, listName: trimmed, listType: "folder" });
            if (!existing) {
                await col.insertOne({
                    userId,
                    listName: trimmed,
                    listType: "folder",
                    createdAt: new Date(),
                });
            }

            res.status(201).json({ success: true, message: "List created.", data: { listName: trimmed } });
        } catch {
            res.status(500).json({ success: false, message: "Failed to create list." });
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

            const page = Math.max(1, parseInt(req.query.page as string) || 1);
            const limit = Math.min(100, Math.max(1, parseInt(req.query.limit as string) || 50));

            const allLists = (await col.distinct("listName", { userId, listName: { $ne: "" } })).filter(Boolean) as string[];
            const total = allLists.length;
            const totalPages = Math.ceil(total / limit);
            const paginatedLists = allLists.slice((page - 1) * limit, page * limit);

            res.status(200).json({
                success: true,
                data: {
                    lists: paginatedLists,
                    pagination: { total, totalPages, currentPage: page, limit },
                },
            });
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

            // Batch user lookup — replaces N+1
            const guestIds = (reviews as any[]).map((r: any) => r.guestId).filter(Boolean);
            const usersMap = guestIds.length > 0 ? await findUsersMap(usersCol, guestIds) : new Map();

            const reviewsWithGuests = (reviews as any[]).map((r) => {
                const guest = usersMap.get(r.guestId);
                return {
                    ...r,
                    guest: guest
                        ? { id: toIdString(guest._id), name: guest.name, image: guest.image }
                        : null,
                };
            });

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

// PUT dismiss review report (admin only)
app.put(
    "/api/admin/reviews/:id/dismiss-report",
    verifyToken,
    verifyAdmin,
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
            const result = await col.updateOne(
                { _id: objectId },
                { $unset: { isReported: "" } },
            );

            if (result.matchedCount === 0) {
                res.status(404).json({ success: false, message: "Review not found." });
                return;
            }

            res.status(200).json({ success: true, message: "Report dismissed." });
        } catch {
            res.status(500).json({ success: false, message: "Failed to dismiss report." });
        }
    },
);

// ============================================================
// ADMIN ADVERTISE ROUTES
// ============================================================

// GET admin advertise stats — real platform metrics
app.get(
    "/api/admin/advertise/stats",
    verifyToken,
    verifyAdmin,
    async (_req: AuthRequest, res: Response): Promise<void> => {
        try {
            const db = await getDb();
            const usersCol = db.collection("user");
            const bookingsCol = db.collection("bookings");
            const transactionsCol = db.collection("transactions");

            const [
                totalUsers,
                totalBookings,
                paymentAgg,
            ] = await Promise.all([
                usersCol.countDocuments({ role: { $ne: "admin" } }),
                bookingsCol.countDocuments({ status: { $in: ["confirmed", "completed"] } }),
                transactionsCol.aggregate([
                    { $match: { type: "payment", status: "success" } },
                    { $group: { _id: null, total: { $sum: "$amount" }, count: { $sum: 1 } } },
                ]).toArray(),
            ]);

            const totalPaymentAmount = paymentAgg.length > 0 ? paymentAgg[0].total : 0;
            const totalPaymentCount = paymentAgg.length > 0 ? paymentAgg[0].count : 0;
            const avgBookingValue = totalPaymentCount > 0 ? Math.round(totalPaymentAmount / totalPaymentCount) : 0;
            const monthlyPageViews = Math.round(totalBookings * 4.5);

            res.status(200).json({
                success: true,
                data: {
                    monthlyActiveUsers: totalUsers,
                    monthlyPageViews,
                    avgBookingValue,
                    totalBookings,
                    totalUsers,
                },
            });
        } catch {
            res.status(500).json({ success: false, message: "Failed to fetch advertise stats." });
        }
    },
);

// POST admin advertise waitlist signup
app.post(
    "/api/admin/advertise/waitlist",
    verifyToken,
    verifyAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const { name, email } = req.body;
            if (!name?.trim() || !email?.trim()) {
                res.status(400).json({ success: false, message: "Name and email are required." });
                return;
            }

            const db = await getDb();
            const col = db.collection("waitlist");

            const existing = await col.findOne({ email: email.trim().toLowerCase() });
            if (existing) {
                res.status(200).json({ success: true, message: "Already on the waitlist." });
                return;
            }

            await col.insertOne({
                name: name.trim(),
                email: email.trim().toLowerCase(),
                userId: toIdString(req.user!._id),
                createdAt: new Date(),
            });

            // Get updated count
            const total = await col.countDocuments();

            res.status(201).json({
                success: true,
                data: { waitlistCount: total },
                message: "Successfully joined the waitlist.",
            });
        } catch {
            res.status(500).json({ success: false, message: "Failed to join waitlist." });
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
// DASHBOARD CONSOLIDATED ENDPOINTS
// ============================================================

// GET /api/dashboard/guest — consolidated guest dashboard data
app.get(
    "/api/dashboard/guest",
    verifyToken,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const db = await getDb();
            const userId = toIdString(req.user!._id);

            const bookingsCol = db.collection("bookings");
            const transactionsCol = db.collection("transactions");
            const wishlistCol = db.collection("wishlist");

            const now = new Date();
            const startOfYear = new Date(now.getFullYear(), 0, 1);

            const [
                totalBookings,
                upcomingTrips,
                wishlistCount,
                totalSpentResult,
                upcomingBookings,
                recentTransactions,
                monthlySpendResult,
            ] = await Promise.all([
                bookingsCol.countDocuments({ guestId: userId }),
                bookingsCol.countDocuments({ guestId: userId, status: "confirmed" }),
                wishlistCol.countDocuments({ userId }),
                transactionsCol.aggregate([
                    { $match: { userId, type: "payment", status: "success" } },
                    { $group: { _id: null, total: { $sum: "$amount" } } },
                ]).toArray(),
                bookingsCol.find({ guestId: userId, status: "confirmed" })
                    .sort({ checkIn: 1 })
                    .limit(5)
                    .toArray(),
                transactionsCol.find({ userId })
                    .sort({ createdAt: -1 })
                    .limit(5)
                    .toArray(),
                transactionsCol.aggregate([
                    { $match: { userId, type: "payment", status: "success", createdAt: { $gte: startOfYear } } },
                    { $group: { _id: { $month: "$createdAt" }, total: { $sum: "$amount" } } },
                    { $sort: { _id: 1 } },
                ]).toArray(),
            ]);

            const totalSpent = totalSpentResult.length > 0 ? totalSpentResult[0].total : 0;
            const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
            const monthlySpend = Array.from({ length: 12 }, (_, i) => ({
                month: MONTHS[i],
                spend: 0,
            }));
            monthlySpendResult.forEach((r: any) => {
                if (r._id >= 1 && r._id <= 12) {
                    monthlySpend[r._id - 1].spend = r.total;
                }
            });

            res.status(200).json({
                success: true,
                data: {
                    totalBookings,
                    upcomingTrips,
                    wishlistCount,
                    totalSpent,
                    upcomingBookings,
                    recentTransactions,
                    monthlySpend,
                },
            });
        } catch {
            res.status(500).json({ success: false, message: "Failed to fetch guest dashboard." });
        }
    },
);

// GET /api/dashboard/host — consolidated host dashboard data
app.get(
    "/api/dashboard/host",
    verifyToken,
    verifyHostOrAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const db = await getDb();
            const userId = toIdString(req.user!._id);

            const propertiesCol = db.collection("properties");
            const bookingsCol = db.collection("bookings");
            const transactionsCol = db.collection("transactions");
            const reviewsCol = db.collection("reviews");

            const now = new Date();
            const startOfYear = new Date(now.getFullYear(), 0, 1);
            const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
            const startOfNextMonth = new Date(now.getFullYear(), now.getMonth() + 1, 1);
            const daysInMonth = new Date(now.getFullYear(), now.getMonth() + 1, 0).getDate();

            const hostProperties = await propertiesCol.find({ hostId: userId }).toArray();
            const propertyIds = hostProperties.map((p: any) => p._id);

            const totalProperties = hostProperties.length;

            const [
                activeBookings,
                pendingBookings,
                reviewsResult,
                totalIncomeResult,
                monthlyIncomeResult,
                recentReservations,
                occupancyResult,
            ] = await Promise.all([
                bookingsCol.countDocuments({ hostId: userId, status: "confirmed" }),
                bookingsCol.find({ hostId: userId, status: "pending" })
                    .sort({ createdAt: -1 })
                    .limit(5)
                    .toArray(),
                reviewsCol.aggregate([
                    { $match: { hostId: userId } },
                    { $group: { _id: null, avg: { $avg: "$rating" }, count: { $sum: 1 } } },
                ]).toArray(),
                transactionsCol.aggregate([
                    { $match: { userId, type: "payout", status: "success" } },
                    { $group: { _id: null, total: { $sum: "$amount" } } },
                ]).toArray(),
                transactionsCol.aggregate([
                    { $match: { userId, type: "payout", status: "success", createdAt: { $gte: startOfYear } } },
                    { $group: { _id: { $month: "$createdAt" }, total: { $sum: "$amount" } } },
                    { $sort: { _id: 1 } },
                ]).toArray(),
                bookingsCol.find({ hostId: userId })
                    .sort({ createdAt: -1 })
                    .limit(5)
                    .toArray(),
                bookingsCol.aggregate([
                    { $match: { hostId: userId, status: { $in: ["confirmed", "completed"] }, checkIn: { $lt: startOfNextMonth }, checkOut: { $gt: startOfMonth } } },
                    { $project: { nightsInMonth: { $ceil: { $divide: [{ $subtract: [{ $min: ["$checkOut", startOfNextMonth] }, { $max: ["$checkIn", startOfMonth] }] }, 86400000] } } } },
                    { $group: { _id: null, totalBookedNights: { $sum: "$nightsInMonth" } } },
                ]).toArray(),
            ]);

            const averageRating = reviewsResult.length > 0 ? Math.round(reviewsResult[0].avg * 10) / 10 : 0;
            const totalReviews = reviewsResult.length > 0 ? reviewsResult[0].count : 0;
            const totalIncome = totalIncomeResult.length > 0 ? totalIncomeResult[0].total : 0;

            const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
            const monthlyIncome = Array.from({ length: 12 }, (_, i) => ({
                month: MONTHS[i],
                income: 0,
            }));
            monthlyIncomeResult.forEach((r: any) => {
                if (r._id >= 1 && r._id <= 12) {
                    monthlyIncome[r._id - 1].income = r.total;
                }
            });

            const thisMonthIncome = monthlyIncome[now.getMonth()].income;

            const totalConfirmed = activeBookings;
            const totalPendings = pendingBookings.length;
            const totalBookedNights = occupancyResult.length > 0 ? occupancyResult[0].totalBookedNights : 0;
            const occupancyRate = totalProperties > 0 && daysInMonth > 0
                ? Math.round((totalBookedNights / (totalProperties * daysInMonth)) * 100)
                : 0;

            res.status(200).json({
                success: true,
                data: {
                    totalProperties,
                    activeBookings,
                    thisMonthIncome,
                    occupancyRate,
                    averageRating,
                    totalReviews,
                    totalIncome,
                    pendingBookings,
                    recentReservations,
                    monthlyIncome,
                },
            });
        } catch {
            res.status(500).json({ success: false, message: "Failed to fetch host dashboard." });
        }
    },
);

// GET /api/dashboard/admin — consolidated admin dashboard data
app.get(
    "/api/dashboard/admin",
    verifyToken,
    verifyAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const db = await getDb();
            const propertiesCol = db.collection("properties");
            const bookingsCol = db.collection("bookings");
            const transactionsCol = db.collection("transactions");
            const usersCol = db.collection("user");
            const reviewsCol = db.collection("reviews");

            const now = new Date();
            const startOfYear = new Date(now.getFullYear(), 0, 1);

            const [
                totalUsers,
                totalProperties,
                totalBookings,
                commissionResult,
                pendingPayoutsResult,
                recentBookings,
                signupsResult,
                bookingsByStatus,
                propertiesByCategory,
                reportedReviews,
            ] = await Promise.all([
                usersCol.countDocuments(),
                propertiesCol.countDocuments(),
                bookingsCol.countDocuments(),
                transactionsCol.aggregate([
                    { $match: { type: "commission", status: "success" } },
                    { $group: { _id: null, total: { $sum: "$amount" } } },
                ]).toArray(),
                transactionsCol.aggregate([
                    { $match: { type: "payout", status: "pending" } },
                    { $group: { _id: null, total: { $sum: "$amount" } } },
                ]).toArray(),
                bookingsCol.find().sort({ createdAt: -1 }).limit(5).toArray(),
                usersCol.aggregate([
                    { $match: { createdAt: { $gte: startOfYear } } },
                    { $group: { _id: { $month: "$createdAt" }, count: { $sum: 1 } } },
                    { $sort: { _id: 1 } },
                ]).toArray(),
                bookingsCol.aggregate([
                    { $group: { _id: "$status", count: { $sum: 1 } } },
                ]).toArray(),
                propertiesCol.aggregate([
                    { $group: { _id: "$category", count: { $sum: 1 } } },
                    { $sort: { count: -1 } },
                ]).toArray(),
                reviewsCol.countDocuments({ isReported: true }),
            ]);

            const commissionEarned = commissionResult.length > 0 ? commissionResult[0].total : 0;
            const pendingPayouts = pendingPayoutsResult.length > 0 ? pendingPayoutsResult[0].total : 0;

            const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
            const signupTrend = Array.from({ length: 12 }, (_, i) => ({
                month: MONTHS[i],
                signups: 0,
            }));
            signupsResult.forEach((r: any) => {
                if (r._id >= 1 && r._id <= 12) {
                    signupTrend[r._id - 1].signups = r.count;
                }
            });

            const bookingStatusData = bookingsByStatus.map((r: any) => ({
                name: r._id,
                count: r.count,
            }));

            const categoryData = propertiesByCategory.map((r: any) => ({
                name: r._id,
                count: r.count,
            }));

            res.status(200).json({
                success: true,
                data: {
                    totalUsers,
                    totalProperties,
                    totalBookings,
                    commissionEarned,
                    pendingPayouts,
                    recentBookings,
                    signupTrend,
                    bookingStatusData,
                    categoryData,
                    reportedReviews,
                },
            });
        } catch {
            res.status(500).json({ success: false, message: "Failed to fetch admin dashboard." });
        }
    },
);

// ============================================================
// AI ROUTES
// ============================================================

// GET /api/ai/recommendations
app.get(
    "/api/ai/recommendations",
    verifyToken,
    async (req: AIAuthReq, res: Response): Promise<void> => {
        try {
            const groq = getGroq();
            if (!groq) {
                res.status(503).json({ success: false, message: "AI service not configured." });
                return;
            }

            const userId = req.user!._id.toString();
            const db = await getDb();
            const bookingsCol = db.collection("bookings");
            const wishlistCol = db.collection("wishlist");
            const reviewsCol = db.collection("reviews");
            const propertiesCol = db.collection("properties");

            const { location, budget, guests, propertyType } = req.query as Record<string, string | undefined>;

            const bookings = await bookingsCol
                .find({ guestId: userId, status: { $in: ["confirmed", "completed"] } })
                .sort({ createdAt: -1 }).limit(10).toArray();

            const wishlistItems = await wishlistCol
                .find({ userId }).sort({ createdAt: -1 }).limit(20).toArray();

            const reviews = await reviewsCol
                .find({ guestId: userId }).sort({ createdAt: -1 }).limit(10).toArray();

            const filter: Record<string, any> = { status: "active" };
            if (location) filter["location.city"] = { $regex: location, $options: "i" };
            if (propertyType) filter.category = propertyType.toLowerCase();
            if (guests) filter["details.maxGuests"] = { $gte: parseInt(guests) };
            if (budget) filter["price.perNight"] = { $lte: parseFloat(budget) };

            const properties = await propertiesCol
                .find(filter).sort({ rating: -1, reviewCount: -1 }).limit(30).toArray();

            if (properties.length === 0) {
                res.status(200).json({
                    success: true,
                    data: { recommendations: [], message: "No properties found matching your criteria." },
                });
                return;
            }

            const propertyList = properties.map((p: any) => ({
                propertyId: p._id.toString(),
                title: p.title, category: p.category, city: p.location?.city,
                country: p.location?.country, pricePerNight: p.price?.perNight,
                currency: p.price?.currency || "BDT", maxGuests: p.details?.maxGuests,
                bedrooms: p.details?.bedrooms, bathrooms: p.details?.bathrooms,
                amenities: p.amenities || [], rating: p.rating || 0, reviewCount: p.reviewCount || 0,
            }));

            const userContext = {
                previousBookings: bookings.map((b: any) => ({ propertyTitle: b.propertyTitle, city: b.city || "Unknown", status: b.status })),
                wishlistProperties: wishlistItems.map((w: any) => w.propertyId),
                pastReviews: reviews.map((r: any) => ({ rating: r.rating, propertyId: r.propertyId })),
            };

            const systemPrompt = `You are a property recommendation AI for AuraSpace.
Analyze the user's profile and preferences against available listings. For each match, provide a concise personalized reason.

USER PREFERENCES:
- Location: ${location || "Any"}
- Budget: ${budget ? `${budget} BDT/night` : "Any"}
- Guests: ${guests || "Any"}
- Property Type: ${propertyType || "Any"}

USER HISTORY:
${JSON.stringify(userContext, null, 2)}

AVAILABLE PROPERTIES (JSON array):
${JSON.stringify(propertyList, null, 2)}

Respond with ONLY a valid JSON array (no markdown):
[{"propertyId":"...","title":"...","reason":"..."}]`;

            const recModels = [AI_MODEL, ...AI_MODEL_FALLBACKS];
            let completion: any = null;
            for (const model of recModels) {
                try {
                    completion = await groq.chat.completions.create({
                        messages: [
                            { role: "system", content: systemPrompt },
                            { role: "user", content: "Recommend the best properties based on my preferences and history." },
                        ],
                        model, temperature: 0.4,
                    });
                    break;
                } catch (e: any) {
                    if (e?.status === 429 || e?.message?.includes("rate limit")) continue;
                    throw e;
                }
            }
            if (!completion) {
                res.status(429).json({ success: false, message: "AI service is experiencing high demand. Please try again in a few minutes." });
                return;
            }

            const raw = completion.choices[0]?.message?.content || "[]";
            let recommendations: any[];
            try {
                const cleaned = raw.replace(/```json\s*/gi, "").replace(/```\s*/g, "").trim();
                recommendations = JSON.parse(cleaned);
                if (!Array.isArray(recommendations)) recommendations = [];
            } catch { recommendations = []; }

            const enriched = recommendations.slice(0, 10).map((r: any) => {
                const prop = properties.find((p: any) => p._id.toString() === r.propertyId);
                if (!prop) return null;
                return {
                    propertyId: r.propertyId, title: prop.title, reason: r.reason || "Matches your preferences",
                    matchScore: r.matchScore || 85, images: prop.images?.[0] || "",
                    pricePerNight: prop.price?.perNight, currency: prop.price?.currency || "BDT",
                    location: prop.location, rating: prop.rating, reviewCount: prop.reviewCount,
                    category: prop.category, details: prop.details,
                };
            }).filter(Boolean);

            res.status(200).json({ success: true, data: { recommendations: enriched } });
        } catch (error: any) {
            console.error("[AI Recommendations] Error:", error);
            res.status(500).json({ success: false, message: error.message || "Failed to generate recommendations." });
        }
    },
);

// POST /api/ai/chat — works with or without auth; saves history only when logged in
app.post(
    "/api/ai/chat",
    async (req: AIAuthReq, res: Response): Promise<void> => {
        try {
            const groq = getGroq();
            if (!groq) {
                res.status(503).json({ success: false, message: "AI service not configured." });
                return;
            }

            // Optional auth: try to identify user but don't block
            let userId: string | null = null;
            let userName = "Guest";
            let userRole = "guest";
            const authHeader = req.headers.authorization;
            if (authHeader?.startsWith("Bearer ")) {
                try {
                    const token = authHeader.substring(7).trim();
                    if (token) {
                        const { payload } = await jwtVerify(token, getJWKS());
                        const jwtPayload = payload as JwtPayload;
                        if (jwtPayload.sub) {
                            const db = await getDb();
                            const user = await findUserById(db.collection("user"), jwtPayload.sub);
                            if (user && !user.banned) {
                                userId = user._id.toString();
                                userName = user.name;
                                userRole = user.role;
                            }
                        }
                    }
                } catch {
                    // Token invalid/expired — continue as guest
                }
            }

            const { message, conversationId } = req.body;

            if (!message || typeof message !== "string") {
                res.status(400).json({ success: false, message: "Message is required." });
                return;
            }

            let conversationHistory: Array<{ role: "user" | "assistant"; content: string }> = [];
            let conversationIdOut: string | null = null;

            // Load conversation history only if user is logged in
            if (userId) {
                const db = await getDb();
                const aiConvoCol = db.collection("ai_conversations");

                let conversation: AIConversationDoc | null = null;
                if (conversationId) {
                    const oid = new ObjectId(conversationId);
                    conversation = await aiConvoCol.findOne({ _id: oid, userId }) as AIConversationDoc | null;
                }
                if (!conversation) {
                    conversation = { userId, messages: [], createdAt: new Date(), updatedAt: new Date() };
                    const result = await aiConvoCol.insertOne(conversation);
                    conversation._id = result.insertedId;
                }
                conversationHistory = conversation.messages;
                conversationIdOut = conversation._id!.toString();
            }

            const systemPrompt = `You are AuraSpace AI, a helpful assistant for a property rental platform. Be concise (1-3 sentences), friendly, and helpful. For property searches, ask about location, budget, and guests. For navigation, give brief step-by-step instructions.`;

            const messages = [
                { role: "system", content: systemPrompt } as const,
                ...conversationHistory.slice(-10).map((m) => ({
                    role: m.role as "user" | "assistant",
                    content: m.content,
                })),
                { role: "user" as const, content: message },
            ];

            const models = [AI_MODEL, ...AI_MODEL_FALLBACKS];
            let completion: any = null;
            let lastError: any = null;

            for (const model of models) {
                try {
                    completion = await groq.chat.completions.create({
                        messages, model, temperature: 0.6,
                    });
                    break;
                } catch (groqError: any) {
                    lastError = groqError;
                    if (groqError?.status === 429 || groqError?.message?.includes("rate limit")) {
                        console.warn(`[AI Chat] Model ${model} rate limited, trying next...`);
                        continue;
                    }
                    throw groqError;
                }
            }

            if (!completion) {
                res.status(429).json({
                    success: false,
                    message: "AI service is experiencing high demand. Please try again in a few minutes.",
                });
                return;
            }

            const reply = completion.choices[0]?.message?.content || "I'm sorry, I couldn't generate a response.";

            // Save to DB only if user is logged in
            if (userId && conversationIdOut) {
                const db = await getDb();
                const aiConvoCol = db.collection("ai_conversations");
                const now = new Date();
                await aiConvoCol.updateOne(
                    { _id: new ObjectId(conversationIdOut) },
                    {
                        $push: {
                            messages: {
                                $each: [
                                    { role: "user" as const, content: message, createdAt: now },
                                    { role: "assistant" as const, content: reply, createdAt: now },
                                ],
                            },
                        } as any,
                        $set: { updatedAt: now },
                    } as any,
                );
            }

            const suggestions = generateSuggestions(message, reply);

            res.status(200).json({
                success: true,
                data: {
                    reply,
                    conversationId: conversationIdOut,
                    suggestions,
                },
            });
        } catch (error: any) {
            console.error("[AI Chat] Error:", error);
            if (error?.status === 429 || error?.message?.includes("rate limit")) {
                res.status(429).json({
                    success: false,
                    message: "AI service is experiencing high demand. Please try again in a few minutes.",
                });
                return;
            }
            res.status(500).json({ success: false, message: error.message || "Failed to process chat message." });
        }
    },
);

// POST /api/ai/chat/stream
app.post(
    "/api/ai/chat/stream",
    verifyToken,
    async (req: AIAuthReq, res: Response): Promise<void> => {
        try {
            const groq = getGroq();
            if (!groq) {
                res.status(503).json({ success: false, message: "AI service not configured." });
                return;
            }

            const userId = req.user!._id.toString();
            const userName = req.user!.name;
            const userRole = req.user!.role;
            const { message, conversationId } = req.body;

            if (!message || typeof message !== "string") {
                res.status(400).json({ success: false, message: "Message is required." });
                return;
            }

            const db = await getDb();
            const aiConvoCol = db.collection("ai_conversations");
            const bookingsCol = db.collection("bookings");

            let conversation: AIConversationDoc | null = null;
            if (conversationId) {
                const oid = new ObjectId(conversationId);
                conversation = await aiConvoCol.findOne({ _id: oid, userId }) as AIConversationDoc | null;
            }

            if (!conversation) {
                conversation = { userId, messages: [], createdAt: new Date(), updatedAt: new Date() };
                const result = await aiConvoCol.insertOne(conversation);
                conversation._id = result.insertedId;
            }

            const bookingCount = await bookingsCol.countDocuments({ guestId: userId });

            const systemPrompt = `You are a helpful AI assistant for AuraSpace, a property rental platform.
Keep responses concise (2-4 sentences). Be friendly and professional.

USER CONTEXT:
- Name: ${userName}
- Role: ${userRole}
- Active Bookings: ${bookingCount}`;

            const messages = [
                { role: "system", content: systemPrompt } as const,
                ...conversation.messages.slice(-20).map((m) => ({
                    role: m.role as "user" | "assistant",
                    content: m.content,
                })),
                { role: "user" as const, content: message },
            ];

            res.setHeader("Content-Type", "text/event-stream");
            res.setHeader("Cache-Control", "no-cache");
            res.setHeader("Connection", "keep-alive");
            res.setHeader("X-Accel-Buffering", "no");

            const stream = await groq.chat.completions.create({
                messages, model: AI_MODEL, temperature: 0.6, max_tokens: 1024, stream: true,
            });

            let fullReply = "";
            for await (const chunk of stream) {
                const content = chunk.choices[0]?.delta?.content || "";
                if (content) {
                    fullReply += content;
                    res.write(`data: ${JSON.stringify({ content })}\n\n`);
                }
            }

            const now = new Date();
            await aiConvoCol.updateOne(
                { _id: conversation._id },
                {
                    $push: {
                        messages: {
                            $each: [
                                { role: "user" as const, content: message, createdAt: now },
                                { role: "assistant" as const, content: fullReply, createdAt: now },
                            ],
                        },
                    } as any,
                    $set: { updatedAt: now },
                } as any,
            );

            const suggestions = generateSuggestions(message, fullReply);
            res.write(`data: ${JSON.stringify({ done: true, conversationId: conversation._id!.toString(), suggestions })}\n\n`);
            res.end();
        } catch (error: any) {
            console.error("[AI Chat Stream] Error:", error);
            if (!res.headersSent) {
                res.status(500).json({ success: false, message: error.message || "Stream failed." });
            } else {
                res.write(`data: ${JSON.stringify({ error: error.message })}\n\n`);
                res.end();
            }
        }
    },
);

// GET /api/ai/chat/history
app.get(
    "/api/ai/chat/history",
    verifyToken,
    async (req: AIAuthReq, res: Response): Promise<void> => {
        try {
            const userId = req.user!._id.toString();
            const { conversationId } = req.query as Record<string, string | undefined>;

            const db = await getDb();
            const aiConvoCol = db.collection("ai_conversations");

            if (conversationId) {
                const oid = new ObjectId(conversationId);
                const convo = await aiConvoCol.findOne({ _id: oid, userId }) as AIConversationDoc | null;
                if (!convo) {
                    res.status(404).json({ success: false, message: "Conversation not found." });
                    return;
                }
                res.status(200).json({
                    success: true,
                    data: {
                        conversationId: convo._id!.toString(),
                        messages: convo.messages,
                        createdAt: convo.createdAt,
                        updatedAt: convo.updatedAt,
                    },
                });
                return;
            }

            const conversations = await aiConvoCol
                .find({ userId })
                .project({ _id: 1, messages: { $slice: -1 }, createdAt: 1, updatedAt: 1 })
                .sort({ updatedAt: -1 }).limit(50).toArray();

            const list = conversations.map((c: any) => ({
                conversationId: c._id.toString(),
                lastMessage: c.messages?.[0]?.content?.slice(0, 100) || "",
                createdAt: c.createdAt,
                updatedAt: c.updatedAt,
            }));

            res.status(200).json({ success: true, data: { conversations: list } });
        } catch (error: any) {
            console.error("[AI Chat History] Error:", error);
            res.status(500).json({ success: false, message: "Failed to fetch history." });
        }
    },
);

// DELETE /api/ai/chat/:conversationId
app.delete(
    "/api/ai/chat/:conversationId",
    verifyToken,
    async (req: AIAuthReq, res: Response): Promise<void> => {
        try {
            const userId = req.user!._id.toString();
            const conversationId = String(req.params.conversationId || "");
            const db = await getDb();
            const aiConvoCol = db.collection("ai_conversations");
            const oid = new ObjectId(conversationId);
            const result = await aiConvoCol.deleteOne({ _id: oid, userId });
            if (result.deletedCount === 0) {
                res.status(404).json({ success: false, message: "Conversation not found." });
                return;
            }
            res.status(200).json({ success: true, message: "Conversation deleted." });
        } catch (error: any) {
            console.error("[AI Chat Delete] Error:", error);
            res.status(500).json({ success: false, message: "Failed to delete conversation." });
        }
    },
);

// POST /api/ai/generate-description
app.post(
    "/api/ai/generate-description",
    verifyToken,
    async (req: AIAuthReq, res: Response): Promise<void> => {
        try {
            const groq = getGroq();
            if (!groq) {
                res.status(503).json({ success: false, message: "AI service not configured." });
                return;
            }

            const {
                title, propertyType, placeType, city, country,
                bedrooms, bathrooms, guests, beds, amenities,
                tone = "professional", length = "medium",
            } = req.body;

            if (!title) {
                res.status(400).json({ success: false, message: "Property title is required." });
                return;
            }

            const lengthGuide: Record<string, string> = {
                short: "2-3 sentences, brief and catchy",
                medium: "3-5 sentences, engaging and informative",
                long: "5-8 sentences, detailed and descriptive",
            };

            const toneGuide: Record<string, string> = {
                professional: "Professional and polished, suitable for business travelers",
                luxury: "Elegant and premium, highlighting exclusivity and comfort",
                friendly: "Warm and inviting, making guests feel at home",
            };

            const amenitiesStr = Array.isArray(amenities) ? amenities.join(", ") : amenities || "various amenities";

            const prompt = `Generate a property description for a rental listing.

PROPERTY DETAILS:
- Title: ${title}
- Type: ${propertyType || "Property"}
- Place Type: ${placeType || "Entire place"}
- Location: ${city || ""}${city && country ? ", " : ""}${country || ""}
- Bedrooms: ${bedrooms || "N/A"}
- Bathrooms: ${bathrooms || "N/A"}
- Beds: ${beds || bedrooms || "N/A"}
- Max Guests: ${guests || "N/A"}
- Amenities: ${amenitiesStr}

TONE: ${toneGuide[tone as string] || toneGuide.professional}
LENGTH: ${lengthGuide[length as string] || lengthGuide.medium}

Write only the description, no title or prefix.`;

            const descModels = [AI_MODEL, ...AI_MODEL_FALLBACKS];
            let completion: any = null;
            for (const model of descModels) {
                try {
                    completion = await groq.chat.completions.create({
                        messages: [
                            { role: "system", content: "You are a professional copywriter specializing in property listings. Write engaging, accurate descriptions that highlight key features." },
                            { role: "user", content: prompt },
                        ],
                        model, temperature: 0.7,
                    });
                    break;
                } catch (e: any) {
                    if (e?.status === 429 || e?.message?.includes("rate limit")) continue;
                    throw e;
                }
            }
            if (!completion) {
                res.status(429).json({ success: false, message: "AI service is experiencing high demand. Please try again in a few minutes." });
                return;
            }

            const description = completion.choices[0]?.message?.content?.trim() || "";

            res.status(200).json({ success: true, data: { description } });
        } catch (error: any) {
            console.error("[AI Description] Error:", error);
            res.status(500).json({ success: false, message: error.message || "Failed to generate description." });
        }
    },
);

// ============================================================
// BLOG ROUTES
// ============================================================

// GET /api/blogs — public, paginated, filterable
app.get(
    "/api/blogs",
    async (req: Request, res: Response): Promise<void> => {
        try {
            const db = await getDb();
            const col = db.collection("blogs");
            const { page, limit, skip } = getPagination(req.query, 50, 12);

            const filter: Record<string, any> = { status: "published" };

            if (req.query.tag) {
                const tag = String(req.query.tag).trim().toLowerCase();
                if (tag) filter.tags = tag;
            }
            if (req.query.search) {
                const term = String(req.query.search).trim().slice(0, 100);
                if (term) {
                    filter.$or = [
                        { title: { $regex: escapeRegex(term), $options: "i" } },
                        { excerpt: { $regex: escapeRegex(term), $options: "i" } },
                        { tags: { $regex: escapeRegex(term), $options: "i" } },
                    ];
                }
            }

            let sort: Record<string, 1 | -1> = { createdAt: -1 };
            if (req.query.sort === "popular") sort = { viewCount: -1 };

            const [blogs, total] = await Promise.all([
                col.find(filter).sort(sort).skip(skip).limit(limit).toArray(),
                col.countDocuments(filter),
            ]);

            res.status(200).json({
                success: true,
                data: {
                    blogs: (blogs as BlogDoc[]).map(buildBlogResponse),
                    pagination: buildPaginationResponse(total, page, limit),
                },
            });
        } catch (error) {
            console.error("[BLOGS] List error:", error);
            res.status(500).json({ success: false, message: "Failed to fetch blogs." });
        }
    },
);

// GET /api/blogs/featured — for homepage
app.get(
    "/api/blogs/featured",
    async (_req: Request, res: Response): Promise<void> => {
        try {
            const db = await getDb();
            const col = db.collection("blogs");

            const blogs = await col
                .find({ status: "published", isFeatured: true })
                .sort({ createdAt: -1 })
                .limit(6)
                .toArray();

            res.status(200).json({
                success: true,
                data: { blogs: (blogs as BlogDoc[]).map(buildBlogResponse) },
            });
        } catch (error) {
            console.error("[BLOGS] Featured error:", error);
            res.status(500).json({ success: false, message: "Failed to fetch featured blogs." });
        }
    },
);

// GET /api/blogs/my/blogs — current user's blogs (must come before /:slug)
app.get(
    "/api/blogs/my/blogs",
    verifyToken,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const db = await getDb();
            const col = db.collection("blogs");
            const userId = toIdString(req.user!._id);
            const { page, limit, skip } = getPagination(req.query, 50, 12);

            const filter: Record<string, any> = { authorId: userId };
            if (req.query.status && ["published", "draft"].includes(String(req.query.status))) {
                filter.status = String(req.query.status);
            }

            const [blogs, total] = await Promise.all([
                col.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
                col.countDocuments(filter),
            ]);

            res.status(200).json({
                success: true,
                data: {
                    blogs: (blogs as BlogDoc[]).map(buildBlogResponse),
                    pagination: buildPaginationResponse(total, page, limit),
                },
            });
        } catch (error) {
            console.error("[BLOGS] My blogs error:", error);
            res.status(500).json({ success: false, message: "Failed to fetch your blogs." });
        }
    },
);

// GET /api/blogs/:slug — single blog by slug (increments view count)
app.get(
    "/api/blogs/:slug",
    async (req: Request, res: Response): Promise<void> => {
        try {
            const slug = String(req.params.slug || "").trim();
            if (!slug) {
                res.status(400).json({ success: false, message: "Slug is required." });
                return;
            }

            const db = await getDb();
            const col = db.collection("blogs");

            const blog = await col.findOne({ slug, status: "published" });
            if (!blog) {
                res.status(404).json({ success: false, message: "Blog not found." });
                return;
            }

            await col.updateOne({ _id: blog._id }, { $inc: { viewCount: 1 } });

            res.status(200).json({
                success: true,
                data: { blog: buildBlogResponse(blog as BlogDoc) },
            });
        } catch (error) {
            console.error("[BLOGS] Detail error:", error);
            res.status(500).json({ success: false, message: "Failed to fetch blog." });
        }
    },
);

// POST /api/blogs — create new blog (any logged-in user)
app.post(
    "/api/blogs",
    verifyToken,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const { title, content, excerpt, tags, coverImage, status } = req.body;

            if (!title || typeof title !== "string" || title.trim().length < 3) {
                res.status(400).json({ success: false, message: "Title must be at least 3 characters." });
                return;
            }
            if (!content || typeof content !== "string" || stripHtml(content).length < 10) {
                res.status(400).json({ success: false, message: "Content must be at least 10 characters." });
                return;
            }

            const db = await getDb();
            const col = db.collection("blogs");

            // Generate unique slug
            let baseSlug = generateSlug(title.trim());
            let slug = baseSlug;
            let suffix = 1;
            while (await col.findOne({ slug })) {
                slug = `${baseSlug}-${suffix}`;
                suffix++;
            }

            const user = req.user!;
            const newBlog: BlogDoc = {
                title: title.trim(),
                slug,
                content: content.trim(),
                excerpt: excerpt?.trim()?.slice(0, 300) || stripHtml(content).slice(0, 200),
                coverImage: coverImage || null,
                tags: Array.isArray(tags)
                    ? tags.map((t: string) => String(t).trim().toLowerCase()).filter(Boolean).slice(0, 10)
                    : [],
                authorId: toIdString(user._id),
                authorName: user.name,
                authorImage: user.image || null,
                status: status === "draft" ? "draft" : "published",
                isFeatured: false,
                viewCount: 0,
                readingTime: calculateReadingTime(content),
                createdAt: new Date(),
                updatedAt: new Date(),
            };

            const result = await col.insertOne(newBlog as any);

            res.status(201).json({
                success: true,
                message: "Blog created successfully.",
                data: buildBlogResponse({ ...newBlog, _id: result.insertedId }),
            });
        } catch (error) {
            console.error("[BLOGS] Create error:", error);
            res.status(500).json({ success: false, message: "Failed to create blog." });
        }
    },
);

// POST /api/blogs/upload-cover — upload cover image via imgbb
app.post(
    "/api/blogs/upload-cover",
    verifyToken,
    upload.single("cover"),
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const file = req.file as Express.Multer.File | undefined;
            if (!file) {
                res.status(400).json({ success: false, message: "No file uploaded." });
                return;
            }

            const key = process.env.IMGBB_API_KEY;
            let url: string;
            if (key) {
                try {
                    url = await uploadToImgbb(file.buffer, file.originalname);
                } catch (err: any) {
                    console.warn("[Blog] imgbb failed, local fallback:", err.message);
                    url = await saveFileLocally(file.buffer, file.originalname);
                }
            } else {
                url = await saveFileLocally(file.buffer, file.originalname);
            }

            res.status(200).json({
                success: true,
                data: { url },
            });
        } catch (error: any) {
            if (error.code === "LIMIT_FILE_SIZE") {
                res.status(400).json({ success: false, message: "File too large. Max 5MB." });
                return;
            }
            console.error("[BLOGS] Cover upload error:", error);
            res.status(500).json({ success: false, message: error.message || "Failed to upload cover image." });
        }
    },
);

// PUT /api/blogs/:id — update blog (owner or admin)
app.put(
    "/api/blogs/:id",
    verifyToken,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const id = parseId(req.params.id);
            const objectId = toObjectId(id);
            const user = req.user!;
            if (!objectId) {
                res.status(400).json({ success: false, message: "Invalid blog ID." });
                return;
            }

            const db = await getDb();
            const col = db.collection("blogs");
            const existing = await col.findOne({ _id: objectId });
            if (!existing) {
                res.status(404).json({ success: false, message: "Blog not found." });
                return;
            }

            if (user.role !== "admin" && existing.authorId !== toIdString(user._id)) {
                res.status(403).json({ success: false, message: "You can only update your own blogs." });
                return;
            }

            const { title, content, excerpt, tags, coverImage, status } = req.body;
            const updates: Record<string, any> = { updatedAt: new Date() };

            if (title !== undefined) {
                if (typeof title !== "string" || title.trim().length < 3) {
                    res.status(400).json({ success: false, message: "Title must be at least 3 characters." });
                    return;
                }
                updates.title = title.trim();
                // Regenerate slug if title changed
                if (title.trim() !== existing.title) {
                    let baseSlug = generateSlug(title.trim());
                    let slug = baseSlug;
                    let suffix = 1;
                    while (await col.findOne({ slug, _id: { $ne: objectId } })) {
                        slug = `${baseSlug}-${suffix}`;
                        suffix++;
                    }
                    updates.slug = slug;
                }
            }
            if (content !== undefined) {
                if (typeof content !== "string" || stripHtml(content).length < 10) {
                    res.status(400).json({ success: false, message: "Content must be at least 10 characters." });
                    return;
                }
                updates.content = content.trim();
                updates.readingTime = calculateReadingTime(content);
            }
            if (excerpt !== undefined) updates.excerpt = String(excerpt).trim().slice(0, 300);
            if (coverImage !== undefined) updates.coverImage = coverImage || null;
            if (tags !== undefined && Array.isArray(tags)) {
                updates.tags = tags.map((t: string) => String(t).trim().toLowerCase()).filter(Boolean).slice(0, 10);
            }
            if (status !== undefined && ["published", "draft"].includes(String(status))) {
                updates.status = status;
            }

            await col.updateOne({ _id: objectId }, { $set: updates });
            const updated = await col.findOne({ _id: objectId });

            res.status(200).json({
                success: true,
                message: "Blog updated successfully.",
                data: buildBlogResponse(updated as BlogDoc),
            });
        } catch (error) {
            console.error("[BLOGS] Update error:", error);
            res.status(500).json({ success: false, message: "Failed to update blog." });
        }
    },
);

// DELETE /api/blogs/:id — soft delete (owner or admin)
app.delete(
    "/api/blogs/:id",
    verifyToken,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const id = parseId(req.params.id);
            const objectId = toObjectId(id);
            const user = req.user!;
            if (!objectId) {
                res.status(400).json({ success: false, message: "Invalid blog ID." });
                return;
            }

            const db = await getDb();
            const col = db.collection("blogs");
            const existing = await col.findOne({ _id: objectId });
            if (!existing) {
                res.status(404).json({ success: false, message: "Blog not found." });
                return;
            }

            if (user.role !== "admin" && existing.authorId !== toIdString(user._id)) {
                res.status(403).json({ success: false, message: "You can only delete your own blogs." });
                return;
            }

            await col.deleteOne({ _id: objectId });

            res.status(200).json({ success: true, message: "Blog deleted successfully." });
        } catch (error) {
            console.error("[BLOGS] Delete error:", error);
            res.status(500).json({ success: false, message: "Failed to delete blog." });
        }
    },
);

// ============================================================
// ADMIN BLOG ROUTES
// ============================================================

// GET /api/admin/blogs — list all blogs (admin only)
app.get(
    "/api/admin/blogs",
    verifyToken,
    verifyAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const db = await getDb();
            const col = db.collection("blogs");
            const { page, limit, skip } = getPagination(req.query, 50, 20);

            const filter: Record<string, any> = {};
            if (req.query.status && ["published", "draft"].includes(String(req.query.status))) {
                filter.status = String(req.query.status);
            }
            if (req.query.featured === "true") filter.isFeatured = true;
            if (req.query.featured === "false") filter.isFeatured = false;
            if (req.query.search) {
                const term = String(req.query.search).trim().slice(0, 100);
                if (term) {
                    filter.$or = [
                        { title: { $regex: escapeRegex(term), $options: "i" } },
                        { authorName: { $regex: escapeRegex(term), $options: "i" } },
                    ];
                }
            }

            const [blogs, total] = await Promise.all([
                col.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
                col.countDocuments(filter),
            ]);

            res.status(200).json({
                success: true,
                data: {
                    blogs: (blogs as BlogDoc[]).map(buildBlogResponse),
                    pagination: buildPaginationResponse(total, page, limit),
                },
            });
        } catch (error) {
            console.error("[ADMIN BLOGS] List error:", error);
            res.status(500).json({ success: false, message: "Failed to fetch blogs." });
        }
    },
);

// PUT /api/admin/blogs/:id/feature — toggle featured status
app.put(
    "/api/admin/blogs/:id/feature",
    verifyToken,
    verifyAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const id = parseId(req.params.id);
            const objectId = toObjectId(id);
            if (!objectId) {
                res.status(400).json({ success: false, message: "Invalid blog ID." });
                return;
            }

            const db = await getDb();
            const col = db.collection("blogs");
            const blog = await col.findOne({ _id: objectId });
            if (!blog) {
                res.status(404).json({ success: false, message: "Blog not found." });
                return;
            }

            const newFeatured = !blog.isFeatured;
            await col.updateOne({ _id: objectId }, { $set: { isFeatured: newFeatured, updatedAt: new Date() } });

            res.status(200).json({
                success: true,
                message: `Blog ${newFeatured ? "featured" : "unfeatured"} successfully.`,
                data: { isFeatured: newFeatured },
            });
        } catch (error) {
            console.error("[ADMIN BLOGS] Feature toggle error:", error);
            res.status(500).json({ success: false, message: "Failed to update blog." });
        }
    },
);

// DELETE /api/admin/blogs/:id — admin can delete any blog
app.delete(
    "/api/admin/blogs/:id",
    verifyToken,
    verifyAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const id = parseId(req.params.id);
            const objectId = toObjectId(id);
            if (!objectId) {
                res.status(400).json({ success: false, message: "Invalid blog ID." });
                return;
            }

            const db = await getDb();
            const col = db.collection("blogs");
            const blog = await col.findOne({ _id: objectId });
            if (!blog) {
                res.status(404).json({ success: false, message: "Blog not found." });
                return;
            }

            await col.deleteOne({ _id: objectId });

            res.status(200).json({ success: true, message: "Blog deleted successfully." });
        } catch (error) {
            console.error("[ADMIN BLOGS] Delete error:", error);
            res.status(500).json({ success: false, message: "Failed to delete blog." });
        }
    },
);

// ============================================================
// AI BLOG GENERATOR
// ============================================================

// POST /api/ai/blog-generator — generate blog content with AI
app.post(
    "/api/ai/blog-generator",
    verifyToken,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const groq = getGroq();
            if (!groq) {
                res.status(503).json({ success: false, message: "AI service not configured." });
                return;
            }

            const { topic, tone, style, length } = req.body;
            if (!topic || typeof topic !== "string" || topic.trim().length < 3) {
                res.status(400).json({ success: false, message: "Topic must be at least 3 characters." });
                return;
            }

            const validTones = ["professional", "casual", "enthusiastic", "informative", "inspirational"];
            const validStyles = ["blog-post", "listicle", "how-to", "guide", "story"];
            const validLengths = ["short", "medium", "long"];

            const selectedTone = validTones.includes(tone) ? tone : "professional";
            const selectedStyle = validStyles.includes(style) ? style : "blog-post";
            const selectedLength = validLengths.includes(length) ? length : "medium";

            const wordCounts: Record<string, string> = {
                short: "400-600 words",
                medium: "800-1200 words",
                long: "1500-2500 words",
            };

            const systemPrompt = `You are an expert travel and hospitality blogger. Write high-quality, engaging blog content for AuraSpace (a travel and property rental platform).

IMPORTANT: Return ONLY valid JSON with this exact structure — no markdown, no code fences, no extra text:
{
  "title": "Blog title",
  "content": "Full blog content in HTML format using <h2>, <h3>, <p>, <ul>, <ol>, <li>, <strong>, <em>, <blockquote> tags",
  "excerpt": "2-3 sentence summary",
  "tags": ["relevant", "tags", "lowercase"]
}

Content rules:
- Write ${wordCounts[selectedLength]} in a ${selectedTone} tone
- Use the ${selectedStyle} format
- Include practical tips, insights, or stories relevant to travel/property rental
- Use HTML tags for formatting (no <html>, <body>, or <head> tags)
- Tags should be lowercase, relevant to the topic (3-5 tags)
- Make it engaging and valuable for readers`;

            const messages = [
                { role: "system" as const, content: systemPrompt },
                { role: "user" as const, content: `Write a ${selectedLength} ${selectedStyle} blog about: ${topic.trim()}` },
            ];

            const models = [AI_MODEL, ...AI_MODEL_FALLBACKS];
            let completion: any = null;

            for (const model of models) {
                try {
                    completion = await groq.chat.completions.create({
                        messages,
                        model,
                        temperature: 0.7,
                    });
                    break;
                } catch (groqError: any) {
                    if (groqError?.status === 429 || groqError?.message?.includes("rate limit")) continue;
                    throw groqError;
                }
            }

            if (!completion) {
                res.status(429).json({ success: false, message: "AI service is experiencing high demand. Please try again in a few minutes." });
                return;
            }

            const raw = completion.choices[0]?.message?.content?.trim() || "";
            if (!raw) {
                res.status(500).json({ success: false, message: "AI returned an empty response." });
                return;
            }

            // Parse JSON from AI response (strip markdown fences if present)
            let parsed: any;
            try {
                let cleaned = raw
                    .replace(/^```(?:json)?\s*/i, "")
                    .replace(/\s*```$/i, "")
                    .replace(/[\x00-\x1F]/g, " ")
                    .trim();
                const braceStart = cleaned.indexOf("{");
                if (braceStart > 0) cleaned = cleaned.slice(braceStart);
                const braceEnd = cleaned.lastIndexOf("}");
                if (braceEnd > 0) cleaned = cleaned.slice(0, braceEnd + 1);
                parsed = JSON.parse(cleaned);
            } catch (parseErr: any) {
                console.error("[AI Blog Generator] Raw response:", raw);
                console.error("[AI Blog Generator] Parse error:", parseErr?.message);
                res.status(500).json({ success: false, message: "AI returned invalid content. Please try again." });
                return;
            }

            if (!parsed.title || !parsed.content) {
                res.status(500).json({ success: false, message: "AI response missing required fields." });
                return;
            }

            res.status(200).json({
                success: true,
                data: {
                    title: String(parsed.title),
                    content: String(parsed.content),
                    excerpt: String(parsed.excerpt || "").slice(0, 300),
                    tags: Array.isArray(parsed.tags) ? parsed.tags.slice(0, 5) : [],
                },
            });
        } catch (error: any) {
            console.error("[AI Blog Generator] Error:", error);
            res.status(500).json({ success: false, message: error.message || "Failed to generate blog content." });
        }
    },
);

// ============================================================
// IMGBB HELPER
// ============================================================

function detectMime(buffer: Buffer): string {
    if (buffer[0] === 0xff && buffer[1] === 0xd8) return "image/jpeg";
    if (buffer[0] === 0x89 && buffer[1] === 0x50) return "image/png";
    if (buffer[0] === 0x52 && buffer[1] === 0x49) return "image/webp";
    return "image/jpeg";
}

async function uploadToImgbb(
    buffer: Buffer,
    filename: string,
): Promise<string> {
    const mime = detectMime(buffer);
    const ext = mime === "image/png" ? ".png" : mime === "image/webp" ? ".webp" : ".jpg";
    const formData = new FormData();
    formData.append("image", new Blob([buffer], { type: mime }), `upload${ext}`);
    const res = await fetch(
        `https://api.imgbb.com/1/upload?key=${process.env.IMGBB_API_KEY}`,
        { method: "POST", body: formData },
    );
    const text = await res.text();
    let data: any;
    try {
        data = JSON.parse(text);
    } catch {
        throw new Error(`imgbb: ${text.slice(0, 300)}`);
    }
    if (!data.success || !data.data?.url) {
        throw new Error(data.error?.message || JSON.stringify(data));
    }
    return data.data.display_url || data.data.url;
}

// Fallback: save locally when imgbb fails (returns relative path, frontend proxies it)
async function saveFileLocally(
    buffer: Buffer,
    originalname: string,
): Promise<string> {
    const ext = path.extname(originalname) || ".jpg";
    const filename = `img_${Date.now()}_${Math.random().toString(36).slice(2, 8)}${ext}`;
    const filePath = path.join(UPLOAD_DIR, filename);
    fs.writeFileSync(filePath, buffer);
    return `/uploads/${filename}`;
}

// ============================================================
// IMAGE UPLOAD (imgbb proxy with local fallback)
// ============================================================

async function handleUpload(
    file: Express.Multer.File,
    res: Response,
): Promise<void> {
    const key = process.env.IMGBB_API_KEY;
    if (key) {
        try {
            const url = await uploadToImgbb(file.buffer, file.originalname);
            res.status(200).json({ success: true, data: { url } });
            return;
        } catch (err: any) {
            console.warn("[Upload] imgbb failed, falling back to local:", err.message);
        }
    }
    const url = await saveFileLocally(file.buffer, file.originalname);
    res.status(200).json({ success: true, data: { url } });
}

// Public endpoint — no auth required
app.post(
    "/api/upload/local",
    upload.single("image"),
    async (req: Request, res: Response): Promise<void> => {
        try {
            const file = req.file as Express.Multer.File | undefined;
            if (!file) {
                res.status(400).json({ success: false, message: "No file uploaded." });
                return;
            }
            await handleUpload(file, res);
        } catch (error: any) {
            console.error("[Upload] error:", error);
            res.status(500).json({ success: false, message: error.message || "Upload failed." });
        }
    },
);

app.post(
    "/api/blogs/upload-cover-local",
    verifyToken,
    upload.single("cover"),
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const file = req.file as Express.Multer.File | undefined;
            if (!file) {
                res.status(400).json({ success: false, message: "No file uploaded." });
                return;
            }
            await handleUpload(file, res);
        } catch (error: any) {
            console.error("[Blog] Cover upload error:", error);
            res.status(500).json({ success: false, message: error.message || "Failed to upload cover image." });
        }
    },
);

// ============================================================
// AI ROUTES
// ============================================================
registerAiRoutes(app, { getDb, verifyToken });

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
