import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import dotenv from "dotenv";
import { MongoClient, ServerApiVersion, ObjectId } from "mongodb";
import bcrypt from "bcryptjs";

const { createRemoteJWKSet, jwtVerify } = require("jose-cjs");

dotenv.config();

const app = express();
const port: number = Number(process.env.PORT) || 5000;

app.use(
    cors({
        origin: process.env.FRONTEND_URL,
        credentials: true,
    }),
);
app.use(express.json());

const uri: string = process.env.MONGODB_URI || "";
const dbName: string = process.env.DB_NAME || "StayEase";

const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    },
});

interface AuthUser {
    _id: ObjectId;
    name: string;
    email: string;
    emailVerified: boolean;
    image?: string | null;
    role: string;
    createdAt: Date;
    updatedAt: Date;
}

interface AuthSession {
    _id: ObjectId;
    userId: string;
    token: string;
    expiresAt: Date;
    createdAt: Date;
    updatedAt: Date;
}

interface AuthAccount {
    _id: ObjectId;
    userId: string;
    accountId: string;
    providerId: string;
    password?: string;
    createdAt: Date;
    updatedAt: Date;
}

interface BetterAuthJwtPayload {
    sub: string;
    email?: string;
    name?: string;
    role?: string;
    sessionId?: string;
    iat?: number;
    exp?: number;
    [key: string]: unknown;
}

interface AuthRequest extends Request {
    user?: AuthUser;
    sessionToken?: string;
    jwtPayload?: BetterAuthJwtPayload;
}

function parseCookies(cookieStr: string): Record<string, string> {
    const result: Record<string, string> = {};
    cookieStr.split(";").forEach((item) => {
        const [key, ...val] = item.split("=");
        const name = key?.trim();
        const value = val.join("=").trim();
        if (name) {
            result[name] = decodeURIComponent(value);
        }
    });
    return result;
}

function checkPassword(pw: string): string | null {
    if (!pw) return "Password is required.";
    if (pw.length < 8) return "Password must be at least 8 characters.";
    if (!/[A-Z]/.test(pw)) return "Password must have at least one uppercase letter.";
    if (!/[0-9]/.test(pw)) return "Password must have at least one number.";
    return null;
}

// String userId ke ObjectId e convert kore user find kore
async function findUserById(usersCol: any, userId: string): Promise<AuthUser | null> {
    try {
        if (ObjectId.isValid(userId)) {
            const user = await usersCol.findOne({ _id: new ObjectId(userId) });
            if (user) return user;
        }
        return await usersCol.findOne({ _id: userId });
    } catch {
        return await usersCol.findOne({ _id: userId });
    }
}

const JWKS = createRemoteJWKSet(
    new URL(`${process.env.FRONTEND_URL}/api/auth/jwks`),
);

async function verifyBetterAuthJWT(
    token: string,
): Promise<BetterAuthJwtPayload | null> {
    try {
        const { payload } = await jwtVerify(token, JWKS);
        return payload as BetterAuthJwtPayload;
    } catch (error) {
        console.error("JWT verify failed:", error);
        return null;
    }
}

async function run(): Promise<void> {
    try {
        await client.connect();
        await client.db("admin").command({ ping: 1 });
        console.log("✅ Connected to MongoDB!");

        const db = client.db(dbName);

        const usersCol = db.collection<AuthUser>("user");
        const sessionsCol = db.collection<AuthSession>("session");
        const accountsCol = db.collection<AuthAccount>("account");
        const propertiesCol = db.collection("properties");
        const bookingsCol = db.collection("bookings");

        console.log(`📦 Database: ${db.databaseName}`);
        console.log(`📂 Collections ready`);

        const verifyAuth = async (
            req: AuthRequest,
            res: Response,
            next: NextFunction,
        ): Promise<void> => {
            try {
                const authHeader = req.headers.authorization;

                if (authHeader && authHeader.startsWith("Bearer ")) {
                    const jwtToken = authHeader.slice(7).trim();
                    const payload = await verifyBetterAuthJWT(jwtToken);

                    if (!payload) {
                        res.status(401).json({
                            success: false,
                            message: "Invalid or expired JWT. Please login again.",
                        });
                        return;
                    }

                    const userId = payload.sub;

                    if (!userId) {
                        res.status(401).json({
                            success: false,
                            message: "Invalid JWT payload.",
                        });
                        return;
                    }

                    // String ID ke ObjectId e convert kore find korte hobe
                    const user = await findUserById(usersCol, userId);

                    if (!user) {
                        res.status(401).json({
                            success: false,
                            message: "User not found.",
                        });
                        return;
                    }

                    req.user = user;
                    req.jwtPayload = payload;
                    next();
                    return;
                }

                let sessionToken: string | null = null;

                if (req.headers.cookie) {
                    const cookies = parseCookies(req.headers.cookie);
                    sessionToken = cookies["better-auth.session_token"] || null;
                }

                if (!sessionToken) {
                    res.status(401).json({
                        success: false,
                        message: "Login required.",
                    });
                    return;
                }

                const session = await sessionsCol.findOne({ token: sessionToken });

                if (!session) {
                    res.status(401).json({
                        success: false,
                        message: "Invalid session. Please login again.",
                    });
                    return;
                }

                if (new Date(session.expiresAt) < new Date()) {
                    res.status(401).json({
                        success: false,
                        message: "Session expired. Please login again.",
                    });
                    return;
                }

                // Session userId diye ObjectId convert kore find
                const user = await findUserById(usersCol, session.userId);

                if (!user) {
                    res.status(401).json({
                        success: false,
                        message: "User not found.",
                    });
                    return;
                }

                req.user = user;
                req.sessionToken = sessionToken;
                next();
            } catch (error) {
                console.error("Auth middleware error:", error);
                res.status(500).json({
                    success: false,
                    message: "Authentication failed.",
                });
            }
        };

        
        const verifyAdmin = async (
            req: AuthRequest,
            res: Response,
            next: NextFunction,
        ): Promise<void> => {
            try {
                // First run auth
                await new Promise<void>((resolve, reject) => {
                    verifyAuth(req, res, (err?: any) => {
                        if (err) reject(err);
                        else resolve();
                    });
                });

                if (!req.user) {
                    res.status(401).json({
                        success: false,
                        message: "Authentication required.",
                    });
                    return;
                }

                if (req.user.role !== "admin") {
                    res.status(403).json({
                        success: false,
                        message: "Access denied. Admin privileges required.",
                    });
                    return;
                }

                next();
            } catch (error) {
                console.error("Admin middleware error:", error);
                res.status(500).json({
                    success: false,
                    message: "Authorization failed.",
                });
            }
        };


        app.get(
            "/api/users/profile",
            verifyAuth,
            async (req: AuthRequest, res: Response): Promise<void> => {
                try {
                    const user = req.user!;

                    res.status(200).json({
                        success: true,
                        message: "Profile fetched.",
                        data: {
                            id: user._id.toString(),
                            name: user.name,
                            email: user.email,
                            emailVerified: user.emailVerified,
                            image: user.image || null,
                            role: user.role,
                            createdAt: user.createdAt,
                            updatedAt: user.updatedAt,
                        },
                    });
                } catch (error) {
                    console.error("Get profile error:", error);
                    res.status(500).json({
                        success: false,
                        message: "Failed to get profile.",
                    });
                }
            },
        );

        app.put(
            "/api/users/profile",
            verifyAuth,
            async (req: AuthRequest, res: Response): Promise<void> => {
                try {
                    const user = req.user!;
                    const { name, image } = req.body;
                    const updates: Record<string, unknown> = {};

                    if (name !== undefined) {
                        const trimmed = String(name).trim();
                        if (!trimmed) { res.status(400).json({ success: false, message: "Name cannot be empty." }); return; }
                        if (trimmed.length < 3) { res.status(400).json({ success: false, message: "Name must be at least 3 characters." }); return; }
                        if (trimmed.length > 100) { res.status(400).json({ success: false, message: "Name cannot exceed 100 characters." }); return; }
                        updates.name = trimmed;
                    }

                    if (image !== undefined) updates.image = image || null;

                    if (Object.keys(updates).length === 0) {
                        res.status(400).json({ success: false, message: "Nothing to update." });
                        return;
                    }

                    updates.updatedAt = new Date();

                    await usersCol.updateOne(
                        { _id: user._id },
                        { $set: updates }
                    );

                    const updated = await usersCol.findOne({ _id: user._id });

                    res.status(200).json({
                        success: true,
                        message: "Profile updated.",
                        data: {
                            id: updated!._id.toString(),
                            name: updated!.name,
                            email: updated!.email,
                            emailVerified: updated!.emailVerified,
                            image: updated!.image || null,
                            role: updated!.role,
                            createdAt: updated!.createdAt,
                            updatedAt: updated!.updatedAt,
                        },
                    });
                } catch (error) {
                    console.error("Update profile error:", error);
                    res.status(500).json({ success: false, message: "Failed to update profile." });
                }
            },
        );

        app.put(
            "/api/users/profile-image",
            verifyAuth,
            async (req: AuthRequest, res: Response): Promise<void> => {
                try {
                    const user = req.user!;
                    const { imageUrl } = req.body;

                    if (!imageUrl || typeof imageUrl !== "string") {
                        res.status(400).json({ success: false, message: "Valid image URL required." });
                        return;
                    }

                    try { new URL(imageUrl); } catch {
                        res.status(400).json({ success: false, message: "Invalid URL format." });
                        return;
                    }

                    await usersCol.updateOne(
                        { _id: user._id },
                        { $set: { image: imageUrl, updatedAt: new Date() } }
                    );

                    res.status(200).json({
                        success: true,
                        message: "Profile image updated.",
                        data: { image: imageUrl },
                    });
                } catch (error) {
                    console.error("Update image error:", error);
                    res.status(500).json({ success: false, message: "Failed to update image." });
                }
            },
        );

        app.put(
            "/api/users/change-password",
            verifyAuth,
            async (req: AuthRequest, res: Response): Promise<void> => {
                try {
                    const user = req.user!;
                    const { currentPassword, newPassword, confirmNewPassword } = req.body;

                    if (!currentPassword) { res.status(400).json({ success: false, message: "Current password required." }); return; }
                    if (!newPassword) { res.status(400).json({ success: false, message: "New password required." }); return; }
                    if (!confirmNewPassword) { res.status(400).json({ success: false, message: "Confirm new password required." }); return; }
                    if (newPassword !== confirmNewPassword) { res.status(400).json({ success: false, message: "New passwords do not match." }); return; }
                    if (currentPassword === newPassword) { res.status(400).json({ success: false, message: "New password must be different." }); return; }

                    const pwError = checkPassword(newPassword);
                    if (pwError) { res.status(400).json({ success: false, message: pwError }); return; }

                    // userId string hisebe account collection e store thake
                    const userId = user._id.toString();

                    const account = await accountsCol.findOne({
                        userId: userId,
                        providerId: "credential",
                    });

                    if (!account || !account.password) {
                        res.status(400).json({ success: false, message: "No password account found." });
                        return;
                    }

                    const isMatch = await bcrypt.compare(currentPassword, account.password);
                    if (!isMatch) { res.status(400).json({ success: false, message: "Current password is wrong." }); return; }

                    const hashed = await bcrypt.hash(newPassword, 10);

                    await accountsCol.updateOne(
                        { userId: userId, providerId: "credential" },
                        { $set: { password: hashed, updatedAt: new Date() } }
                    );

                    if (req.sessionToken) {
                        await sessionsCol.deleteMany({
                            userId: userId,
                            token: { $ne: req.sessionToken },
                        });
                    }

                    res.status(200).json({
                        success: true,
                        message: "Password changed. Other sessions logged out.",
                    });
                } catch (error) {
                    console.error("Change password error:", error);
                    res.status(500).json({ success: false, message: "Failed to change password." });
                }
            },
        );

        app.delete(
            "/api/users/account",
            verifyAuth,
            async (req: AuthRequest, res: Response): Promise<void> => {
                try {
                    const user = req.user!;
                    const { password } = req.body;

                    if (!password) { res.status(400).json({ success: false, message: "Password required to delete account." }); return; }
                    if (user.role === "admin") { res.status(403).json({ success: false, message: "Admin cannot self-delete." }); return; }

                    const userId = user._id.toString();

                    const account = await accountsCol.findOne({
                        userId: userId,
                        providerId: "credential",
                    });

                    if (!account || !account.password) {
                        res.status(400).json({ success: false, message: "No password account found." });
                        return;
                    }

                    const isMatch = await bcrypt.compare(password, account.password);
                    if (!isMatch) { res.status(400).json({ success: false, message: "Wrong password. Deletion cancelled." }); return; }

                    const bookingFilter = user.role === "host"
                        ? { hostId: userId }
                        : { guestId: userId };

                    const activeCount = await bookingsCol.countDocuments({
                        ...bookingFilter,
                        status: { $in: ["confirmed", "pending", "checked-in"] },
                    });

                    if (activeCount > 0) {
                        res.status(400).json({
                            success: false,
                            message: `You have ${activeCount} active booking(s). Resolve them first.`,
                        });
                        return;
                    }

                    await sessionsCol.deleteMany({ userId: userId });
                    await accountsCol.deleteMany({ userId: userId });

                    if (user.role === "host") {
                        await propertiesCol.updateMany(
                            { hostId: userId },
                            { $set: { status: "deleted", deletedAt: new Date() } }
                        );
                    }

                    await usersCol.deleteOne({ _id: user._id });

                    res.status(200).json({
                        success: true,
                        message: "Account permanently deleted.",
                    });
                } catch (error) {
                    console.error("Delete account error:", error);
                    res.status(500).json({ success: false, message: "Failed to delete account." });
                }
            },
        );

        

    } catch (error) {
        console.error("❌ MongoDB connection error:", error);
    }
}

run().catch(console.dir);

app.get("/", (req: Request, res: Response) => {
    res.send("🏡 StayEase Server is Running!");
});

app.listen(port, () => {
    console.log(`🚀 Server running on port ${port}`);
});