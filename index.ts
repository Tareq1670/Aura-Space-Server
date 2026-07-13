import express, { Request, Response, NextFunction } from "express";
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

dotenv.config();

const app = express();

app.use(
    cors({
        origin: process.env.FRONTEND_URL || "http://localhost:3000",
        credentials: true,
        methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization"],
    }),
);
app.use(express.json());

const uri: string = process.env.MONGODB_URI || "";
const dbName: string = process.env.DB_NAME || "StayEase";
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:3000";

if (!uri) {
    throw new Error("MONGODB_URI environment variable is not set");
}

let clientPromise: Promise<MongoClient>;

const globalWithMongo = global as typeof globalThis & {
    _mongoClientPromise?: Promise<MongoClient>;
};

if (!globalWithMongo._mongoClientPromise) {
    const client = new MongoClient(uri, {
        serverApi: {
            version: ServerApiVersion.v1,
            strict: true,
            deprecationErrors: true,
        },
    });
    globalWithMongo._mongoClientPromise = client.connect();
}
clientPromise = globalWithMongo._mongoClientPromise;

async function getDb() {
    const c = await clientPromise;
    return c.db(dbName);
}

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

interface AuthRequest extends Request {
    user?: AuthUser;
    jwtPayload?: JwtPayload;
}

const JWKS = createRemoteJWKSet(new URL(`${FRONTEND_URL}/api/auth/jwks`));

function userIdFilter(id: ObjectId): Filter<Document> {
    return { _id: id } as Filter<Document>;
}

function toIdString(id: ObjectId): string {
    return id.toString();
}

async function findUserById(
    usersCol: any,
    userId: string,
): Promise<AuthUser | null> {
    if (ObjectId.isValid(userId) && userId.length === 24) {
        try {
            const user = await usersCol.findOne({
                _id: new ObjectId(userId),
            } as Filter<Document>);
            if (user) return user as unknown as AuthUser;
        } catch {}
    }

    try {
        const user = await usersCol.findOne({
            _id: userId as unknown as ObjectId,
        } as Filter<Document>);
        if (user) return user as unknown as AuthUser;
    } catch {}

    return null;
}

function checkPassword(pw: string): string | null {
    if (!pw) return "Password is required.";
    if (pw.length < 8) return "Password must be at least 8 characters.";
    if (!/[A-Z]/.test(pw))
        return "Password must have at least one uppercase letter.";
    if (!/[0-9]/.test(pw)) return "Password must have at least one number.";
    return null;
}

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
        res.status(401).json({
            success: false,
            message: "Token is required.",
        });
        return;
    }

    try {
        const { payload } = await jwtVerify(token, JWKS);
        const jwtPayload = payload as JwtPayload;

        if (!jwtPayload.sub) {
            res.status(401).json({
                success: false,
                message: "Invalid token payload.",
            });
            return;
        }

        const db = await getDb();
        const usersCol = db.collection("user");

        const user = await findUserById(usersCol, jwtPayload.sub);

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
                message:
                    user.banReason || "Your account has been suspended.",
            });
            return;
        }

        req.user = user;
        req.jwtPayload = jwtPayload;
        next();
    } catch (error) {
        console.error("[verifyToken] JWT error:", error);
        res.status(401).json({
            success: false,
            message: "Invalid or expired token. Please login again.",
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
            message: "Access denied. Admin privileges required.",
        });
        return;
    }
    next();
};

app.get("/", (_req: Request, res: Response) => {
    res.send("🏡 StayEase Server is Running!");
});

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
            await usersCol.updateOne(userIdFilter(user._id), {
                $set: updates,
            });
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
        } catch (error) {
            console.error("Update profile error:", error);
            res.status(500).json({
                success: false,
                message: "Failed to update profile.",
            });
        }
    },
);

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
            const usersCol = db.collection("user");

            await usersCol.updateOne(userIdFilter(user._id), {
                $set: { image: imageUrl, updatedAt: new Date() },
            });

            res.status(200).json({
                success: true,
                message: "Profile image updated.",
                data: { image: imageUrl },
            });
        } catch (error) {
            console.error("Update image error:", error);
            res.status(500).json({
                success: false,
                message: "Failed to update image.",
            });
        }
    },
);

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
                    message: "Confirm new password required.",
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
                res.status(400).json({
                    success: false,
                    message: pwError,
                });
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
        } catch (error) {
            console.error("Change password error:", error);
            res.status(500).json({
                success: false,
                message: "Failed to change password.",
            });
        }
    },
);

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
                user.role === "host"
                    ? { hostId: userId }
                    : { guestId: userId };
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

            if (user.role === "host") {
                await propertiesCol.updateMany(
                    { hostId: userId },
                    {
                        $set: {
                            status: "deleted",
                            deletedAt: new Date(),
                        },
                    },
                );
            }

            await usersCol.deleteOne(userIdFilter(user._id));
            res.status(200).json({
                success: true,
                message: "Account permanently deleted.",
            });
        } catch (error) {
            console.error("Delete account error:", error);
            res.status(500).json({
                success: false,
                message: "Failed to delete account.",
            });
        }
    },
);

app.get(
    "/api/admin/users",
    verifyToken,
    verifyAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const db = await getDb();
            const usersCol = db.collection("user");

            const users = await usersCol
                .find({})
                .sort({ createdAt: -1 })
                .toArray();

            const currentUserId = toIdString(req.user!._id);

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

            res.status(200).json({
                success: true,
                data: {
                    users: safeUsers,
                    currentUserId,
                    stats: {
                        total: safeUsers.length,
                        admins: safeUsers.filter((u) => u.role === "admin")
                            .length,
                        hosts: safeUsers.filter((u) => u.role === "host")
                            .length,
                        guests: safeUsers.filter((u) => u.role === "guest")
                            .length,
                        banned: safeUsers.filter((u) => u.banned).length,
                    },
                },
            });
        } catch (error) {
            console.error("Admin get users error:", error);
            res.status(500).json({
                success: false,
                message: "Failed to fetch users.",
            });
        }
    },
);

app.get(
    "/api/admin/users/:id",
    verifyToken,
    verifyAdmin,
    async (req: AuthRequest, res: Response): Promise<void> => {
        try {
            const db = await getDb();
            const usersCol = db.collection("user");

            const user = await findUserById(usersCol, String(req.params.id));
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
        } catch (error) {
            console.error("Admin get user error:", error);
            res.status(500).json({
                success: false,
                message: "Failed to fetch user.",
            });
        }
    },
);

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
                    message: `Invalid role. Must be one of: ${validRoles.join(", ")}`,
                });
                return;
            }

            const db = await getDb();
            const usersCol = db.collection("user");

            const user = await findUserById(usersCol, String(req.params.id));
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
                message: `Role updated to "${role}" successfully.`,
                data: {
                    id: targetUserId,
                    name: user.name,
                    email: user.email,
                    role,
                },
            });
        } catch (error) {
            console.error("Admin update role error:", error);
            res.status(500).json({
                success: false,
                message: "Failed to update role.",
            });
        }
    },
);

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
                    message: "banned must be a boolean.",
                });
                return;
            }

            const db = await getDb();
            const usersCol = db.collection("user");
            const sessionsCol = db.collection("session");

            const user = await findUserById(usersCol, String(req.params.id));
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
                    message: "Cannot block/unblock yourself.",
                });
                return;
            }
            if (user.role === "admin") {
                res.status(400).json({
                    success: false,
                    message: "Cannot block an admin user.",
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
                message: banned
                    ? "User has been blocked."
                    : "User has been unblocked.",
                data: {
                    id: targetUserId,
                    name: user.name,
                    email: user.email,
                    banned,
                    banReason: banned
                        ? banReason || "Blocked by admin"
                        : null,
                },
            });
        } catch (error) {
            console.error("Admin update status error:", error);
            res.status(500).json({
                success: false,
                message: "Failed to update user status.",
            });
        }
    },
);

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

            const user = await findUserById(usersCol, String(req.params.id));
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
                    message: `User has ${activeBookings} active booking(s). Cannot delete.`,
                });
                return;
            }

            await sessionsCol.deleteMany({ userId: targetUserId });
            await accountsCol.deleteMany({ userId: targetUserId });

            if (user.role === "host") {
                await propertiesCol.updateMany(
                    { hostId: targetUserId },
                    {
                        $set: {
                            status: "deleted",
                            deletedAt: new Date(),
                        },
                    },
                );
            }

            await usersCol.deleteOne(userIdFilter(user._id));

            res.status(200).json({
                success: true,
                message: `User "${user.name}" has been permanently deleted.`,
            });
        } catch (error) {
            console.error("Admin delete user error:", error);
            res.status(500).json({
                success: false,
                message: "Failed to delete user.",
            });
        }
    },
);

// Local development এর জন্য
if (process.env.NODE_ENV !== "production") {
    const port = Number(process.env.PORT) || 5000;
    app.listen(port, () => {
        console.log(`🚀 Server running locally on port ${port}`);
    });
}

// Vercel এর জন্য এই export টা দরকার
export default app;