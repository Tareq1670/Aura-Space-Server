import { Request, Response } from "express";
import { ObjectId } from "mongodb";
import Groq from "groq-sdk";

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

interface AuthReq extends Request {
    user?: {
        _id: ObjectId;
        name: string;
        email: string;
        role: string;
        image?: string | null;
    };
}

function handleGroqError(error: any, res: Response): boolean {
    if (error?.status === 429 || error?.message?.includes("rate limit")) {
        res.status(429).json({
            success: false,
            message: "AI service is experiencing high demand. Please try again in a few minutes.",
        });
        return true;
    }
    return false;
}

export function registerAiRoutes(
    app: any,
    deps: {
        getDb: () => Promise<any>;
        verifyToken: (req: any, res: any, next: any) => Promise<void>;
    },
) {
    const { getDb, verifyToken } = deps;

    // ============================================================
    // GET /api/ai/recommendations
    // ============================================================
    app.get(
        "/api/ai/recommendations",
        verifyToken,
        async (req: AuthReq, res: Response): Promise<void> => {
            try {
                const groq = getGroq();
                if (!groq) {
                    res.status(503).json({ success: false, message: "AI service not configured." });
                    return;
                }

                const userId = req.user!._id.toString();
                const db = await getDb();
                const usersCol = db.collection("user");
                const bookingsCol = db.collection("bookings");
                const wishlistCol = db.collection("wishlist");
                const reviewsCol = db.collection("reviews");
                const propertiesCol = db.collection("properties");

                const { location, budget, guests, propertyType } = req.query as Record<string, string | undefined>;

                // Fetch user context
                const bookings = await bookingsCol
                    .find({ guestId: userId, status: { $in: ["confirmed", "completed"] } })
                    .sort({ createdAt: -1 })
                    .limit(10)
                    .toArray();

                const wishlistItems = await wishlistCol
                    .find({ userId })
                    .sort({ createdAt: -1 })
                    .limit(20)
                    .toArray();

                const reviews = await reviewsCol
                    .find({ guestId: userId })
                    .sort({ createdAt: -1 })
                    .limit(10)
                    .toArray();

                // Fetch available properties
                const filter: Record<string, any> = { status: "active" };
                if (location) filter["location.city"] = { $regex: location, $options: "i" };
                if (propertyType) filter.category = propertyType.toLowerCase();
                if (guests) filter["details.maxGuests"] = { $gte: parseInt(guests) };
                if (budget) filter["price.perNight"] = { $lte: parseFloat(budget) };

                const properties = await propertiesCol
                    .find(filter)
                    .sort({ rating: -1, reviewCount: -1 })
                    .limit(30)
                    .toArray();

                if (properties.length === 0) {
                    res.status(200).json({
                        success: true,
                        data: { recommendations: [], message: "No properties found matching your criteria." },
                    });
                    return;
                }

                // Build prompt
                const propertyList = properties.map((p: any) => ({
                    propertyId: p._id.toString(),
                    title: p.title,
                    category: p.category,
                    city: p.location?.city,
                    country: p.location?.country,
                    pricePerNight: p.price?.perNight,
                    currency: p.price?.currency || "BDT",
                    maxGuests: p.details?.maxGuests,
                    bedrooms: p.details?.bedrooms,
                    bathrooms: p.details?.bathrooms,
                    amenities: p.amenities || [],
                    rating: p.rating || 0,
                    reviewCount: p.reviewCount || 0,
                }));

                const userContext = {
                    previousBookings: bookings.map((b: any) => ({
                        propertyTitle: b.propertyTitle,
                        city: b.city || "Unknown",
                        status: b.status,
                    })),
                    wishlistProperties: wishlistItems.map((w: any) => w.propertyId),
                    pastReviews: reviews.map((r: any) => ({
                        rating: r.rating,
                        propertyId: r.propertyId,
                    })),
                };

                const systemPrompt = `You are a property recommendation AI for StayEase (AuraSpace). 
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

Respond with ONLY a valid JSON array (no markdown, no code blocks):
[{"propertyId":"...","title":"...","reason":"..."}]`;

                let completion;
                try {
                    completion = await groq.chat.completions.create({
                        messages: [
                            { role: "system", content: systemPrompt },
                            { role: "user", content: "Recommend the best properties based on my preferences and history." },
                        ],
                        model: AI_MODEL,
                        temperature: 0.4,
                        max_tokens: 2048,
                    });
                } catch (groqError: any) {
                    if (handleGroqError(groqError, res)) return;
                    throw groqError;
                }

                const raw = completion.choices[0]?.message?.content || "[]";
                let recommendations: any[];
                try {
                    const cleaned = raw.replace(/```json\s*/gi, "").replace(/```\s*/g, "").trim();
                    recommendations = JSON.parse(cleaned);
                    if (!Array.isArray(recommendations)) recommendations = [];
                } catch {
                    recommendations = [];
                }

                // Enrich with full property data
                const enriched = recommendations.slice(0, 10).map((r: any) => {
                    const prop = properties.find((p: any) => p._id.toString() === r.propertyId);
                    if (!prop) return null;
                    return {
                        propertyId: r.propertyId,
                        title: prop.title,
                        reason: r.reason || "Matches your preferences",
                        matchScore: r.matchScore || 85,
                        images: prop.images?.[0] || "",
                        pricePerNight: prop.price?.perNight,
                        currency: prop.price?.currency || "BDT",
                        location: prop.location,
                        rating: prop.rating,
                        reviewCount: prop.reviewCount,
                        category: prop.category,
                        details: prop.details,
                    };
                }).filter(Boolean);

                res.status(200).json({
                    success: true,
                    data: { recommendations: enriched },
                });
            } catch (error: any) {
                console.error("[AI Recommendations] Error:", error);
                res.status(500).json({
                    success: false,
                    message: error.message || "Failed to generate recommendations.",
                });
            }
        },
    );

    // ============================================================
    // POST /api/ai/chat — works with or without auth; saves history only when logged in
    // ============================================================
    app.post(
        "/api/ai/chat",
        async (req: AuthReq, res: Response): Promise<void> => {
            try {
                const groq = getGroq();
                if (!groq) {
                    res.status(503).json({ success: false, message: "AI service not configured." });
                    return;
                }

                let userId: string | null = null;
                let userName = "Guest";
                let userRole = "guest";
                const authHeader = req.headers.authorization;
                if (authHeader?.startsWith("Bearer ")) {
                    try {
                        const token = authHeader.substring(7).trim();
                        if (token) {
                            const { jwtVerify } = await import("jose-cjs");
                            const { payload } = await jwtVerify(token, getGroq() as any);
                            const jwtPayload = payload as any;
                            if (jwtPayload.sub) {
                                const db = await getDb();
                                const user = await db.collection("user").findOne({ _id: new ObjectId(jwtPayload.sub) });
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

                const systemPrompt = `You are a helpful AI assistant for StayEase (AuraSpace), a property rental platform. 
You help users find properties, with booking guidance, and platform navigation.

RULES:
- Keep responses concise (2-4 sentences).
- If the user asks about finding properties, ask about their location, budget, guests, and preferences.
- For navigation questions, give clear step-by-step instructions.
- Be friendly, professional, and helpful.
- If you don't know something, say so honestly.

USER CONTEXT:
- Name: ${userName}
- Role: ${userRole}${userId ? `\n- Authenticated: Yes` : `\n- Authenticated: No (guest mode — no history saved)`}`;

                const messages = [
                    { role: "system", content: systemPrompt } as const,
                    ...conversationHistory.slice(-20).map((m) => ({
                        role: m.role as "user" | "assistant",
                        content: m.content,
                    })),
                    { role: "user" as const, content: message },
                ];

                let completion;
                try {
                    completion = await groq.chat.completions.create({
                        messages, model: AI_MODEL, temperature: 0.6, max_tokens: 1024,
                    });
                } catch (groqError: any) {
                    if (handleGroqError(groqError, res)) return;
                    throw groqError;
                }

                const reply = completion.choices[0]?.message?.content || "I'm sorry, I couldn't generate a response.";

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
                                        { role: "user", content: message, createdAt: now },
                                        { role: "assistant", content: reply, createdAt: now },
                                    ],
                                },
                            },
                            $set: { updatedAt: now },
                        },
                    );
                }

                const suggestions = generateSuggestions(message, reply);

                res.status(200).json({
                    success: true,
                    data: { reply, conversationId: conversationIdOut, suggestions },
                });
            } catch (error: any) {
                console.error("[AI Chat] Error:", error);
                if (handleGroqError(error, res)) return;
                res.status(500).json({ success: false, message: error.message || "Failed to process chat message." });
            }
        },
    );

    // ============================================================
    // POST /api/ai/chat/stream
    // ============================================================
    app.post(
        "/api/ai/chat/stream",
        verifyToken,
        async (req: AuthReq, res: Response): Promise<void> => {
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
                    conversation = {
                        userId,
                        messages: [],
                        createdAt: new Date(),
                        updatedAt: new Date(),
                    };
                    const result = await aiConvoCol.insertOne(conversation);
                    conversation._id = result.insertedId;
                }

                const bookingCount = await bookingsCol.countDocuments({ guestId: userId });

                const systemPrompt = `You are a helpful AI assistant for StayEase (AuraSpace), a property rental platform.
Keep responses concise (2-4 sentences).
Be friendly and professional.

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

                // SSE setup
                res.setHeader("Content-Type", "text/event-stream");
                res.setHeader("Cache-Control", "no-cache");
                res.setHeader("Connection", "keep-alive");
                res.setHeader("X-Accel-Buffering", "no");

                let stream;
                try {
                    stream = await groq.chat.completions.create({
                        messages,
                        model: AI_MODEL,
                        temperature: 0.6,
                        max_tokens: 1024,
                        stream: true,
                    });
                } catch (groqError: any) {
                    if (handleGroqError(groqError, res)) return;
                    throw groqError;
                }

                let fullReply = "";

                for await (const chunk of stream) {
                    const content = chunk.choices[0]?.delta?.content || "";
                    if (content) {
                        fullReply += content;
                        res.write(`data: ${JSON.stringify({ content })}\n\n`);
                    }
                }

                // Save to DB
                const now = new Date();
                await aiConvoCol.updateOne(
                    { _id: conversation._id },
                    {
                        $push: {
                            messages: {
                                $each: [
                                    { role: "user", content: message, createdAt: now },
                                    { role: "assistant", content: fullReply, createdAt: now },
                                ],
                            },
                        },
                        $set: { updatedAt: now },
                    },
                );

                const suggestions = generateSuggestions(message, fullReply);
                res.write(`data: ${JSON.stringify({ done: true, conversationId: conversation._id!.toString(), suggestions })}\n\n`);
                res.end();
            } catch (error: any) {
                console.error("[AI Chat Stream] Error:", error);
                if (!res.headersSent) {
                    if (handleGroqError(error, res)) return;
                    res.status(500).json({ success: false, message: error.message || "Stream failed." });
                } else {
                    res.write(`data: ${JSON.stringify({ error: error.message })}\n\n`);
                    res.end();
                }
            }
        },
    );

    // ============================================================
    // GET /api/ai/chat/history
    // ============================================================
    app.get(
        "/api/ai/chat/history",
        verifyToken,
        async (req: AuthReq, res: Response): Promise<void> => {
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

                // List all conversations for user
                const conversations = await aiConvoCol
                    .find({ userId })
                    .project({ _id: 1, messages: { $slice: -1 }, createdAt: 1, updatedAt: 1 })
                    .sort({ updatedAt: -1 })
                    .limit(50)
                    .toArray();

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

    // ============================================================
    // DELETE /api/ai/chat/:conversationId
    // ============================================================
    app.delete(
        "/api/ai/chat/:conversationId",
        verifyToken,
        async (req: AuthReq, res: Response): Promise<void> => {
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

    // ============================================================
    // POST /api/ai/generate-description
    // ============================================================
    app.post(
        "/api/ai/generate-description",
        verifyToken,
        async (req: AuthReq, res: Response): Promise<void> => {
            try {
                const groq = getGroq();
                if (!groq) {
                    res.status(503).json({ success: false, message: "AI service not configured." });
                    return;
                }

                const {
                    title,
                    propertyType,
                    placeType,
                    city,
                    country,
                    bedrooms,
                    bathrooms,
                    guests,
                    beds,
                    amenities,
                    tone = "professional",
                    length = "medium",
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

                let completion;
                try {
                    completion = await groq.chat.completions.create({
                        messages: [
                            { role: "system", content: "You are a professional copywriter specializing in property listings. Write engaging, accurate descriptions that highlight key features." },
                            { role: "user", content: prompt },
                        ],
                        model: AI_MODEL,
                        temperature: 0.7,
                        max_tokens: 1024,
                    });
                } catch (groqError: any) {
                    if (handleGroqError(groqError, res)) return;
                    throw groqError;
                }

                const description = completion.choices[0]?.message?.content?.trim() || "";

                res.status(200).json({ success: true, data: { description } });
            } catch (error: any) {
                console.error("[AI Description] Error:", error);
                res.status(500).json({
                    success: false,
                    message: error.message || "Failed to generate description.",
                });
            }
        },
    );
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
