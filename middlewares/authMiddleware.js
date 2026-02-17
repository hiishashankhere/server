import { clerkClient } from "@clerk/express";
import prisma from "../configs/prisma.js";

export const protect = async (req, res, next) => {
    try {
        const authData = req.auth;
        if (!authData) {
            console.log("Protect Middleware - No authData found (req.auth is undefined)");
            return res.status(401).json({ message: "Unauthorized: No Auth Data" });
        }
        const { userId, has } = authData;
        console.log("Protect Middleware - AuthData:", { userId, hasPremium: has({ plan: 'premium' }) });

        if (!userId) {
            console.log("Protect Middleware - No UserId found");
            return res.status(401).json({ message: "Unauthorized: No User ID" });
        }

        // Lazy Sync: Check if user exists in DB, if not create it
        const user = await prisma.user.findUnique({
            where: { id: userId },
        });

        if (!user) {
            console.log("Protect Middleware - User not in DB, fetching from Clerk...");
            try {
                const clerkUser = await clerkClient.users.getUser(userId);
                console.log("Protect Middleware - Clerk User fetched:", clerkUser.id);

                await prisma.user.create({
                    data: {
                        id: userId,
                        email: clerkUser.emailAddresses[0].emailAddress,
                        name: (clerkUser.firstName || "") + " " + (clerkUser.lastName || ""),
                        image: clerkUser.imageUrl,
                    },
                });
                console.log("Protect Middleware - User created in DB");
            } catch (clerkError) {
                console.error("Protect Middleware - Clerk/DB Error:", clerkError);
                // Don't block the request if user sync fails. 
                // The controller has its own fallback logic now.
            }
        }

        const hasPremiumPlan = has({ plan: 'premium' });
        req.plan = hasPremiumPlan ? 'premium' : 'free';

        return next();
    } catch (error) {
        console.error("Protect Middleware - Final Catch:", error);
        res.status(401).json({ message: `Auth Error: ${error.message}`, code: error.code });
    }
};

export const protectAdmin = async (req, res, next) => {
    try {
        const user = await clerkClient.users.getUser(req.auth.userId);

        const isAdmin = process.env.ADMIN_EMAILS.split(",").includes(user.emailAddresses[0].emailAddress);

        if (!isAdmin) {
            return res.status(401).json({ message: "Unauthorized" });
        }

        return next();
    } catch (error) {
        console.error("Protect Middleware - Final Catch:", error);
        res.status(401).json({ message: `Auth Error: ${error.message}`, code: error.code });
    }
};
