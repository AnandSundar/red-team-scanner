"use client";

import { ClerkProvider } from "@clerk/nextjs";
import { ReactNode } from "react";

interface AuthProviderProps {
    children: ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
    const publishableKey = process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY;
    const isDevelopment = process.env.NODE_ENV === "development";
    const hasValidKey = publishableKey && !publishableKey.includes("your_clerk");

    // In development without Clerk keys, render without authentication
    if (isDevelopment && !hasValidKey) {
        console.warn("[Auth] Running in development mode without Clerk authentication");
        return <>{children}</>;
    }

    // With valid Clerk key, use Clerk authentication
    return <ClerkProvider>{children}</ClerkProvider>;
}
