"use client";

import { ClerkProvider } from "@clerk/nextjs";
import { ReactNode } from "react";

interface AuthProviderProps {
    children: ReactNode;
}

// Check if we're in development mode without valid Clerk keys
const isDevelopment = process.env.NODE_ENV === "development";
const publishableKey = process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY;
const hasValidKey = publishableKey && 
    !publishableKey.includes("your_clerk") && 
    publishableKey.startsWith("pk_");

const useMockAuth = isDevelopment && !hasValidKey;

export function AuthProvider({ children }: AuthProviderProps) {
    // In development without Clerk keys, render without ClerkProvider
    if (useMockAuth) {
        console.warn("[Auth] Running in development mode without Clerk authentication");
        return <>{children}</>;
    }

    // With valid Clerk key, use Clerk authentication
    return <ClerkProvider publishableKey={publishableKey}>{children}</ClerkProvider>;
}

export { useMockAuth };
