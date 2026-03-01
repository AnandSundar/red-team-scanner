"use client";

import { useUser as useClerkUser } from "@clerk/nextjs";

// Check if we're in development mode without valid Clerk keys
const isDevelopment = process.env.NODE_ENV === "development";
const publishableKey = process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY;
const hasValidKey = publishableKey &&
    !publishableKey.includes("your_clerk") &&
    publishableKey.startsWith("pk_");

export const useMockAuth = isDevelopment && !hasValidKey;

// Mock user for development without Clerk
const mockUser = {
    id: "dev-user-001",
    emailAddresses: [{ emailAddress: "dev@localhost" }],
    firstName: "Developer",
    lastName: "Mode",
    imageUrl: null,
};

export function useUser() {
    // If in development without Clerk, return mock user
    if (useMockAuth) {
        return {
            isSignedIn: true,
            isLoaded: true,
            user: mockUser,
        };
    }

    // Otherwise use Clerk
    return useClerkUser();
}
