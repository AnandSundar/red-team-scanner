"use client";

import { useUser as useClerkUser, UserButton, SignInButton } from "@clerk/nextjs";

const isDevelopment = process.env.NODE_ENV === "development";
const hasClerkKey = process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY &&
    !process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY.includes("your_clerk");

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
    if (isDevelopment && !hasClerkKey) {
        return {
            isSignedIn: true,
            isLoaded: true,
            user: mockUser,
        };
    }

    // Otherwise use Clerk
    return useClerkUser();
}

export { UserButton, SignInButton };
