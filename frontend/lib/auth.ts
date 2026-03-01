import { auth } from "@clerk/nextjs";

export async function getAuthToken(): Promise<string | null> {
    const { getToken } = auth();
    return getToken();
}

export function isAuthenticated(): boolean {
    const { userId } = auth();
    return !!userId;
}
