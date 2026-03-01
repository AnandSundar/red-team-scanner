import { Scan, Report, Module } from "@/types";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080";

async function fetchAPI<T>(path: string, options?: RequestInit): Promise<T> {
    const response = await fetch(`${API_BASE}${path}`, {
        ...options,
        headers: {
            "Content-Type": "application/json",
            ...options?.headers,
        },
    });

    if (!response.ok) {
        throw new Error(`API error: ${response.statusText}`);
    }

    return response.json();
}

export const api = {
    scans: {
        list: () => fetchAPI<Scan[]>("/api/v1/scans"),
        get: (id: string) => fetchAPI<Scan>(`/api/v1/scans/${id}`),
        create: (data: { target: string; modules: string[]; depth: number }) =>
            fetchAPI<Scan>("/api/v1/scans", {
                method: "POST",
                body: JSON.stringify(data),
            }),
        stop: (id: string) =>
            fetchAPI<void>(`/api/v1/scans/${id}/stop`, { method: "POST" }),
        report: (id: string) => fetchAPI<Report>(`/api/v1/scans/${id}/report`),
    },
    modules: {
        list: () => fetchAPI<Module[]>("/api/v1/modules"),
    },
};
