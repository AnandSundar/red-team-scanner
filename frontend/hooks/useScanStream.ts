"use client";

import { useEffect, useState, useCallback } from "react";
import { ScanEvent } from "@/types";

export function useScanStream(scanId: string | null) {
    const [events, setEvents] = useState<ScanEvent[]>([]);
    const [isConnected, setIsConnected] = useState(false);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        if (!scanId) return;

        const eventSource = new EventSource(
            `${process.env.NEXT_PUBLIC_API_URL}/sse/scans/${scanId}/stream`
        );

        eventSource.onopen = () => {
            setIsConnected(true);
            setError(null);
        };

        eventSource.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                setEvents((prev) => [...prev, data]);
            } catch (err) {
                console.error("Failed to parse SSE event:", err);
            }
        };

        eventSource.onerror = () => {
            setIsConnected(false);
            setError("Connection lost");
            eventSource.close();
        };

        return () => {
            eventSource.close();
        };
    }, [scanId]);

    const clearEvents = useCallback(() => {
        setEvents([]);
    }, []);

    return { events, isConnected, error, clearEvents };
}
