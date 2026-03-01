import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import { AuthProvider } from "@/components/AuthProvider";
import { Toaster } from "@/components/ui/sonner";
import { AnimatedBackground } from "@/components/AnimatedBackground";
import { Navbar } from "@/components/layout/Navbar";
import "./globals.css";

const inter = Inter({ 
    subsets: ["latin"],
    variable: "--font-inter",
});

const jetbrainsMono = JetBrains_Mono({
    subsets: ["latin"],
    variable: "--font-mono",
});

export const metadata: Metadata = {
    title: "Red Team Scanner | AI-Powered Security Testing",
    description: "Advanced AI-powered security testing and vulnerability scanning platform",
    keywords: ["security", "pentesting", "red team", "vulnerability scanner", "AI security"],
};

export default function RootLayout({
    children,
}: {
    children: React.ReactNode;
}) {
    return (
        <AuthProvider>
            <html lang="en" className="dark">
                <body className={`${inter.variable} ${jetbrainsMono.variable} font-sans antialiased`}>
                    <AnimatedBackground />
                    <div className="noise-overlay" />
                    <div className="scan-line" />
                    <div className="relative z-10 min-h-screen flex flex-col">
                        <Navbar />
                        <main className="flex-1">
                            {children}
                        </main>
                    </div>
                    <Toaster 
                        position="bottom-right"
                        toastOptions={{
                            style: {
                                background: 'rgba(15, 23, 30, 0.95)',
                                border: '1px solid rgba(16, 185, 129, 0.2)',
                                color: '#fff',
                            },
                        }}
                    />
                </body>
            </html>
        </AuthProvider>
    );
}
