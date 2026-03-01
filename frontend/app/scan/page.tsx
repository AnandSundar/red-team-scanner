'use client';

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Zap, Globe, Shield, AlertCircle } from "lucide-react";
import { toast } from "sonner";

export default function ScanPage() {
    const router = useRouter();
    const [target, setTarget] = useState("");
    const [isLoading, setIsLoading] = useState(false);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!target) {
            toast.error("Please enter a target URL");
            return;
        }
        setIsLoading(true);
        // TODO: Implement scan creation
        toast.success("Scan started!");
        setIsLoading(false);
    };

    return (
        <div className="min-h-screen py-8 px-4 sm:px-6 lg:px-8">
            <div className="max-w-4xl mx-auto">
                <div className="mb-8">
                    <h1 className="text-3xl font-bold text-white flex items-center gap-3">
                        <Zap className="w-8 h-8 text-neon-cyan" />
                        New Security Scan
                    </h1>
                    <p className="text-gray-400 mt-2">
                        Enter a target URL to start an AI-powered security assessment
                    </p>
                </div>

                <div className="glass rounded-2xl p-8">
                    <form onSubmit={handleSubmit} className="space-y-6">
                        <div>
                            <label className="block text-sm font-medium text-gray-300 mb-2">
                                Target URL
                            </label>
                            <div className="relative">
                                <Globe className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
                                <input
                                    type="url"
                                    value={target}
                                    onChange={(e) => setTarget(e.target.value)}
                                    placeholder="https://example.com"
                                    className="w-full pl-12 pr-4 py-4 bg-white/5 border border-white/10 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-neon-green focus:ring-1 focus:ring-neon-green"
                                />
                            </div>
                        </div>

                        <div className="flex items-start gap-3 p-4 rounded-xl bg-neon-green/5 border border-neon-green/20">
                            <Shield className="w-5 h-5 text-neon-green mt-0.5" />
                            <div>
                                <h3 className="text-sm font-medium text-white">Security Note</h3>
                                <p className="text-sm text-gray-400 mt-1">
                                    Only scan targets you own or have explicit permission to test.
                                    Unauthorized scanning is illegal.
                                </p>
                            </div>
                        </div>

                        <button
                            type="submit"
                            disabled={isLoading}
                            className="w-full py-4 bg-neon-green text-cyber-dark font-bold rounded-xl hover:shadow-neon-green transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                        >
                            {isLoading ? (
                                <>
                                    <div className="w-5 h-5 border-2 border-cyber-dark/30 border-t-cyber-dark rounded-full animate-spin" />
                                    Starting Scan...
                                </>
                            ) : (
                                <>
                                    <Zap className="w-5 h-5" />
                                    Start Scan
                                </>
                            )}
                        </button>
                    </form>
                </div>
            </div>
        </div>
    );
}
