'use client';

import { useParams } from "next/navigation";
import { useScanStream } from "@/hooks/useScanStream";
import { Shield, Zap, AlertCircle, CheckCircle, Clock, Terminal } from "lucide-react";
import Link from "next/link";

export default function ScanDetailPage() {
    const params = useParams();
    const scanId = params.id as string;
    const { events, isConnected, error } = useScanStream(scanId);

    const getStatusIcon = (status: string) => {
        switch (status) {
            case 'running':
                return <Zap className="w-5 h-5 text-neon-cyan animate-pulse" />;
            case 'completed':
                return <CheckCircle className="w-5 h-5 text-neon-green" />;
            case 'error':
                return <AlertCircle className="w-5 h-5 text-red-500" />;
            default:
                return <Clock className="w-5 h-5 text-gray-400" />;
        }
    };

    const getSeverityColor = (severity: string) => {
        switch (severity) {
            case 'critical': return 'text-red-500 bg-red-500/10 border-red-500/30';
            case 'high': return 'text-orange-500 bg-orange-500/10 border-orange-500/30';
            case 'medium': return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/30';
            case 'low': return 'text-green-500 bg-green-500/10 border-green-500/30';
            default: return 'text-gray-400 bg-gray-400/10 border-gray-400/30';
        }
    };

    return (
        <div className="min-h-screen py-8 px-4 sm:px-6 lg:px-8">
            <div className="max-w-6xl mx-auto">
                {/* Header */}
                <div className="mb-8">
                    <div className="flex items-center gap-3 mb-4">
                        <Link 
                            href="/dashboard" 
                            className="text-gray-400 hover:text-white transition-colors"
                        >
                            ← Back to Dashboard
                        </Link>
                    </div>
                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                            <Shield className="w-8 h-8 text-neon-cyan" />
                            <div>
                                <h1 className="text-3xl font-bold text-white">Security Scan</h1>
                                <p className="text-gray-400 mt-1">ID: {scanId}</p>
                            </div>
                        </div>
                        <div className="flex items-center gap-2">
                            <div className={`w-3 h-3 rounded-full ${isConnected ? 'bg-neon-green animate-pulse' : 'bg-red-500'}`} />
                            <span className="text-sm text-gray-400">
                                {isConnected ? 'Live' : 'Disconnected'}
                            </span>
                        </div>
                    </div>
                </div>

                {/* Error Message */}
                {error && (
                    <div className="mb-6 p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400">
                        <AlertCircle className="w-5 h-5 inline mr-2" />
                        {error}
                    </div>
                )}

                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    {/* Live Events Feed */}
                    <div className="lg:col-span-2">
                        <div className="glass rounded-2xl p-6">
                            <div className="flex items-center gap-2 mb-4">
                                <Terminal className="w-5 h-5 text-neon-cyan" />
                                <h2 className="text-lg font-semibold text-white">Live Scan Results</h2>
                            </div>
                            
                            <div className="space-y-3 max-h-[600px] overflow-y-auto">
                                {events.length === 0 ? (
                                    <div className="text-center py-12 text-gray-400">
                                        <Zap className="w-12 h-12 mx-auto mb-4 text-neon-cyan animate-pulse" />
                                        <p>Scan is initializing...</p>
                                        <p className="text-sm mt-2">Waiting for results from the target</p>
                                    </div>
                                ) : (
                                    events.map((event, index) => (
                                        <div 
                                            key={index}
                                            className="p-4 rounded-xl bg-white/5 border border-white/10"
                                        >
                                            <div className="flex items-start gap-3">
                                                {getStatusIcon(event.type)}
                                                <div className="flex-1">
                                                    <div className="flex items-center justify-between mb-1">
                                                        <span className="text-sm font-medium text-white capitalize">
                                                            {event.type}
                                                        </span>
                                                        <span className="text-xs text-gray-500">
                                                            {new Date(event.timestamp).toLocaleTimeString()}
                                                        </span>
                                                    </div>
                                                    {event.type === 'finding' && (
                                                        <div className={`inline-block px-2 py-1 rounded text-xs font-medium border mb-2 ${getSeverityColor((event.data as any)?.severity || 'info')}`}>
                                                            {(event.data as any)?.severity?.toUpperCase() || 'INFO'}
                                                        </div>
                                                    )}
                                                    <p className="text-sm text-gray-300">
                                                        {typeof event.data === 'string' 
                                                            ? event.data 
                                                            : (event.data as any)?.message || JSON.stringify(event.data)
                                                        }
                                                    </p>
                                                </div>
                                            </div>
                                        </div>
                                    ))
                                )}
                            </div>
                        </div>
                    </div>

                    {/* Scan Summary */}
                    <div className="space-y-6">
                        <div className="glass rounded-2xl p-6">
                            <h2 className="text-lg font-semibold text-white mb-4">Scan Status</h2>
                            <div className="space-y-4">
                                <div className="flex justify-between items-center">
                                    <span className="text-gray-400">Status</span>
                                    <span className={`px-3 py-1 rounded-full text-sm font-medium ${
                                        isConnected 
                                            ? 'bg-neon-green/10 text-neon-green' 
                                            : 'bg-yellow-500/10 text-yellow-500'
                                    }`}>
                                        {isConnected ? 'Running' : 'Pending'}
                                    </span>
                                </div>
                                <div className="flex justify-between items-center">
                                    <span className="text-gray-400">Events Received</span>
                                    <span className="text-white font-mono">{events.length}</span>
                                </div>
                            </div>
                        </div>

                        <div className="glass rounded-2xl p-6">
                            <h2 className="text-lg font-semibold text-white mb-4">Findings</h2>
                            <div className="space-y-3">
                                {['critical', 'high', 'medium', 'low'].map((severity) => {
                                    const count = events.filter(e => 
                                        e.type === 'finding' && 
                                        (e.data as any)?.severity === severity
                                    ).length;
                                    return (
                                        <div key={severity} className="flex justify-between items-center">
                                            <span className={`capitalize ${getSeverityColor(severity).split(' ')[0]}`}>
                                                {severity}
                                            </span>
                                            <span className="text-white font-mono">{count}</span>
                                        </div>
                                    );
                                })}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
