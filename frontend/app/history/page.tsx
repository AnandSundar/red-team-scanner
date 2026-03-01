'use client';

import { useState } from "react";
import Link from "next/link";
import { History, Search, Filter, Clock, CheckCircle, XCircle, AlertCircle } from "lucide-react";

const mockScans = [
    { id: "scan-001", target: "api.example.com", status: "completed", findings: 12, date: "2 hours ago", severity: "high" },
    { id: "scan-002", target: "app.example.com", status: "running", findings: 0, date: "In progress", severity: null },
    { id: "scan-003", target: "blog.example.com", status: "completed", findings: 3, date: "5 hours ago", severity: "medium" },
    { id: "scan-004", target: "shop.example.com", status: "failed", findings: 0, date: "1 day ago", severity: null },
    { id: "scan-005", target: "admin.example.com", status: "completed", findings: 0, date: "2 days ago", severity: "low" },
];

export default function HistoryPage() {
    const [searchQuery, setSearchQuery] = useState("");

    const getStatusIcon = (status: string) => {
        switch (status) {
            case 'completed': return <CheckCircle className="w-4 h-4 text-neon-green" />;
            case 'running': return <Clock className="w-4 h-4 text-neon-cyan animate-pulse" />;
            case 'failed': return <XCircle className="w-4 h-4 text-red-400" />;
            default: return <AlertCircle className="w-4 h-4 text-gray-400" />;
        }
    };

    const getSeverityColor = (severity: string | null) => {
        switch (severity) {
            case 'critical': return 'text-red-500 bg-red-500/10';
            case 'high': return 'text-orange-500 bg-orange-500/10';
            case 'medium': return 'text-yellow-500 bg-yellow-500/10';
            case 'low': return 'text-green-500 bg-green-500/10';
            default: return 'text-gray-500 bg-gray-500/10';
        }
    };

    const filteredScans = mockScans.filter(scan => 
        scan.target.toLowerCase().includes(searchQuery.toLowerCase())
    );

    return (
        <div className="min-h-screen py-8 px-4 sm:px-6 lg:px-8">
            <div className="max-w-7xl mx-auto">
                <div className="mb-8">
                    <h1 className="text-3xl font-bold text-white flex items-center gap-3">
                        <History className="w-8 h-8 text-neon-cyan" />
                        Scan History
                    </h1>
                    <p className="text-gray-400 mt-2">
                        View and manage your previous security scans
                    </p>
                </div>

                {/* Search and Filter */}
                <div className="glass rounded-2xl p-4 mb-6">
                    <div className="flex flex-col sm:flex-row gap-4">
                        <div className="relative flex-1">
                            <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
                            <input
                                type="text"
                                value={searchQuery}
                                onChange={(e) => setSearchQuery(e.target.value)}
                                placeholder="Search scans..."
                                className="w-full pl-12 pr-4 py-3 bg-white/5 border border-white/10 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-neon-green focus:ring-1 focus:ring-neon-green"
                            />
                        </div>
                        <button className="px-6 py-3 glass rounded-xl text-gray-300 hover:text-white hover:bg-white/10 transition-all flex items-center gap-2">
                            <Filter className="w-4 h-4" />
                            Filter
                        </button>
                    </div>
                </div>

                {/* Scans Table */}
                <div className="glass rounded-2xl overflow-hidden">
                    <table className="w-full">
                        <thead>
                            <tr className="text-left text-xs text-gray-500 uppercase tracking-wider border-b border-white/5">
                                <th className="px-6 py-4 font-medium">Target</th>
                                <th className="px-6 py-4 font-medium">Status</th>
                                <th className="px-6 py-4 font-medium">Findings</th>
                                <th className="px-6 py-4 font-medium">Severity</th>
                                <th className="px-6 py-4 font-medium">Date</th>
                                <th className="px-6 py-4 font-medium">Actions</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-white/5">
                            {filteredScans.map((scan) => (
                                <tr key={scan.id} className="group hover:bg-white/5 transition-colors">
                                    <td className="px-6 py-4">
                                        <span className="text-white font-medium">{scan.target}</span>
                                    </td>
                                    <td className="px-6 py-4">
                                        <div className="flex items-center gap-2">
                                            {getStatusIcon(scan.status)}
                                            <span className={`text-sm capitalize ${
                                                scan.status === 'completed' ? 'text-neon-green' : 
                                                scan.status === 'failed' ? 'text-red-400' : 'text-neon-cyan'
                                            }`}>
                                                {scan.status}
                                            </span>
                                        </div>
                                    </td>
                                    <td className="px-6 py-4">
                                        <span className="text-white font-mono">{scan.findings}</span>
                                    </td>
                                    <td className="px-6 py-4">
                                        {scan.severity ? (
                                            <span className={`px-2 py-1 rounded-full text-xs font-medium uppercase ${getSeverityColor(scan.severity)}`}>
                                                {scan.severity}
                                            </span>
                                        ) : (
                                            <span className="text-gray-500">-</span>
                                        )}
                                    </td>
                                    <td className="px-6 py-4">
                                        <span className="text-gray-400 text-sm">{scan.date}</span>
                                    </td>
                                    <td className="px-6 py-4">
                                        <Link 
                                            href={`/reports/${scan.id}`}
                                            className="text-neon-green text-sm hover:underline"
                                        >
                                            View Report
                                        </Link>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
}
