'use client';

import { useUser } from "@/hooks/useAuth";
import { 
    Shield, 
    Zap, 
    Activity, 
    AlertTriangle, 
    CheckCircle, 
    Clock,
    TrendingUp,
    Target,
    ArrowUpRight,
    ArrowDownRight,
    MoreHorizontal
} from "lucide-react";
import Link from "next/link";

const stats = [
    {
        title: "Total Scans",
        value: "124",
        change: "+12%",
        trend: "up",
        icon: Shield,
        color: "neon-green",
    },
    {
        title: "Active Scans",
        value: "3",
        change: "+2",
        trend: "up",
        icon: Zap,
        color: "neon-cyan",
    },
    {
        title: "Vulnerabilities",
        value: "47",
        change: "-8%",
        trend: "down",
        icon: AlertTriangle,
        color: "neon-pink",
    },
    {
        title: "Resolved",
        value: "89%",
        change: "+5%",
        trend: "up",
        icon: CheckCircle,
        color: "neon-amber",
    },
];

const recentScans = [
    { id: "scan-001", target: "api.example.com", status: "completed", findings: 12, date: "2 hours ago", severity: "high" },
    { id: "scan-002", target: "app.example.com", status: "running", findings: 0, date: "In progress", severity: null },
    { id: "scan-003", target: "blog.example.com", status: "completed", findings: 3, date: "5 hours ago", severity: "medium" },
    { id: "scan-004", target: "shop.example.com", status: "completed", findings: 0, date: "1 day ago", severity: "low" },
];

const vulnerabilities = [
    { id: 1, name: "SQL Injection", severity: "critical", location: "/api/users", count: 2 },
    { id: 2, name: "XSS Vulnerability", severity: "high", location: "/search", count: 5 },
    { id: 3, name: "Missing Headers", severity: "medium", location: "Global", count: 12 },
    { id: 4, name: "Weak SSL Config", severity: "medium", location: "HTTPS", count: 1 },
];

export default function DashboardPage() {
    const { user } = useUser();

    const getSeverityColor = (severity: string | null) => {
        switch (severity) {
            case 'critical': return 'text-red-500 bg-red-500/10';
            case 'high': return 'text-orange-500 bg-orange-500/10';
            case 'medium': return 'text-yellow-500 bg-yellow-500/10';
            case 'low': return 'text-green-500 bg-green-500/10';
            default: return 'text-gray-500 bg-gray-500/10';
        }
    };

    const getStatusIcon = (status: string) => {
        switch (status) {
            case 'completed': return <CheckCircle className="w-4 h-4 text-neon-green" />;
            case 'running': return <Activity className="w-4 h-4 text-neon-cyan animate-pulse" />;
            default: return <Clock className="w-4 h-4 text-gray-400" />;
        }
    };

    return (
        <div className="min-h-screen py-8 px-4 sm:px-6 lg:px-8">
            <div className="max-w-7xl mx-auto space-y-8">
                {/* Header */}
                <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
                    <div>
                        <h1 className="text-3xl font-bold text-white">
                            Welcome back, <span className="text-neon-green">{user?.firstName || 'Security Analyst'}</span>
                        </h1>
                        <p className="text-gray-400 mt-1">
                            Here's what's happening with your security posture
                        </p>
                    </div>
                    <Link
                        href="/scan"
                        className="btn-primary inline-flex items-center gap-2 w-fit"
                    >
                        <Zap className="w-4 h-4" />
                        New Scan
                    </Link>
                </div>

                {/* Stats Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                    {stats.map((stat, index) => {
                        const Icon = stat.icon;
                        const isPositive = stat.trend === 'up';
                        return (
                            <div
                                key={stat.title}
                                className="glass rounded-2xl p-6 card-hover glow-border animate-slide-up"
                                style={{ animationDelay: `${index * 100}ms` }}
                            >
                                <div className="flex items-start justify-between">
                                    <div>
                                        <p className="text-gray-400 text-sm">{stat.title}</p>
                                        <p className="text-3xl font-bold text-white mt-2">{stat.value}</p>
                                    </div>
                                    <div className={`
                                        w-12 h-12 rounded-xl flex items-center justify-center
                                        bg-${stat.color}/10 text-${stat.color}
                                    `}>
                                        <Icon className="w-6 h-6" />
                                    </div>
                                </div>
                                <div className="flex items-center gap-2 mt-4">
                                    {isPositive ? (
                                        <ArrowUpRight className="w-4 h-4 text-neon-green" />
                                    ) : (
                                        <ArrowDownRight className="w-4 h-4 text-neon-pink" />
                                    )}
                                    <span className={isPositive ? 'text-neon-green' : 'text-neon-pink'}>
                                        {stat.change}
                                    </span>
                                    <span className="text-gray-500 text-sm">vs last month</span>
                                </div>
                            </div>
                        );
                    })}
                </div>

                {/* Charts & Lists Grid */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    {/* Security Score */}
                    <div className="glass rounded-2xl p-6 animate-slide-up" style={{ animationDelay: '200ms' }}>
                        <div className="flex items-center justify-between mb-6">
                            <h3 className="text-lg font-semibold text-white">Security Score</h3>
                            <Target className="w-5 h-5 text-neon-cyan" />
                        </div>
                        <div className="flex items-center justify-center py-8">
                            <div className="relative">
                                <svg className="w-40 h-40 transform -rotate-90">
                                    <circle
                                        cx="80"
                                        cy="80"
                                        r="70"
                                        stroke="rgba(255,255,255,0.1)"
                                        strokeWidth="12"
                                        fill="transparent"
                                    />
                                    <circle
                                        cx="80"
                                        cy="80"
                                        r="70"
                                        stroke="#10b981"
                                        strokeWidth="12"
                                        fill="transparent"
                                        strokeDasharray={`${2 * Math.PI * 70}`}
                                        strokeDashoffset={`${2 * Math.PI * 70 * (1 - 0.85)}`}
                                        strokeLinecap="round"
                                        className="transition-all duration-1000"
                                    />
                                </svg>
                                <div className="absolute inset-0 flex flex-col items-center justify-center">
                                    <span className="text-4xl font-bold text-white">85</span>
                                    <span className="text-sm text-gray-400">/100</span>
                                </div>
                            </div>
                        </div>
                        <div className="space-y-3">
                            <div className="flex items-center justify-between text-sm">
                                <span className="text-gray-400">Critical Issues</span>
                                <span className="text-red-400 font-medium">2</span>
                            </div>
                            <div className="flex items-center justify-between text-sm">
                                <span className="text-gray-400">Warnings</span>
                                <span className="text-yellow-400 font-medium">8</span>
                            </div>
                            <div className="flex items-center justify-between text-sm">
                                <span className="text-gray-400">Passed</span>
                                <span className="text-neon-green font-medium">42</span>
                            </div>
                        </div>
                    </div>

                    {/* Recent Scans */}
                    <div className="glass rounded-2xl p-6 lg:col-span-2 animate-slide-up" style={{ animationDelay: '300ms' }}>
                        <div className="flex items-center justify-between mb-6">
                            <h3 className="text-lg font-semibold text-white">Recent Scans</h3>
                            <Link href="/history" className="text-neon-green text-sm hover:underline">
                                View All
                            </Link>
                        </div>
                        <div className="overflow-x-auto">
                            <table className="w-full">
                                <thead>
                                    <tr className="text-left text-xs text-gray-500 uppercase tracking-wider">
                                        <th className="pb-3 font-medium">Target</th>
                                        <th className="pb-3 font-medium">Status</th>
                                        <th className="pb-3 font-medium">Findings</th>
                                        <th className="pb-3 font-medium">Severity</th>
                                        <th className="pb-3 font-medium">Date</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-white/5">
                                    {recentScans.map((scan) => (
                                        <tr key={scan.id} className="group hover:bg-white/5 transition-colors">
                                            <td className="py-4">
                                                <div className="flex items-center gap-3">
                                                    <div className="w-8 h-8 rounded-lg bg-neon-green/10 flex items-center justify-center">
                                                        <Target className="w-4 h-4 text-neon-green" />
                                                    </div>
                                                    <span className="text-white font-medium">{scan.target}</span>
                                                </div>
                                            </td>
                                            <td className="py-4">
                                                <div className="flex items-center gap-2">
                                                    {getStatusIcon(scan.status)}
                                                    <span className={`
                                                        text-sm capitalize
                                                        ${scan.status === 'completed' ? 'text-neon-green' : 'text-neon-cyan'}
                                                    `}>
                                                        {scan.status}
                                                    </span>
                                                </div>
                                            </td>
                                            <td className="py-4">
                                                <span className="text-white font-mono">
                                                    {scan.findings}
                                                </span>
                                            </td>
                                            <td className="py-4">
                                                {scan.severity ? (
                                                    <span className={`
                                                        px-2 py-1 rounded-full text-xs font-medium uppercase
                                                        ${getSeverityColor(scan.severity)}
                                                    `}>
                                                        {scan.severity}
                                                    </span>
                                                ) : (
                                                    <span className="text-gray-500">-</span>
                                                )}
                                            </td>
                                            <td className="py-4">
                                                <span className="text-gray-400 text-sm">{scan.date}</span>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                {/* Bottom Row */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    {/* Top Vulnerabilities */}
                    <div className="glass rounded-2xl p-6 animate-slide-up" style={{ animationDelay: '400ms' }}>
                        <div className="flex items-center justify-between mb-6">
                            <h3 className="text-lg font-semibold text-white">Top Vulnerabilities</h3>
                            <AlertTriangle className="w-5 h-5 text-neon-pink" />
                        </div>
                        <div className="space-y-4">
                            {vulnerabilities.map((vuln) => (
                                <div
                                    key={vuln.id}
                                    className="flex items-center justify-between p-4 rounded-xl bg-white/5 hover:bg-white/10 transition-colors group"
                                >
                                    <div className="flex items-center gap-4">
                                        <div className={`
                                            w-10 h-10 rounded-lg flex items-center justify-center
                                            ${getSeverityColor(vuln.severity)}
                                        `}>
                                            <AlertTriangle className="w-5 h-5" />
                                        </div>
                                        <div>
                                            <p className="text-white font-medium">{vuln.name}</p>
                                            <p className="text-gray-400 text-sm">{vuln.location}</p>
                                        </div>
                                    </div>
                                    <div className="flex items-center gap-4">
                                        <div className="text-right">
                                            <span className={`
                                                px-2 py-1 rounded-full text-xs font-medium uppercase
                                                ${getSeverityColor(vuln.severity)}
                                            `}>
                                                {vuln.severity}
                                            </span>
                                        </div>
                                        <span className="text-white font-mono min-w-[2rem] text-right">
                                            {vuln.count}
                                        </span>
                                        <button className="p-2 rounded-lg hover:bg-white/10 text-gray-400 hover:text-white transition-colors">
                                            <MoreHorizontal className="w-4 h-4" />
                                        </button>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Activity Chart Placeholder */}
                    <div className="glass rounded-2xl p-6 animate-slide-up" style={{ animationDelay: '500ms' }}>
                        <div className="flex items-center justify-between mb-6">
                            <h3 className="text-lg font-semibold text-white">Scan Activity</h3>
                            <TrendingUp className="w-5 h-5 text-neon-amber" />
                        </div>
                        <div className="h-64 flex items-end justify-between gap-2">
                            {[65, 45, 80, 55, 90, 70, 85, 60, 95, 75, 85, 70].map((height, index) => (
                                <div
                                    key={index}
                                    className="flex-1 flex flex-col items-center gap-2"
                                >
                                    <div
                                        className="w-full bg-gradient-to-t from-neon-green/20 to-neon-green rounded-t-lg transition-all duration-500 hover:from-neon-green/40 hover:to-neon-cyan"
                                        style={{ height: `${height}%` }}
                                    />
                                </div>
                            ))}
                        </div>
                        <div className="flex justify-between mt-4 text-xs text-gray-500">
                            <span>Jan</span>
                            <span>Feb</span>
                            <span>Mar</span>
                            <span>Apr</span>
                            <span>May</span>
                            <span>Jun</span>
                            <span>Jul</span>
                            <span>Aug</span>
                            <span>Sep</span>
                            <span>Oct</span>
                            <span>Nov</span>
                            <span>Dec</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
