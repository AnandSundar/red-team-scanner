import Link from "next/link";
import { ArrowRight, Shield, Zap, Lock, Globe, Terminal, Activity } from "lucide-react";

export default function Home() {
    return (
        <div className="min-h-screen">
            {/* Hero Section */}
            <section className="relative pt-20 pb-32 overflow-hidden">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="text-center">
                        {/* Badge */}
                        <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full glass mb-8 animate-fade-in">
                            <span className="relative flex h-2 w-2">
                                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-neon-green opacity-75"></span>
                                <span className="relative inline-flex rounded-full h-2 w-2 bg-neon-green"></span>
                            </span>
                            <span className="text-sm text-gray-300 font-medium">
                                AI-Powered Security Testing
                            </span>
                        </div>

                        {/* Main Heading */}
                        <h1 className="text-5xl md:text-7xl font-extrabold tracking-tight mb-6">
                            <span className="block text-white mb-2">Secure Your</span>
                            <span className="gradient-text-hero">
                                Digital Assets
                            </span>
                        </h1>

                        {/* Subheading */}
                        <p className="max-w-2xl mx-auto text-xl text-gray-400 mb-10 leading-relaxed">
                            Advanced AI-driven vulnerability scanning and penetration testing platform. 
                            Identify threats before attackers do with our intelligent security engine.
                        </p>

                        {/* CTA Buttons */}
                        <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-16">
                            <Link
                                href="/sign-up"
                                className="group relative px-8 py-4 bg-neon-green text-cyber-dark font-bold rounded-xl overflow-hidden transition-all duration-300 hover:scale-105 hover:shadow-neon-green"
                            >
                                <span className="relative z-10 flex items-center gap-2">
                                    Start Free Scan
                                    <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
                                </span>
                            </Link>
                            <Link
                                href="/sign-in"
                                className="px-8 py-4 glass text-white font-semibold rounded-xl hover:bg-white/10 transition-all duration-300 flex items-center gap-2"
                            >
                                <Terminal className="w-5 h-5" />
                                View Demo
                            </Link>
                        </div>

                        {/* Stats */}
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-6 max-w-3xl mx-auto">
                            {[
                                { value: "10K+", label: "Scans Completed" },
                                { value: "99.9%", label: "Accuracy Rate" },
                                { value: "50ms", label: "Response Time" },
                                { value: "24/7", label: "Monitoring" },
                            ].map((stat, index) => (
                                <div
                                    key={stat.label}
                                    className="glass rounded-2xl p-4 animate-slide-up"
                                    style={{ animationDelay: `${index * 100}ms` }}
                                >
                                    <div className="text-2xl md:text-3xl font-bold text-neon-green mb-1">
                                        {stat.value}
                                    </div>
                                    <div className="text-sm text-gray-400">{stat.label}</div>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            </section>

            {/* Features Section */}
            <section className="py-24 relative">
                <div className="absolute inset-0 bg-gradient-to-b from-transparent via-neon-green/5 to-transparent" />
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative">
                    <div className="text-center mb-16">
                        <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
                            Advanced <span className="text-neon-green">Security Features</span>
                        </h2>
                        <p className="text-gray-400 max-w-2xl mx-auto">
                            Comprehensive security testing powered by cutting-edge AI technology
                        </p>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                        {[
                            {
                                icon: Shield,
                                title: "Vulnerability Scanning",
                                description: "Automated detection of security vulnerabilities across your entire infrastructure",
                                color: "neon-green",
                            },
                            {
                                icon: Zap,
                                title: "AI-Powered Analysis",
                                description: "Machine learning algorithms that adapt and improve threat detection over time",
                                color: "neon-cyan",
                            },
                            {
                                icon: Lock,
                                title: "Penetration Testing",
                                description: "Simulate real-world attacks to identify exploitable weaknesses",
                                color: "neon-pink",
                            },
                            {
                                icon: Globe,
                                title: "Web App Security",
                                description: "Deep scanning of web applications for OWASP Top 10 vulnerabilities",
                                color: "neon-violet",
                            },
                            {
                                icon: Activity,
                                title: "Real-time Monitoring",
                                description: "Continuous security monitoring with instant alert notifications",
                                color: "neon-amber",
                            },
                            {
                                icon: Terminal,
                                title: "API Security",
                                description: "Comprehensive API endpoint testing and authentication validation",
                                color: "neon-green",
                            },
                        ].map((feature, index) => {
                            const Icon = feature.icon;
                            return (
                                <div
                                    key={feature.title}
                                    className="group glass rounded-2xl p-6 card-hover glow-border"
                                    style={{ animationDelay: `${index * 100}ms` }}
                                >
                                    <div className={`
                                        w-12 h-12 rounded-xl flex items-center justify-center mb-4
                                        bg-${feature.color}/10 text-${feature.color}
                                        group-hover:scale-110 transition-transform duration-300
                                    `}>
                                        <Icon className="w-6 h-6" />
                                    </div>
                                    <h3 className="text-lg font-semibold text-white mb-2">
                                        {feature.title}
                                    </h3>
                                    <p className="text-gray-400 text-sm leading-relaxed">
                                        {feature.description}
                                    </p>
                                </div>
                            );
                        })}
                    </div>
                </div>
            </section>

            {/* Terminal Preview Section */}
            <section className="py-24">
                <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
                        <div>
                            <h2 className="text-3xl md:text-4xl font-bold text-white mb-6">
                                Real-time <span className="text-neon-cyan">Scan Results</span>
                            </h2>
                            <p className="text-gray-400 mb-8 leading-relaxed">
                                Watch as our AI engine analyzes your systems in real-time. Get instant 
                                feedback on vulnerabilities with detailed remediation guidance.
                            </p>
                            <ul className="space-y-4">
                                {[
                                    "Live vulnerability detection",
                                    "Detailed remediation steps",
                                    "Risk severity classification",
                                    "Compliance reporting",
                                ].map((item) => (
                                    <li key={item} className="flex items-center gap-3 text-gray-300">
                                        <div className="w-5 h-5 rounded-full bg-neon-green/20 flex items-center justify-center">
                                            <div className="w-2 h-2 rounded-full bg-neon-green" />
                                        </div>
                                        {item}
                                    </li>
                                ))}
                            </ul>
                        </div>

                        {/* Terminal Mockup */}
                        <div className="terminal overflow-hidden animate-float">
                            <div className="terminal-header">
                                <div className="terminal-dot red" />
                                <div className="terminal-dot yellow" />
                                <div className="terminal-dot green" />
                                <span className="ml-4 text-xs text-gray-500 font-mono">scanner-agent — bash — 80x24</span>
                            </div>
                            <div className="p-4 font-mono text-sm space-y-2">
                                <div className="text-gray-500">
                                    <span className="text-neon-green">➜</span> <span className="text-neon-cyan">~</span> ./redteam-scanner --target example.com
                                </div>
                                <div className="text-gray-400">
                                    [INFO] Initializing AI security engine...
                                </div>
                                <div className="text-gray-400">
                                    [INFO] Loading vulnerability database... <span className="text-neon-green">✓</span>
                                </div>
                                <div className="text-gray-400">
                                    [SCAN] Probing target endpoints...
                                </div>
                                <div className="text-neon-amber">
                                    [WARN] Potential SQL injection detected at /api/users
                                </div>
                                <div className="text-red-400">
                                    [CRITICAL] XSS vulnerability found in search parameter
                                </div>
                                <div className="text-gray-400">
                                    [SCAN] Analyzing response headers... <span className="text-neon-green">✓</span>
                                </div>
                                <div className="text-gray-400">
                                    [INFO] Generating compliance report...
                                </div>
                                <div className="text-neon-green">
                                    [DONE] Scan completed. 3 vulnerabilities found.
                                </div>
                                <div className="flex items-center gap-2 mt-4">
                                    <span className="text-neon-green">➜</span> <span className="text-neon-cyan">~</span>
                                    <span className="w-2 h-4 bg-neon-green animate-blink" />
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            {/* CTA Section */}
            <section className="py-24">
                <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="glass rounded-3xl p-8 md:p-12 text-center relative overflow-hidden">
                        <div className="absolute inset-0 bg-gradient-to-r from-neon-green/10 via-neon-cyan/10 to-neon-violet/10" />
                        <div className="relative z-10">
                            <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
                                Ready to Secure Your Infrastructure?
                            </h2>
                            <p className="text-gray-400 mb-8 max-w-xl mx-auto">
                                Join thousands of security teams using our AI-powered platform to 
                                stay ahead of emerging threats.
                            </p>
                            <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
                                <Link
                                    href="/sign-up"
                                    className="w-full sm:w-auto px-8 py-4 bg-neon-green text-cyber-dark font-bold rounded-xl hover:shadow-neon-green transition-all duration-300 hover:scale-105"
                                >
                                    Get Started Free
                                </Link>
                                <Link
                                    href="/sign-in"
                                    className="w-full sm:w-auto px-8 py-4 glass text-white font-semibold rounded-xl hover:bg-white/10 transition-all duration-300"
                                >
                                    Sign In
                                </Link>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            {/* Footer */}
            <footer className="border-t border-white/5 py-12">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="flex flex-col md:flex-row items-center justify-between gap-4">
                        <div className="flex items-center gap-2">
                            <Shield className="w-6 h-6 text-neon-green" />
                            <span className="font-bold text-white">Red Team Scanner</span>
                        </div>
                        <p className="text-gray-500 text-sm">
                            © 2026 Red Team Scanner. All rights reserved.
                        </p>
                    </div>
                </div>
            </footer>
        </div>
    );
}
