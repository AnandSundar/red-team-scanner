'use client';

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useUser, useMockAuth } from "@/hooks/useAuth";
import { UserButton, SignInButton } from "@clerk/nextjs";
import { MockUserButton } from "@/components/MockUserButton";
import { Shield, Menu, X, Zap, History, Settings, LayoutDashboard } from "lucide-react";
import { useState } from "react";

const navItems = [
    { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
    { href: "/scan", label: "New Scan", icon: Zap },
    { href: "/history", label: "History", icon: History },
    { href: "/settings", label: "Settings", icon: Settings },
];

export function Navbar() {
    const { isSignedIn, user } = useUser();
    const pathname = usePathname();
    const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

    const isActive = (href: string) => pathname === href || pathname.startsWith(href + '/');

    return (
        <header className="sticky top-0 z-50 w-full">
            <nav className="glass-strong border-b border-white/5">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="flex items-center justify-between h-16">
                        {/* Logo */}
                        <Link href="/" className="flex items-center gap-3 group">
                            <div className="relative">
                                <div className="absolute inset-0 bg-neon-green/20 blur-xl rounded-full group-hover:bg-neon-green/30 transition-all duration-300" />
                                <Shield className="w-8 h-8 text-neon-green relative z-10" />
                            </div>
                            <div className="flex flex-col">
                                <span className="font-bold text-lg leading-tight text-white">
                                    Red Team
                                </span>
                                <span className="text-[10px] text-neon-green font-mono tracking-wider uppercase">
                                    Scanner
                                </span>
                            </div>
                        </Link>

                        {/* Desktop Navigation */}
                        <div className="hidden md:flex items-center gap-1">
                            {isSignedIn && navItems.map((item) => {
                                const Icon = item.icon;
                                return (
                                    <Link
                                        key={item.href}
                                        href={item.href}
                                        className={`
                                            relative px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200
                                            flex items-center gap-2
                                            ${isActive(item.href) 
                                                ? 'text-white' 
                                                : 'text-gray-400 hover:text-white hover:bg-white/5'
                                            }
                                        `}
                                    >
                                        {isActive(item.href) && (
                                            <span className="absolute inset-0 bg-neon-green/10 rounded-lg" />
                                        )}
                                        <span className={`
                                            relative z-10 flex items-center gap-2
                                            ${isActive(item.href) ? 'text-neon-green' : ''}
                                        `}>
                                            <Icon className="w-4 h-4" />
                                            {item.label}
                                        </span>
                                        {isActive(item.href) && (
                                            <span className="absolute bottom-0 left-1/2 -translate-x-1/2 w-1 h-1 bg-neon-green rounded-full" />
                                        )}
                                    </Link>
                                );
                            })}
                        </div>

                        {/* Right side */}
                        <div className="flex items-center gap-4">
                            {isSignedIn ? (
                                <div className="flex items-center gap-4">
                                    <span className="hidden md:block text-sm text-gray-400">
                                        {user?.emailAddresses[0]?.emailAddress}
                                    </span>
                                    {useMockAuth ? (
                                        <MockUserButton />
                                    ) : (
                                        <UserButton 
                                            afterSignOutUrl="/"
                                            appearance={{
                                                elements: {
                                                    avatarBox: "w-9 h-9 ring-2 ring-neon-green/30 ring-offset-2 ring-offset-transparent rounded-full"
                                                }
                                            }}
                                        />
                                    )}
                                </div>
                            ) : (
                                <div className="hidden md:flex items-center gap-3">
                                    {useMockAuth ? (
                                        <Link href="/dashboard" className="btn-primary text-sm">
                                            Get Started
                                        </Link>
                                    ) : (
                                        <>
                                            <SignInButton mode="modal">
                                                <button className="px-4 py-2 text-sm font-medium text-gray-300 hover:text-white transition-colors">
                                                    Sign In
                                                </button>
                                            </SignInButton>
                                            <Link
                                                href="/sign-up"
                                                className="btn-primary text-sm"
                                            >
                                                Get Started
                                            </Link>
                                        </>
                                    )}
                                </div>
                            )}

                            {/* Mobile menu button */}
                            <button
                                onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
                                className="md:hidden p-2 text-gray-400 hover:text-white transition-colors"
                            >
                                {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
                            </button>
                        </div>
                    </div>
                </div>

                {/* Mobile menu */}
                {mobileMenuOpen && (
                    <div className="md:hidden glass-strong border-t border-white/5 animate-slide-up">
                        <div className="px-4 py-4 space-y-2">
                            {isSignedIn ? (
                                navItems.map((item) => {
                                    const Icon = item.icon;
                                    return (
                                        <Link
                                            key={item.href}
                                            href={item.href}
                                            onClick={() => setMobileMenuOpen(false)}
                                            className={`
                                                flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all
                                                ${isActive(item.href)
                                                    ? 'bg-neon-green/10 text-neon-green'
                                                    : 'text-gray-400 hover:text-white hover:bg-white/5'
                                                }
                                            `}
                                        >
                                            <Icon className="w-5 h-5" />
                                            {item.label}
                                        </Link>
                                    );
                                })
                            ) : (
                                <div className="space-y-2">
                                    <Link
                                        href="/sign-in"
                                        onClick={() => setMobileMenuOpen(false)}
                                        className="block w-full px-4 py-3 text-center text-gray-300 hover:text-white rounded-lg hover:bg-white/5 transition-all"
                                    >
                                        Sign In
                                    </Link>
                                    <Link
                                        href="/sign-up"
                                        onClick={() => setMobileMenuOpen(false)}
                                        className="block w-full btn-primary text-center"
                                    >
                                        Get Started
                                    </Link>
                                </div>
                            )}
                        </div>
                    </div>
                )}
            </nav>
        </header>
    );
}
