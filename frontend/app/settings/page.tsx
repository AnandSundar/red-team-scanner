'use client';

import { useState } from "react";
import { Settings, User, Bell, Shield, Key, Save } from "lucide-react";
import { toast } from "sonner";

export default function SettingsPage() {
    const [activeTab, setActiveTab] = useState("profile");
    const [isSaving, setIsSaving] = useState(false);

    const handleSave = async () => {
        setIsSaving(true);
        // Simulate API call
        await new Promise(resolve => setTimeout(resolve, 1000));
        toast.success("Settings saved successfully");
        setIsSaving(false);
    };

    const tabs = [
        { id: "profile", label: "Profile", icon: User },
        { id: "notifications", label: "Notifications", icon: Bell },
        { id: "security", label: "Security", icon: Shield },
        { id: "api", label: "API Keys", icon: Key },
    ];

    return (
        <div className="min-h-screen py-8 px-4 sm:px-6 lg:px-8">
            <div className="max-w-6xl mx-auto">
                <div className="mb-8">
                    <h1 className="text-3xl font-bold text-white flex items-center gap-3">
                        <Settings className="w-8 h-8 text-neon-cyan" />
                        Settings
                    </h1>
                    <p className="text-gray-400 mt-2">
                        Manage your account and application preferences
                    </p>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
                    {/* Sidebar */}
                    <div className="lg:col-span-1">
                        <div className="glass rounded-2xl p-2 space-y-1">
                            {tabs.map((tab) => {
                                const Icon = tab.icon;
                                return (
                                    <button
                                        key={tab.id}
                                        onClick={() => setActiveTab(tab.id)}
                                        className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium transition-all ${
                                            activeTab === tab.id
                                                ? 'bg-neon-green/10 text-neon-green'
                                                : 'text-gray-400 hover:text-white hover:bg-white/5'
                                        }`}
                                    >
                                        <Icon className="w-4 h-4" />
                                        {tab.label}
                                    </button>
                                );
                            })}
                        </div>
                    </div>

                    {/* Content */}
                    <div className="lg:col-span-3">
                        <div className="glass rounded-2xl p-6">
                            {activeTab === "profile" && (
                                <div className="space-y-6">
                                    <h2 className="text-xl font-semibold text-white">Profile Settings</h2>
                                    <div className="space-y-4">
                                        <div>
                                            <label className="block text-sm font-medium text-gray-300 mb-2">
                                                Display Name
                                            </label>
                                            <input
                                                type="text"
                                                placeholder="Your name"
                                                className="w-full px-4 py-3 bg-white/5 border border-white/10 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-neon-green focus:ring-1 focus:ring-neon-green"
                                            />
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium text-gray-300 mb-2">
                                                Email
                                            </label>
                                            <input
                                                type="email"
                                                placeholder="your@email.com"
                                                disabled
                                                className="w-full px-4 py-3 bg-white/5 border border-white/10 rounded-xl text-gray-400 cursor-not-allowed"
                                            />
                                        </div>
                                    </div>
                                </div>
                            )}

                            {activeTab === "notifications" && (
                                <div className="space-y-6">
                                    <h2 className="text-xl font-semibold text-white">Notification Preferences</h2>
                                    <div className="space-y-4">
                                        {[
                                            { id: "email", label: "Email Notifications", desc: "Receive scan completion alerts via email" },
                                            { id: "critical", label: "Critical Alerts", desc: "Get notified immediately for critical vulnerabilities" },
                                            { id: "weekly", label: "Weekly Summary", desc: "Receive a weekly summary of all scan activities" },
                                        ].map((item) => (
                                            <div key={item.id} className="flex items-center justify-between p-4 rounded-xl bg-white/5">
                                                <div>
                                                    <h3 className="text-white font-medium">{item.label}</h3>
                                                    <p className="text-sm text-gray-400">{item.desc}</p>
                                                </div>
                                                <label className="relative inline-flex items-center cursor-pointer">
                                                    <input type="checkbox" className="sr-only peer" />
                                                    <div className="w-11 h-6 bg-white/10 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-neon-green"></div>
                                                </label>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}

                            {activeTab === "security" && (
                                <div className="space-y-6">
                                    <h2 className="text-xl font-semibold text-white">Security Settings</h2>
                                    <div className="p-4 rounded-xl bg-white/5">
                                        <h3 className="text-white font-medium mb-2">Two-Factor Authentication</h3>
                                        <p className="text-sm text-gray-400 mb-4">Add an extra layer of security to your account</p>
                                        <button className="px-4 py-2 bg-neon-green/10 text-neon-green rounded-lg text-sm font-medium hover:bg-neon-green/20 transition-colors">
                                            Enable 2FA
                                        </button>
                                    </div>
                                </div>
                            )}

                            {activeTab === "api" && (
                                <div className="space-y-6">
                                    <h2 className="text-xl font-semibold text-white">API Keys</h2>
                                    <div className="p-4 rounded-xl bg-white/5">
                                        <h3 className="text-white font-medium mb-2">Your API Key</h3>
                                        <p className="text-sm text-gray-400 mb-4">Use this key to authenticate API requests</p>
                                        <div className="flex gap-2">
                                            <input
                                                type="password"
                                                value="************************"
                                                disabled
                                                className="flex-1 px-4 py-2 bg-black/20 border border-white/10 rounded-lg text-gray-400 font-mono text-sm"
                                            />
                                            <button className="px-4 py-2 bg-white/10 text-white rounded-lg text-sm hover:bg-white/20 transition-colors">
                                                Reveal
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            )}

                            <div className="pt-6 border-t border-white/5">
                                <button
                                    onClick={handleSave}
                                    disabled={isSaving}
                                    className="px-6 py-3 bg-neon-green text-cyber-dark font-bold rounded-xl hover:shadow-neon-green transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
                                >
                                    {isSaving ? (
                                        <>
                                            <div className="w-4 h-4 border-2 border-cyber-dark/30 border-t-cyber-dark rounded-full animate-spin" />
                                            Saving...
                                        </>
                                    ) : (
                                        <>
                                            <Save className="w-4 h-4" />
                                            Save Changes
                                        </>
                                    )}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
