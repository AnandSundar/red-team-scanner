import { SignIn } from "@clerk/nextjs";
import { Shield } from "lucide-react";

export default function SignInPage() {
    return (
        <div className="min-h-screen flex items-center justify-center px-4 py-12">
            <div className="w-full max-w-md">
                {/* Logo */}
                <div className="text-center mb-8">
                    <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-neon-green/10 mb-4">
                        <Shield className="w-8 h-8 text-neon-green" />
                    </div>
                    <h1 className="text-2xl font-bold text-white">Welcome Back</h1>
                    <p className="text-gray-400 mt-2">Sign in to access your security dashboard</p>
                </div>

                {/* Sign In Component */}
                <div className="glass rounded-2xl p-8">
                    <SignIn 
                        appearance={{
                            elements: {
                                card: "bg-transparent shadow-none",
                                headerTitle: "hidden",
                                headerSubtitle: "hidden",
                                socialButtonsBlockButton: "bg-white/5 border-white/10 text-white hover:bg-white/10",
                                formFieldLabel: "text-gray-300",
                                formFieldInput: "bg-white/5 border-white/10 text-white focus:border-neon-green focus:ring-neon-green",
                                formButtonPrimary: "bg-neon-green text-cyber-dark hover:bg-neon-green/90",
                                footerActionText: "text-gray-400",
                                footerActionLink: "text-neon-green hover:text-neon-green/80",
                                identityPreviewText: "text-white",
                                identityPreviewEditButton: "text-neon-green",
                                formFieldWarningText: "text-yellow-400",
                                formFieldErrorText: "text-red-400",
                                alertText: "text-red-400",
                                dividerLine: "bg-white/10",
                                dividerText: "text-gray-500",
                                otpCodeFieldInput: "bg-white/5 border-white/10 text-white",
                            }
                        }}
                    />
                </div>

                {/* Back Link */}
                <p className="text-center mt-6 text-gray-400 text-sm">
                    Don't have an account?{" "}
                    <a href="/sign-up" className="text-neon-green hover:underline">
                        Sign up
                    </a>
                </p>
            </div>
        </div>
    );
}
