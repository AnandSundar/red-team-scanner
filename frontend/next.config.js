/** @type {import('next').NextConfig} */
const nextConfig = {
    // Enable standalone output for Docker
    output: 'standalone',
    // Disable image optimization in production build (optional, can be enabled)
    images: {
        domains: ['localhost'],
        unoptimized: process.env.NODE_ENV === 'development',
    },
    // API rewrites to backend service
    async rewrites() {
        return [
            {
                source: '/api/v1/:path*',
                destination: `${process.env.API_URL || 'http://localhost:8080'}/api/v1/:path*`,
            },
            {
                source: '/sse/:path*',
                destination: `${process.env.API_URL || 'http://localhost:8080'}/sse/:path*`,
            },
        ];
    },
    // Headers for security
    async headers() {
        return [
            {
                source: '/:path*',
                headers: [
                    {
                        key: 'X-DNS-Prefetch-Control',
                        value: 'on',
                    },
                    {
                        key: 'X-XSS-Protection',
                        value: '1; mode=block',
                    },
                    {
                        key: 'X-Frame-Options',
                        value: 'SAMEORIGIN',
                    },
                    {
                        key: 'X-Content-Type-Options',
                        value: 'nosniff',
                    },
                    {
                        key: 'Referrer-Policy',
                        value: 'strict-origin-when-cross-origin',
                    },
                ],
            },
        ];
    },
    // Environment variables that should be available at build time
    env: {
        NEXT_PUBLIC_APP_VERSION: process.env.NEXT_PUBLIC_APP_VERSION || '1.0.0',
    },
    // TypeScript configuration
    typescript: {
        // Dangerously allow production builds to successfully complete even if
        // your project has type errors (not recommended for production)
        ignoreBuildErrors: process.env.NODE_ENV === 'development',
    },
    // ESLint configuration
    eslint: {
        // Allow production builds to successfully complete even if
        // your project has ESLint errors (not recommended for production)
        ignoreDuringBuilds: process.env.NODE_ENV === 'development',
    },
    // webpack configuration for Docker compatibility
    webpack: (config, { isServer }) => {
        // Fix for webpack watching in Docker
        config.watchOptions = {
            poll: 1000,
            aggregateTimeout: 300,
        };
        return config;
    },
};

module.exports = nextConfig;
