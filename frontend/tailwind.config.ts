import type { Config } from "tailwindcss";

const config: Config = {
    content: [
        "./pages/**/*.{js,ts,jsx,tsx,mdx}",
        "./components/**/*.{js,ts,jsx,tsx,mdx}",
        "./app/**/*.{js,ts,jsx,tsx,mdx}",
    ],
    theme: {
        extend: {
            colors: {
                border: "hsl(var(--border))",
                background: "hsl(var(--background))",
                foreground: "hsl(var(--foreground))",
                critical: {
                    DEFAULT: "hsl(0, 84%, 60%)",
                    foreground: "hsl(0, 0%, 100%)",
                },
                high: {
                    DEFAULT: "hsl(25, 95%, 53%)",
                    foreground: "hsl(0, 0%, 100%)",
                },
                medium: {
                    DEFAULT: "hsl(45, 93%, 47%)",
                    foreground: "hsl(0, 0%, 0%)",
                },
                low: {
                    DEFAULT: "hsl(142, 71%, 45%)",
                    foreground: "hsl(0, 0%, 100%)",
                },
            },
        },
    },
    plugins: [],
};

export default config;
