import type { Metadata } from "next";
import { Fraunces, IBM_Plex_Sans, IBM_Plex_Mono } from "next/font/google";
import { SiteFooter, SiteHeader } from "@/components/SiteChrome";
import "./globals.css";

const display = Fraunces({
  variable: "--font-display",
  subsets: ["latin"],
  weight: ["600", "700"],
});

const body = IBM_Plex_Sans({
  variable: "--font-body",
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
});

const mono = IBM_Plex_Mono({
  variable: "--font-code",
  subsets: ["latin"],
  weight: ["400", "500"],
});

const siteUrl =
  process.env.NEXT_PUBLIC_SITE_URL ??
  "https://himat.tech/free-tools/ai-prompt-security-scanner";

export const metadata: Metadata = {
  metadataBase: new URL("https://himat.tech"),
  title: "AI Prompt Security & Injection Scanner | HIMAT Technology",
  description:
    "Scan AI prompts, system instructions, MCP payloads, and agent inputs for prompt injection, jailbreaks, API key leaks, PII exposure, and data exfiltration entirely in your browser.",
  keywords: [
    "prompt injection scanner",
    "AI prompt security",
    "jailbreak detection",
    "MCP security",
    "PII detection",
    "API key leak",
    "client-side security scanner",
    "HIMAT Technology",
  ],
  authors: [{ name: "HIMAT Technology" }],
  alternates: {
    canonical: "/free-tools/ai-prompt-security-scanner",
  },
  openGraph: {
    type: "website",
    url: siteUrl,
    title: "AI Prompt Security & Injection Scanner | HIMAT Technology",
    description:
      "Scan AI prompts, system instructions, MCP payloads, and agent inputs for prompt injection, jailbreaks, API key leaks, PII exposure, and data exfiltration entirely in your browser.",
    siteName: "HIMAT Technology",
  },
  twitter: {
    card: "summary_large_image",
    title: "AI Prompt Security & Injection Scanner | HIMAT Technology",
    description:
      "100% browser-local scanner for prompt injection, jailbreaks, secrets, PII, and exfiltration risks.",
  },
  robots: {
    index: true,
    follow: true,
  },
};

const jsonLd = {
  "@context": "https://schema.org",
  "@type": "WebApplication",
  name: "AI Prompt Security & Injection Scanner",
  applicationCategory: "SecurityApplication",
  operatingSystem: "Any",
  offers: {
    "@type": "Offer",
    price: "0",
    priceCurrency: "USD",
  },
  description:
    "Scan AI prompts, system instructions, MCP payloads, and agent inputs for prompt injection, jailbreaks, API key leaks, PII exposure, and data exfiltration entirely in your browser.",
  url: siteUrl,
  publisher: {
    "@type": "Organization",
    name: "HIMAT Technology",
    url: "https://himat.co.in",
    email: "info@himat.co.in",
    telephone: "+91-94452-34023",
    sameAs: [
      "https://www.facebook.com/people/Himat-technology/61593829197445/",
      "https://www.linkedin.com/company/himat-technology",
      "https://www.instagram.com/himat_technology/",
    ],
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        className={`${display.variable} ${body.variable} ${mono.variable} min-h-screen antialiased`}
      >
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
        />
        <div className="relative min-h-screen overflow-x-hidden">
          <div
            className="pointer-events-none absolute inset-0 -z-10"
            aria-hidden="true"
          >
            <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,_#0e7490_0%,_#07111f_42%,_#020617_100%)]" />
            <div className="absolute -left-24 top-24 h-72 w-72 rounded-full bg-cyan-400/25 blur-3xl animate-float-soft" />
            <div className="absolute right-0 top-40 h-80 w-80 rounded-full bg-rose-500/20 blur-3xl animate-float-soft-delayed" />
            <div className="absolute bottom-32 left-1/3 h-64 w-64 rounded-full bg-amber-400/15 blur-3xl" />
            <div className="absolute inset-0 opacity-[0.22] [background-image:linear-gradient(to_right,rgba(255,255,255,0.06)_1px,transparent_1px),linear-gradient(to_bottom,rgba(255,255,255,0.06)_1px,transparent_1px)] [background-size:32px_32px]" />
          </div>
          <SiteHeader />
          <main>{children}</main>
          <SiteFooter />
        </div>
      </body>
    </html>
  );
}
