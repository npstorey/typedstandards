import type { Metadata } from "next";
import { Space_Grotesk, Noto_Sans } from "next/font/google";
import Link from "next/link";
import "./globals.css";

const spaceGrotesk = Space_Grotesk({
  variable: "--font-space-grotesk",
  subsets: ["latin"],
  weight: ["500", "600", "700"],
});

const notoSans = Noto_Sans({
  variable: "--font-noto-sans",
  subsets: ["latin"],
  weight: ["400", "500", "600"],
});

export const metadata: Metadata = {
  metadataBase: new URL("https://typedstandards.org"),
  title: {
    default: "Typed Standards",
    template: "%s · Typed Standards",
  },
  description:
    "A standard for verifiable, signed evidence packages — and an independent verifier you can run yourself, in your own browser.",
  openGraph: {
    title: "Typed Standards",
    description:
      "A standard for verifiable, signed evidence packages — and an independent verifier you can run yourself.",
    type: "website",
    url: "https://typedstandards.org",
  },
  twitter: {
    card: "summary_large_image",
    title: "Typed Standards",
    description:
      "A standard for verifiable, signed evidence packages — and an independent verifier you can run yourself.",
  },
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body className={`${spaceGrotesk.variable} ${notoSans.variable} font-sans`}>
        <div className="flex min-h-dvh flex-col">
          <header className="border-b border-border">
            <div className="mx-auto flex max-w-5xl items-center justify-between px-6 py-4">
              <Link
                href="/"
                className="font-display text-lg font-semibold tracking-tight"
              >
                Typed<span className="text-accent">Standards</span>
              </Link>
              <nav className="flex items-center gap-6 text-sm">
                <Link href="/verify" className="hover:text-accent">
                  Verify
                </Link>
                <Link href="/badge" className="hover:text-accent">
                  Badge
                </Link>
                <a
                  href="https://github.com/npstorey/typedstandards"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-muted hover:text-accent"
                >
                  GitHub
                </a>
              </nav>
            </div>
          </header>

          <main className="flex-1">{children}</main>

          <footer className="border-t border-border">
            <div className="mx-auto flex max-w-5xl flex-col items-center gap-2 px-6 py-8 text-center text-sm text-muted">
              <p>
                Typed Standards — verifiable, signed evidence. Verification runs
                in your browser; nothing is uploaded.
              </p>
              <p className="text-xs">
                By{" "}
                <a
                  href="https://nathanstorey.com"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="hover:text-accent"
                >
                  Nathan Storey
                </a>
              </p>
            </div>
          </footer>
        </div>
      </body>
    </html>
  );
}
