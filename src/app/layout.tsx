import type { Metadata, Viewport } from "next";
import "./globals.css";
import { I18nProvider } from "@/lib/ui/i18n";
import { ThemeProvider } from "@/lib/ui/theme";
import { ToastProvider } from "@/lib/ui/toast";
import { SessionProvider } from "@/lib/ui/session";

export const metadata: Metadata = {
  title: {
    default: "SENTINEL — منصة استخبارات الأمن",
    template: "%s · SENTINEL",
  },
  description:
    "SENTINEL — منصة استخبارات الأمن: فحص استباقي بأدلة قابلة للإعادة، تغطية مُوثّقة، وحدود معلنة بلا تهويل.",
  applicationName: "SENTINEL",
  robots: { index: false, follow: false },
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  themeColor: [
    { media: "(prefers-color-scheme: dark)", color: "#0b1222" },
    { media: "(prefers-color-scheme: light)", color: "#f6f8fb" },
  ],
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="ar" dir="rtl" className="dark" suppressHydrationWarning>
      <body className="min-h-dvh bg-background text-foreground">
        <ThemeProvider>
          <I18nProvider>
            <ToastProvider>
              <SessionProvider>{children}</SessionProvider>
            </ToastProvider>
          </I18nProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
