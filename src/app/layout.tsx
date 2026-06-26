import type { Metadata } from "next"
import { Inter, JetBrains_Mono } from "next/font/google"
import "./globals.css"
import { AppLayout } from "@/components/layout/app-layout"

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
  weight: ["300", "400", "500", "600", "700"],
})

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-mono",
  weight: ["400", "500", "600"],
})

export const metadata: Metadata = {
  title: "VulnGuard - Security Scanner",
  description: "Automated security vulnerability scanner for web applications",
  icons: {
    icon: "/favicon.svg",
  },
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="zh" className={`dark ${inter.variable} ${jetbrainsMono.variable}`}>
      <body>
        <AppLayout>{children}</AppLayout>
      </body>
    </html>
  )
}
