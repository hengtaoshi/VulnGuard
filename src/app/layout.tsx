import type { Metadata } from "next"
import { Inter, JetBrains_Mono } from "next/font/google"
import "./globals.css"
import { AppLayout } from "@/components/layout/app-layout"

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
  display: "swap",
})

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-mono",
  display: "swap",
})

export const metadata: Metadata = {
  title: "VulnGuard - Security Scanner",
  description: "Automated security vulnerability scanner for web applications",
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
