import type { Metadata } from "next"
import "./globals.css"
import { AppLayout } from "@/components/layout/app-layout"

export const metadata: Metadata = {
  title: "VulnGuard - Security Scanner",
  description: "Automated security vulnerability scanner for web applications",
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="zh" className="dark">
      <body>
        <AppLayout>{children}</AppLayout>
      </body>
    </html>
  )
}
