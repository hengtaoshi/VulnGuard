"use client"

import { useState } from "react"
import { I18nProvider } from "@/lib/i18n/context"
import { Providers } from "@/app/providers"
import { ErrorBoundary } from "@/components/ui/error-boundary"
import { Sidebar } from "./sidebar"
import { Header } from "./header"
import { UpdateBanner } from "./update-banner"
import { InstallProgressProvider } from "@/lib/install-context"

export function AppLayout({ children }: { children: React.ReactNode }) {
  const [sidebarOpen, setSidebarOpen] = useState(false)

  return (
    <I18nProvider>
      <Providers>
        <InstallProgressProvider>
          <div className="min-h-screen">
            <Sidebar isOpen={sidebarOpen} onClose={() => setSidebarOpen(false)} />
            <div className="md:pl-60">
              <Header onMenuClick={() => setSidebarOpen(true)} />
              <UpdateBanner />
              <main className="p-4 md:p-6">
                <ErrorBoundary>{children}</ErrorBoundary>
              </main>
            </div>
          </div>
        </InstallProgressProvider>
      </Providers>
    </I18nProvider>
  )
}
