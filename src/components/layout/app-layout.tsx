"use client"

import { useState, useEffect } from "react"
import { I18nProvider } from "@/lib/i18n/context"
import { Providers } from "@/app/providers"
import { ErrorBoundary } from "@/components/ui/error-boundary"
import { Sidebar } from "./sidebar"
import { Header } from "./header"
import { TitleBar } from "./titlebar"
import { UpdateBanner } from "./update-banner"
import { SetupWizard } from "@/components/scanner/setup-wizard"
import { InstallProgressProvider } from "@/lib/install-context"

export function AppLayout({ children }: { children: React.ReactNode }) {
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [showWizard, setShowWizard] = useState(false)

  // 检测是否需要弹出安装向导（首次安装 或 升级后归档未解压）
  useEffect(() => {
    try {
      const onboarded = localStorage.getItem("vulnguard-onboarded")

      if (onboarded === "true" && typeof window !== "undefined" && window.vulnguard?.getScannerStatus) {
        window.vulnguard.getScannerStatus().then((status) => {
          if (!status.archiveExtracted) setShowWizard(true)
        }).catch(() => {})
        return
      }

      if (onboarded !== "true") setShowWizard(true)
    } catch { /* SSR */ }
  }, [])

  return (
    <I18nProvider>
      <Providers>
        <InstallProgressProvider>
          <div className="relative min-h-screen">
            <TitleBar />
            <div className="pt-9 flex">
              <Sidebar isOpen={sidebarOpen} onClose={() => setSidebarOpen(false)} />
              <div className="flex-1 md:pl-60 flex flex-col">
                <Header onMenuClick={() => setSidebarOpen(true)} />
                <UpdateBanner />
                <main className="p-4 md:p-6 flex-1">
                  <ErrorBoundary>{children}</ErrorBoundary>
                </main>
              </div>
            </div>
          </div>

          {/* 安装向导 — 在 AppLayout 层级渲染，避免父级 CSS 影响 fixed 定位 */}
          <SetupWizard
            open={showWizard}
            onFinish={() => {
              setShowWizard(false)
              try { localStorage.setItem("vulnguard-onboarded", "true") } catch {}
            }}
          />
        </InstallProgressProvider>
      </Providers>
    </I18nProvider>
  )
}
