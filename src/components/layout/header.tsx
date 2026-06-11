"use client"

import { Plus, Languages, Menu } from "lucide-react"
import { Button } from "@/components/ui/button"
import { usePathname } from "next/navigation"
import Link from "next/link"
import { useI18n } from "@/lib/i18n/context"
import { cn } from "@/lib/utils"

const pageTitles: Record<string, string> = {
  "/": "nav.dashboard",
  "/scan/new": "nav.newScan",
  "/scan/history": "nav.scanHistory",
  "/reports": "nav.reports",
  "/settings": "nav.settings",
}

interface HeaderProps {
  onMenuClick?: () => void
}

export function Header({ onMenuClick }: HeaderProps) {
  const pathname = usePathname()
  const { t, locale, setLocale } = useI18n()
  const title = pageTitles[pathname] || "app.name"

  return (
    <header className="sticky top-0 z-30 flex h-14 items-center gap-4 border-b border-border bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60 px-4 md:px-6">
      <button onClick={onMenuClick} className="p-1 -ml-1 text-muted-foreground hover:text-foreground md:hidden" aria-label="Toggle navigation menu">
        <Menu className="h-5 w-5" />
      </button>

      <div className="flex-1">
        <h1 className="text-lg font-semibold">{t(title)}</h1>
      </div>

      <div className="flex items-center gap-2 md:gap-3">
        {/* Language Toggle */}
        <button
          onClick={() => setLocale(locale === "zh" ? "en" : "zh")}
          className={cn(
            "flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs font-medium transition-colors",
            "border border-border hover:border-primary/50 hover:text-primary",
          )}
          title={locale === "zh" ? "Switch to English" : "切换到中文"}
          aria-label={locale === "zh" ? "Switch to English" : "切换语言"}
        >
          <Languages className="h-3.5 w-3.5" />
          <span className="hidden sm:inline">{locale === "zh" ? "EN" : "中文"}</span>
        </button>

        {pathname !== "/scan/new" && (
          <Link href="/scan/new">
            <Button size="sm" className="gap-1.5">
              <Plus className="h-4 w-4" />
              <span className="hidden sm:inline">{t("header.newScan")}</span>
            </Button>
          </Link>
        )}

      </div>
    </header>
  )
}
