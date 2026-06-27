"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { cn } from "@/lib/utils"
import { useI18n } from "@/lib/i18n/context"
import { Shield, LayoutDashboard, Search, History, FileText, Server, Settings, X } from "lucide-react"

const navItems = [
  { href: "/", label: "nav.dashboard", icon: LayoutDashboard },
  { href: "/scan/new", label: "nav.newScan", icon: Search },
  { href: "/scan/history", label: "nav.scanHistory", icon: History },
  { href: "/scanners", label: "nav.scanners", icon: Server },
  { href: "/reports", label: "nav.reports", icon: FileText },
  { href: "/settings", label: "nav.settings", icon: Settings },
]

interface SidebarProps {
  isOpen?: boolean
  onClose?: () => void
}

export function Sidebar({ isOpen, onClose }: SidebarProps) {
  const pathname = usePathname()
  const { t } = useI18n()

  const sidebarContent = (
    <>
      <div className="flex h-14 items-center gap-2 border-b border-border px-6">
        <Shield className="h-6 w-6 text-primary" />
        <span className="font-bold text-lg tracking-tight">
          Vuln<span className="text-primary">Guard</span>
        </span>
        <span className="bg-primary/15 text-primary text-[10px] px-1.5 py-0.5 rounded font-medium ml-1">
          {t("app.beta")}
        </span>
        {onClose && (
          <button onClick={onClose} className="ml-auto p-1 text-muted-foreground hover:text-foreground md:hidden">
            <X className="h-5 w-5" />
          </button>
        )}
      </div>
      <nav className="space-y-1 p-4" aria-label="Main navigation">
        {navItems.map(item => {
          const isActive = pathname === item.href
          return (
            <Link
              key={item.href}
              href={item.href}
              onClick={onClose}
              aria-current={isActive ? "page" : undefined}
              aria-label={t(item.label)}
              className={cn(
                "flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors",
                isActive
                  ? "bg-primary/10 text-primary"
                  : "text-muted-foreground hover:text-foreground hover:bg-accent",
              )}
            >
              <item.icon className="h-4 w-4" />
              {t(item.label)}
            </Link>
          )
        })}
      </nav>
    </>
  )

  return (
    <>
      {/* Desktop sidebar */}
      <aside className="fixed left-0 top-0 z-40 hidden md:flex h-screen w-60 flex-col border-r border-border bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        {sidebarContent}
      </aside>

      {/* Mobile overlay */}
      {isOpen && (
        <>
          <div className="fixed inset-0 z-40 bg-black/50 md:hidden" onClick={onClose} />
          <aside className="fixed left-0 top-0 z-50 flex h-screen w-60 flex-col border-r border-border bg-background md:hidden animate-in slide-in-from-left">
            {sidebarContent}
          </aside>
        </>
      )}
    </>
  )
}
