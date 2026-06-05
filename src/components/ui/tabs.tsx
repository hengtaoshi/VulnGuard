"use client"

import * as React from "react"
import { cn } from "@/lib/utils"

interface TabsProps {
  tabs: { id: string; label: string; content: React.ReactNode }[]
  defaultTab?: string
  className?: string
}

export function Tabs({ tabs, defaultTab, className }: TabsProps) {
  const [active, setActive] = React.useState(defaultTab || tabs[0]?.id)

  return (
    <div className={className}>
      <div className="flex border-b border-border">
        {tabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActive(tab.id)}
            className={`px-4 py-2 text-sm font-medium transition-colors ${
              active === tab.id
                ? "text-primary border-b-2 border-primary"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>
      <div className="mt-4">
        {tabs.find(t => t.id === active)?.content}
      </div>
    </div>
  )
}
