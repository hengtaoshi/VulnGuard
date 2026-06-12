"use client"

import { createContext, useContext, useState, useCallback, type ReactNode } from "react"
import { zh, type TranslationDict } from "./zh"
import { en } from "./en"

type Locale = "zh" | "en"

interface I18nContextType {
  locale: Locale
  t: (path: string, params?: Record<string, string | number>) => string
  setLocale: (locale: Locale) => void
}

const I18nContext = createContext<I18nContextType | null>(null)

const dictionaries: Record<Locale, TranslationDict> = { zh, en }
const STORAGE_KEY = "vulnguard-locale"

function resolvePath(obj: TranslationDict, path: string): string | undefined {
  const keys = path.split(".")
  let current: unknown = obj
  for (const key of keys) {
    if (current == null || typeof current !== "object") return undefined
    current = (current as Record<string, unknown>)[key]
  }
  return typeof current === "string" ? current : undefined
}

function interpolate(text: string, params?: Record<string, string | number>): string {
  if (!params) return text
  return text.replace(/\{\{(\w+)\}\}/g, (_, key) => {
    const val = params[key]
    return val != null ? String(val) : `{{${key}}}`
  })
}

function getInitialLocale(): Locale {
  if (typeof window !== "undefined") {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored === "zh" || stored === "en") return stored
  }
  return "zh"
}

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(getInitialLocale())

  const setLocale = useCallback((next: Locale) => {
    setLocaleState(next)
    try {
      localStorage.setItem(STORAGE_KEY, next)
    } catch { /* noop */ }
  }, [])

  const t = useCallback(
    (path: string, params?: Record<string, string | number>): string => {
      const raw = resolvePath(dictionaries[locale], path)
      if (raw == null) return path
      return interpolate(raw, params)
    },
    [locale],
  )

  return (
    <I18nContext.Provider value={{ locale, t, setLocale }}>
      {children}
    </I18nContext.Provider>
  )
}

export function useI18n() {
  const ctx = useContext(I18nContext)
  if (!ctx) throw new Error("useI18n must be used within I18nProvider")
  return ctx
}
