"use client"

import { useEffect } from "react"
import { ShieldAlert, RefreshCw } from "lucide-react"

export default function ErrorPage({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  useEffect(() => {
    console.error("Page error:", error)
  }, [error])

  return (
    <div className="flex flex-col items-center justify-center min-h-[60vh] text-center">
      <ShieldAlert className="h-16 w-16 text-destructive mb-6" />
      <h1 className="text-4xl font-bold tracking-tight mb-2">500</h1>
      <p className="text-muted-foreground mb-2">Internal server error</p>
      <p className="text-sm text-muted-foreground/60 mb-6 max-w-md">
        {error.message || "An unexpected error occurred. Please try again."}
      </p>
      <button
        onClick={reset}
        className="inline-flex items-center gap-2 text-sm font-medium text-primary hover:underline"
      >
        <RefreshCw className="h-4 w-4" />
        Try again
      </button>
    </div>
  )
}
