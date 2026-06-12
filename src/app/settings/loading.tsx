export default function SettingsLoading() {
  return (
    <div className="animate-in fade-in duration-500 p-4 md:p-6 space-y-6">
      {/* Header skeleton */}
      <div className="h-8 w-32 bg-muted rounded-md animate-pulse" />
      <div className="h-4 w-56 bg-muted rounded-md animate-pulse" />

      {/* Settings cards skeleton */}
      <div className="space-y-4">
        {Array.from({ length: 3 }).map((_, i) => (
          <div key={i} className="rounded-xl border border-border bg-card p-5 space-y-4">
            <div className="flex items-center gap-3">
              <div className="h-8 w-8 rounded-lg bg-muted animate-pulse" />
              <div className="space-y-1">
                <div className="h-5 w-32 bg-muted rounded animate-pulse" />
                <div className="h-3 w-48 bg-muted rounded animate-pulse" />
              </div>
            </div>
            <div className="h-10 w-full bg-muted rounded-lg animate-pulse" />
          </div>
        ))}
      </div>
    </div>
  )
}
