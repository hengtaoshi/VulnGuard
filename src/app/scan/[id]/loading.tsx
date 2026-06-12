export default function ScanDetailLoading() {
  return (
    <div className="animate-in fade-in duration-500 p-4 md:p-6 space-y-6">
      {/* Back button + title skeleton */}
      <div className="flex items-center gap-3">
        <div className="h-8 w-8 rounded-md bg-muted animate-pulse" />
        <div className="h-6 w-48 bg-muted rounded-md animate-pulse" />
      </div>

      {/* Progress card skeleton */}
      <div className="rounded-xl border border-border bg-card p-6 space-y-4">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-full bg-muted animate-pulse" />
          <div className="space-y-2 flex-1">
            <div className="h-5 w-36 bg-muted rounded animate-pulse" />
            <div className="h-3 w-56 bg-muted rounded animate-pulse" />
          </div>
        </div>
        {/* Progress bar */}
        <div className="h-2 w-full bg-muted rounded-full animate-pulse" />
        {/* Scanner statuses */}
        <div className="space-y-2">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="flex items-center gap-3">
              <div className="h-5 w-5 rounded bg-muted animate-pulse" />
              <div className="h-4 w-32 bg-muted rounded animate-pulse" />
              <div className="h-4 w-20 bg-muted rounded animate-pulse ml-auto" />
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
