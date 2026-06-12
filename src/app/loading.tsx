export default function Loading() {
  return (
    <div className="animate-in fade-in duration-500 p-4 md:p-6 space-y-6">
      {/* Page title skeleton */}
      <div className="h-8 w-48 bg-muted rounded-md animate-pulse" />
      <div className="h-4 w-72 bg-muted rounded-md animate-pulse" />

      {/* Stats cards skeleton */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="rounded-xl border border-border bg-card p-5 space-y-3">
            <div className="h-4 w-24 bg-muted rounded animate-pulse" />
            <div className="h-8 w-16 bg-muted rounded animate-pulse" />
            <div className="h-3 w-32 bg-muted rounded animate-pulse" />
          </div>
        ))}
      </div>

      {/* Chart skeleton */}
      <div className="rounded-xl border border-border bg-card p-5">
        <div className="h-5 w-32 bg-muted rounded animate-pulse mb-4" />
        <div className="h-64 bg-muted/50 rounded animate-pulse" />
      </div>

      {/* Table rows skeleton */}
      <div className="rounded-xl border border-border bg-card p-5">
        <div className="h-5 w-40 bg-muted rounded animate-pulse mb-4" />
        <div className="space-y-3">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="flex items-center gap-4">
              <div className="h-4 w-4 rounded-full bg-muted animate-pulse" />
              <div className="h-4 flex-1 bg-muted rounded animate-pulse" />
              <div className="h-4 w-20 bg-muted rounded animate-pulse" />
              <div className="h-4 w-16 bg-muted rounded animate-pulse" />
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
