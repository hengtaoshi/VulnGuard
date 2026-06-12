export default function ReportsLoading() {
  return (
    <div className="animate-in fade-in duration-500 p-4 md:p-6 space-y-6">
      {/* Header skeleton */}
      <div className="h-8 w-32 bg-muted rounded-md animate-pulse" />
      <div className="h-4 w-56 bg-muted rounded-md animate-pulse" />

      {/* Filter bar skeleton */}
      <div className="flex gap-3">
        <div className="h-10 w-48 bg-muted rounded-lg animate-pulse" />
        <div className="h-10 w-32 bg-muted rounded-lg animate-pulse" />
      </div>

      {/* Report cards skeleton */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {Array.from({ length: 6 }).map((_, i) => (
          <div key={i} className="rounded-xl border border-border bg-card p-5 space-y-3">
            <div className="h-5 w-3/4 bg-muted rounded animate-pulse" />
            <div className="h-3 w-1/2 bg-muted rounded animate-pulse" />
            <div className="flex gap-2 mt-3">
              <div className="h-6 w-16 rounded-full bg-muted animate-pulse" />
              <div className="h-6 w-16 rounded-full bg-muted animate-pulse" />
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
