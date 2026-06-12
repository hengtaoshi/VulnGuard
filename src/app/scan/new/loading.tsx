export default function ScanNewLoading() {
  return (
    <div className="animate-in fade-in duration-500 p-4 md:p-6 space-y-6">
      {/* Header skeleton */}
      <div className="h-8 w-36 bg-muted rounded-md animate-pulse" />
      <div className="h-4 w-64 bg-muted rounded-md animate-pulse" />

      {/* Upload zone skeleton */}
      <div className="rounded-xl border-2 border-dashed border-border bg-card p-12">
        <div className="flex flex-col items-center gap-4">
          <div className="h-12 w-12 rounded-full bg-muted animate-pulse" />
          <div className="h-5 w-48 bg-muted rounded animate-pulse" />
          <div className="h-4 w-64 bg-muted rounded animate-pulse" />
        </div>
      </div>

      {/* Options skeleton */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {Array.from({ length: 2 }).map((_, i) => (
          <div key={i} className="rounded-xl border border-border bg-card p-5 space-y-3">
            <div className="h-5 w-28 bg-muted rounded animate-pulse" />
            <div className="h-12 w-full bg-muted rounded animate-pulse" />
          </div>
        ))}
      </div>
    </div>
  )
}
