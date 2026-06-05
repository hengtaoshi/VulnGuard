import Link from "next/link"
import { ShieldAlert } from "lucide-react"

export default function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center min-h-[60vh] text-center">
      <ShieldAlert className="h-16 w-16 text-destructive mb-6" />
      <h1 className="text-4xl font-bold tracking-tight mb-2">404</h1>
      <p className="text-muted-foreground mb-6">Page not found</p>
      <Link
        href="/"
        className="inline-flex items-center gap-2 text-sm font-medium text-primary hover:underline"
      >
        Back to Dashboard
      </Link>
    </div>
  )
}
