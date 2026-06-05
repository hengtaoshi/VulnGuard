# VulnGuard MVP 实施计划 (Phase 1)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 构建 VulnGuard 可演示的 MVP 版本，包含完整的 UI 界面和模拟扫描流程

**Architecture:** Next.js 14 (App Router) + Tailwind CSS + shadcn/ui，Python FastAPI 扫描引擎（MVP 阶段使用模拟数据），Redis + BullMQ 异步队列，PostgreSQL 持久化。预留 LLM 分析引导模块接口，通过结构化 Prompt 框架引导 DeepSeek 等通用大模型进行专业级安全审计。

**Tech Stack:** Next.js 14, TypeScript, Tailwind CSS, shadcn/ui, Recharts, Python FastAPI, Redis, PostgreSQL, Prisma, Docker

---

### Task 1: 项目初始化与基础配置

**Files:**
- Create: `D:/DEMO/aut/package.json`
- Create: `D:/DEMO/aut/tsconfig.json`
- Create: `D:/DEMO/aut/next.config.ts`
- Create: `D:/DEMO/aut/tailwind.config.ts`
- Create: `D:/DEMO/aut/postcss.config.js`
- Create: `D:/DEMO/aut/.env.local`
- Create: `D:/DEMO/aut/.gitignore`

- [ ] **Step 1: 创建 package.json**

```json
{
  "name": "vulnguard",
  "version": "0.1.0",
  "private": true,
  "scripts": {
    "dev": "next dev",
    "build": "next build",
    "start": "next start",
    "lint": "next lint"
  },
  "dependencies": {
    "next": "^14.2.0",
    "react": "^18.3.0",
    "react-dom": "^18.3.0",
    "@prisma/client": "^5.0.0",
    "recharts": "^2.12.0",
    "lucide-react": "^0.400.0",
    "class-variance-authority": "^0.7.0",
    "clsx": "^2.1.0",
    "tailwind-merge": "^2.3.0",
    "zod": "^3.23.0"
  },
  "devDependencies": {
    "typescript": "^5.4.0",
    "@types/node": "^20.0.0",
    "@types/react": "^18.3.0",
    "@types/react-dom": "^18.3.0",
    "tailwindcss": "^3.4.0",
    "postcss": "^8.4.0",
    "autoprefixer": "^10.4.0",
    "prisma": "^5.0.0"
  }
}
```

- [ ] **Step 2: 创建 tsconfig.json**

```json
{
  "compilerOptions": {
    "lib": ["dom", "dom.iterable", "esnext"],
    "allowJs": true,
    "skipLibCheck": true,
    "strict": true,
    "noEmit": true,
    "esModuleInterop": true,
    "module": "esnext",
    "moduleResolution": "bundler",
    "resolveJsonModule": true,
    "isolatedModules": true,
    "jsx": "preserve",
    "incremental": true,
    "plugins": [{ "name": "next" }],
    "paths": { "@/*": ["./src/*"] }
  },
  "include": ["next-env.d.ts", "**/*.ts", "**/*.tsx", ".next/types/**/*.ts"],
  "exclude": ["node_modules"]
}
```

- [ ] **Step 3: 创建 next.config.ts**

```ts
/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  images: { domains: [] },
}

module.exports = nextConfig
```

- [ ] **Step 4: 创建 tailwind.config.ts**

```ts
import type { Config } from "tailwindcss"

const config: Config = {
  content: ["./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        border: "hsl(var(--border))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        primary: {
          DEFAULT: "hsl(var(--primary))",
          foreground: "hsl(var(--primary-foreground))",
        },
        destructive: {
          DEFAULT: "hsl(var(--destructive))",
          foreground: "hsl(var(--destructive-foreground))",
        },
        muted: {
          DEFAULT: "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))",
        },
        card: {
          DEFAULT: "hsl(var(--card))",
          foreground: "hsl(var(--card-foreground))",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "monospace"],
      },
      borderRadius: {
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
      },
    },
  },
  plugins: [],
}

export default config
```

- [ ] **Step 5: 创建 postcss.config.js**

```js
module.exports = {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
  },
}
```

- [ ] **Step 6: 创建 .env.local**

```
DATABASE_URL="postgresql://vulnguard:vulnguard@localhost:5432/vulnguard"
REDIS_URL="redis://localhost:6379"
NEXT_PUBLIC_APP_NAME="VulnGuard"
NEXT_PUBLIC_APP_VERSION="0.1.0"
```

- [ ] **Step 7: 创建 .gitignore**

```
node_modules/
.next/
*.local
.env
.env.local
.DS_Store
*.tsbuildinfo
next-env.d.ts
dist/
```

- [ ] **Step 8: 安装依赖**

Run: `cd /d/DEMO/aut && npm install`

---

### Task 2: 创建 CSS 变量与全局样式

**Files:**
- Create: `D:/DEMO/aut/src/app/globals.css`

- [ ] **Step 1: 创建 globals.css**

```css
@tailwind base;
@tailwind components;
@tailwind utilities;

@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

@layer base {
  :root {
    --background: 228 71% 4%;
    --foreground: 210 40% 98%;
    --card: 228 39% 8%;
    --card-foreground: 210 40% 98%;
    --popover: 228 39% 8%;
    --popover-foreground: 210 40% 98%;
    --primary: 142 76% 36%;
    --primary-foreground: 0 0% 0%;
    --secondary: 228 25% 16%;
    --secondary-foreground: 210 40% 98%;
    --muted: 228 25% 16%;
    --muted-foreground: 215 20% 65%;
    --accent: 228 25% 16%;
    --accent-foreground: 210 40% 98%;
    --destructive: 0 84% 60%;
    --destructive-foreground: 210 40% 98%;
    --border: 228 25% 16%;
    --input: 228 25% 16%;
    --ring: 142 76% 36%;
    --radius: 0.5rem;
  }
}

@layer base {
  * {
    @apply border-border;
  }
  body {
    @apply bg-background text-foreground font-sans antialiased;
  }
}

/* Scrollbar styling */
::-webkit-scrollbar {
  width: 6px;
  height: 6px;
}
::-webkit-scrollbar-track {
  background: hsl(228, 39%, 6%);
}
::-webkit-scrollbar-thumb {
  background: hsl(228, 25%, 20%);
  border-radius: 3px;
}
::-webkit-scrollbar-thumb:hover {
  background: hsl(228, 25%, 30%);
}
```

---

### Task 3: 创建 UI 基础组件

**Files:**
- Create: `D:/DEMO/aut/src/lib/utils.ts`
- Create: `D:/DEMO/aut/src/components/ui/button.tsx`
- Create: `D:/DEMO/aut/src/components/ui/card.tsx`
- Create: `D:/DEMO/aut/src/components/ui/badge.tsx`
- Create: `D:/DEMO/aut/src/components/ui/input.tsx`
- Create: `D:/DEMO/aut/src/components/ui/tabs.tsx`

- [ ] **Step 1: 创建 utils.ts**

```ts
import { type ClassValue, clsx } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}
```

- [ ] **Step 2: 创建 button.tsx**

```tsx
import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"

const buttonVariants = cva(
  "inline-flex items-center justify-center whitespace-nowrap rounded-lg text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50",
  {
    variants: {
      variant: {
        default: "bg-primary text-primary-foreground shadow hover:bg-primary/90",
        destructive: "bg-destructive text-destructive-foreground shadow-sm hover:bg-destructive/90",
        outline: "border border-border bg-transparent shadow-sm hover:bg-accent hover:text-accent-foreground",
        secondary: "bg-secondary text-secondary-foreground shadow-sm hover:bg-secondary/80",
        ghost: "hover:bg-accent hover:text-accent-foreground",
        link: "text-primary underline-offset-4 hover:underline",
      },
      size: {
        default: "h-9 px-4 py-2",
        sm: "h-8 rounded-md px-3 text-xs",
        lg: "h-10 rounded-md px-8",
        icon: "h-9 w-9",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  }
)

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, ...props }, ref) => {
    return (
      <button
        className={cn(buttonVariants({ variant, size, className }))}
        ref={ref}
        {...props}
      />
    )
  }
)
Button.displayName = "Button"

export { Button, buttonVariants }
```

- [ ] **Step 3: 创建 card.tsx**

```tsx
import * as React from "react"
import { cn } from "@/lib/utils"

const Card = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div ref={ref} className={cn("rounded-xl border border-border bg-card text-card-foreground shadow-sm", className)} {...props} />
  )
)
Card.displayName = "Card"

const CardHeader = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div ref={ref} className={cn("flex flex-col space-y-1.5 p-6", className)} {...props} />
  )
)
CardHeader.displayName = "CardHeader"

const CardTitle = React.forwardRef<HTMLParagraphElement, React.HTMLAttributes<HTMLHeadingElement>>(
  ({ className, ...props }, ref) => (
    <h3 ref={ref} className={cn("font-semibold leading-none tracking-tight", className)} {...props} />
  )
)
CardTitle.displayName = "CardTitle"

const CardDescription = React.forwardRef<HTMLParagraphElement, React.HTMLAttributes<HTMLParagraphElement>>(
  ({ className, ...props }, ref) => (
    <p ref={ref} className={cn("text-sm text-muted-foreground", className)} {...props} />
  )
)
CardDescription.displayName = "CardDescription"

const CardContent = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div ref={ref} className={cn("p-6 pt-0", className)} {...props} />
  )
)
CardContent.displayName = "CardContent"

export { Card, CardHeader, CardTitle, CardDescription, CardContent }
```

- [ ] **Step 4: 创建 badge.tsx**

```tsx
import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"

const badgeVariants = cva(
  "inline-flex items-center rounded-md border px-2.5 py-0.5 text-xs font-semibold transition-colors",
  {
    variants: {
      variant: {
        default: "border-transparent bg-primary/20 text-primary shadow",
        secondary: "border-transparent bg-secondary text-secondary-foreground",
        destructive: "border-transparent bg-destructive/20 text-destructive shadow",
        warning: "border-transparent bg-amber-500/20 text-amber-500 shadow",
        info: "border-transparent bg-blue-500/20 text-blue-500 shadow",
        success: "border-transparent bg-emerald-500/20 text-emerald-500 shadow",
        outline: "text-foreground",
      },
    },
    defaultVariants: { variant: "default" },
  }
)

export interface BadgeProps extends React.HTMLAttributes<HTMLDivElement>, VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />
}

export { Badge, badgeVariants }
```

- [ ] **Step 5: 创建 input.tsx**

```tsx
import * as React from "react"
import { cn } from "@/lib/utils"

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {}

const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ className, type, ...props }, ref) => {
    return (
      <input
        type={type}
        className={cn(
          "flex h-9 w-full rounded-lg border border-input bg-transparent px-3 py-1 text-sm shadow-sm transition-colors file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50",
          className
        )}
        ref={ref}
        {...props}
      />
    )
  }
)
Input.displayName = "Input"

export { Input }
```

- [ ] **Step 6: 创建 tabs.tsx**

```tsx
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
```

---

### Task 4: 创建布局组件 (Sidebar + Header)

**Files:**
- Create: `D:/DEMO/aut/src/components/layout/sidebar.tsx`
- Create: `D:/DEMO/aut/src/components/layout/header.tsx`
- Create: `D:/DEMO/aut/src/components/layout/app-layout.tsx`

- [ ] **Step 1: 创建 sidebar.tsx**

```tsx
"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { cn } from "@/lib/utils"
import { Shield, LayoutDashboard, Search, History, FileText, Settings } from "lucide-react"

const navItems = [
  { href: "/", label: "Dashboard", icon: LayoutDashboard },
  { href: "/scan/new", label: "New Scan", icon: Search },
  { href: "/scan/history", label: "Scan History", icon: History },
  { href: "/reports", label: "Reports", icon: FileText },
  { href: "/settings", label: "Settings", icon: Settings },
]

export function Sidebar() {
  const pathname = usePathname()

  return (
    <aside className="fixed left-0 top-0 z-40 h-screen w-60 border-r border-border bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="flex h-14 items-center gap-2 border-b border-border px-6">
        <Shield className="h-6 w-6 text-primary" />
        <span className="font-bold text-lg tracking-tight">
          Vuln<span className="text-primary">Guard</span>
        </span>
        <span className="bg-primary/15 text-primary text-[10px] px-1.5 py-0.5 rounded font-medium ml-1">BETA</span>
      </div>
      <nav className="space-y-1 p-4">
        {navItems.map(item => {
          const isActive = pathname === item.href
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors",
                isActive
                  ? "bg-primary/10 text-primary"
                  : "text-muted-foreground hover:text-foreground hover:bg-accent"
              )}
            >
              <item.icon className="h-4 w-4" />
              {item.label}
            </Link>
          )
        })}
      </nav>
    </aside>
  )
}
```

- [ ] **Step 2: 创建 header.tsx**

```tsx
"use client"

import { Bell, Plus } from "lucide-react"
import { Button } from "@/components/ui/button"
import { usePathname } from "next/navigation"
import Link from "next/link"

const pageTitles: Record<string, string> = {
  "/": "Dashboard",
  "/scan/new": "New Scan",
  "/scan/history": "Scan History",
  "/reports": "Reports",
  "/settings": "Settings",
}

export function Header() {
  const pathname = usePathname()
  const title = pageTitles[pathname] || "VulnGuard"

  return (
    <header className="sticky top-0 z-30 flex h-14 items-center gap-4 border-b border-border bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60 px-6">
      <div className="flex-1">
        <h1 className="text-lg font-semibold">{title}</h1>
      </div>
      <div className="flex items-center gap-3">
        {pathname !== "/scan/new" && (
          <Link href="/scan/new">
            <Button size="sm" className="gap-1.5">
              <Plus className="h-4 w-4" />
              New Scan
            </Button>
          </Link>
        )}
        <button className="relative p-2 text-muted-foreground hover:text-foreground transition-colors">
          <Bell className="h-5 w-5" />
          <span className="absolute top-1.5 right-1.5 h-2 w-2 rounded-full bg-destructive" />
        </button>
        <div className="h-8 w-8 rounded-full bg-primary/20 flex items-center justify-center text-sm font-medium text-primary">
          U
        </div>
      </div>
    </header>
  )
}
```

- [ ] **Step 3: 创建 app-layout.tsx**

```tsx
"use client"

import { Sidebar } from "./sidebar"
import { Header } from "./header"

export function AppLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen">
      <Sidebar />
      <div className="pl-60">
        <Header />
        <main className="p-6">
          {children}
        </main>
      </div>
    </div>
  )
}
```

---

### Task 5: 创建根布局与页面路由

**Files:**
- Create: `D:/DEMO/aut/src/app/layout.tsx`
- Create: `D:/DEMO/aut/src/app/page.tsx`
- Create: `D:/DEMO/aut/src/app/scan/new/page.tsx`
- Create: `D:/DEMO/aut/src/app/scan/history/page.tsx`
- Create: `D:/DEMO/aut/src/app/scan/[id]/page.tsx`
- Create: `D:/DEMO/aut/src/app/reports/page.tsx`
- Create: `D:/DEMO/aut/src/app/settings/page.tsx`

- [ ] **Step 1: 创建 layout.tsx**

```tsx
import type { Metadata } from "next"
import "./globals.css"
import { AppLayout } from "@/components/layout/app-layout"

export const metadata: Metadata = {
  title: "VulnGuard - Security Scanner",
  description: "Automated security vulnerability scanner for web applications",
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body>
        <AppLayout>{children}</AppLayout>
      </body>
    </html>
  )
}
```

- [ ] **Step 2: 创建 Dashboard 页面 (src/app/page.tsx)**

```tsx
"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Shield, AlertTriangle, CheckCircle, Activity } from "lucide-react"
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts"

const stats = [
  { label: "Total Scans", value: "24", icon: Shield, change: "+12% this week", color: "text-primary" },
  { label: "Vulnerabilities", value: "47", icon: AlertTriangle, change: "+3 new", color: "text-destructive" },
  { label: "Secure", value: "12", icon: CheckCircle, change: "100% pass rate", color: "text-emerald-500" },
  { label: "Risk Score", value: "B+", icon: Activity, change: "Moderate risk", color: "text-amber-500" },
]

const recentScans = [
  { target: "my-ai-app.com", type: "URL", status: "Completed", risk: "Critical", date: "2m ago" },
  { target: "ecommerce-test.zip", type: "Source", status: "Scanning", risk: "—", date: "15m ago" },
  { target: "blog-platform.vercel.app", type: "URL", status: "Completed", risk: "Secure", date: "1h ago" },
  { target: "dashboard-app.zip", type: "Source", status: "Completed", risk: "High", date: "3h ago" },
  { target: "api-gateway.test.com", type: "URL", status: "Completed", risk: "Medium", date: "5h ago" },
]

const chartData = [
  { name: "Mon", critical: 3, high: 5, medium: 8, low: 12 },
  { name: "Tue", critical: 1, high: 7, medium: 4, low: 9 },
  { name: "Wed", critical: 4, high: 2, medium: 6, low: 15 },
  { name: "Thu", critical: 2, high: 8, medium: 3, low: 11 },
  { name: "Fri", critical: 0, high: 4, medium: 7, low: 8 },
  { name: "Sat", critical: 1, high: 3, medium: 5, low: 6 },
  { name: "Sun", critical: 2, high: 6, medium: 9, low: 10 },
]

function getRiskBadge(risk: string) {
  const variants: Record<string, "destructive" | "success" | "warning" | "info" | "outline"> = {
    "Critical": "destructive",
    "High": "warning",
    "Medium": "info",
    "Secure": "success",
    "—": "outline",
  }
  return <Badge variant={variants[risk] || "outline"}>{risk}</Badge>
}

export default function Dashboard() {
  return (
    <div className="space-y-6">
      {/* Stats Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {stats.map(stat => (
          <Card key={stat.label}>
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-muted-foreground tracking-wider uppercase">{stat.label}</span>
                <stat.icon className={`h-4 w-4 ${stat.color}`} />
              </div>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="text-3xl font-bold tracking-tight">{stat.value}</span>
              </div>
              <p className="text-xs text-muted-foreground mt-1">{stat.change}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Chart */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">Vulnerability Trends</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-[250px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(228, 25%, 16%)" />
                <XAxis dataKey="name" stroke="hsl(215, 20%, 65%)" fontSize={12} />
                <YAxis stroke="hsl(215, 20%, 65%)" fontSize={12} />
                <Tooltip
                  contentStyle={{
                    background: "hsl(228, 39%, 8%)",
                    border: "1px solid hsl(228, 25%, 16%)",
                    borderRadius: "8px",
                    color: "#f1f5f9",
                  }}
                />
                <Bar dataKey="critical" fill="#ef4444" radius={[2, 2, 0, 0]} />
                <Bar dataKey="high" fill="#f59e0b" radius={[2, 2, 0, 0]} />
                <Bar dataKey="medium" fill="#3b82f6" radius={[2, 2, 0, 0]} />
                <Bar dataKey="low" fill="#22c55e" radius={[2, 2, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>

      {/* Recent Scans */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="text-sm font-medium">Recent Scans</CardTitle>
          <button className="text-xs text-primary hover:underline">View all →</button>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-muted-foreground text-xs uppercase tracking-wider">
                  <th className="text-left font-medium pb-3">Target</th>
                  <th className="text-left font-medium pb-3">Type</th>
                  <th className="text-left font-medium pb-3">Status</th>
                  <th className="text-left font-medium pb-3">Risk</th>
                  <th className="text-left font-medium pb-3">Date</th>
                </tr>
              </thead>
              <tbody>
                {recentScans.map((scan, i) => (
                  <tr key={i} className="border-b border-border/50 last:border-0">
                    <td className="py-3 font-medium">{scan.target}</td>
                    <td className="py-3 text-muted-foreground">{scan.type}</td>
                    <td className="py-3">
                      <span className={scan.status === "Completed" ? "text-emerald-500" : "text-amber-500"}>
                        {scan.status}
                      </span>
                    </td>
                    <td className="py-3">{getRiskBadge(scan.risk)}</td>
                    <td className="py-3 text-muted-foreground">{scan.date}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
```

- [ ] **Step 3: 创建 New Scan 页面 (src/app/scan/new/page.tsx)**

```tsx
"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { Globe, Upload, Check, ChevronRight } from "lucide-react"

const scanModules = [
  { id: "owasp", label: "OWASP Top 10", color: "destructive" as const },
  { id: "sca", label: "Dependency Security", color: "warning" as const },
  { id: "infra", label: "Infrastructure Config", color: "info" as const },
  { id: "logic", label: "Business Logic", color: "secondary" as const },
  { id: "attack", label: "Attack Resistance", color: "default" as const },
  { id: "quality", label: "Code Quality", color: "success" as const },
]

export default function NewScanPage() {
  const [mode, setMode] = useState<"url" | "source">("url")
  const [url, setUrl] = useState("")

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      {/* Mode Selection */}
      <Card>
        <CardHeader>
          <CardTitle>Scan Mode</CardTitle>
          <CardDescription>Choose how to submit your target for security analysis</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-4">
            <button
              onClick={() => setMode("url")}
              className={`relative rounded-xl border-2 p-6 text-left transition-all ${
                mode === "url"
                  ? "border-primary bg-primary/5"
                  : "border-border hover:border-muted-foreground/30"
              }`}
            >
              {mode === "url" && (
                <div className="absolute top-3 right-3 h-5 w-5 rounded-full bg-primary flex items-center justify-center">
                  <Check className="h-3 w-3 text-primary-foreground" />
                </div>
              )}
              <Globe className="h-8 w-8 text-primary mb-3" />
              <h3 className="font-semibold mb-1">URL Scanner</h3>
              <p className="text-sm text-muted-foreground">Scan a live website URL for vulnerabilities</p>
            </button>
            <button
              onClick={() => setMode("source")}
              className={`relative rounded-xl border-2 p-6 text-left transition-all ${
                mode === "source"
                  ? "border-primary bg-primary/5"
                  : "border-border hover:border-muted-foreground/30"
              }`}
            >
              {mode === "source" && (
                <div className="absolute top-3 right-3 h-5 w-5 rounded-full bg-primary flex items-center justify-center">
                  <Check className="h-3 w-3 text-primary-foreground" />
                </div>
              )}
              <Upload className="h-8 w-8 text-blue-500 mb-3" />
              <h3 className="font-semibold mb-1">Source Code</h3>
              <p className="text-sm text-muted-foreground">Upload source code (ZIP) for static analysis</p>
            </button>
          </div>
        </CardContent>
      </Card>

      {/* Input Area */}
      <Card>
        <CardHeader>
          <CardTitle>{mode === "url" ? "Target URL" : "Upload Source"}</CardTitle>
          <CardDescription>
            {mode === "url"
              ? "Enter the URL of the website you want to scan"
              : "Upload a ZIP file containing the source code"}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {mode === "url" ? (
            <div className="flex gap-3">
              <Input
                placeholder="https://example.com"
                value={url}
                onChange={e => setUrl(e.target.value)}
                className="flex-1"
              />
              <Button disabled={!url}>Scan</Button>
            </div>
          ) : (
            <div className="border-2 border-dashed border-border rounded-xl p-12 text-center hover:border-muted-foreground/30 transition-colors cursor-pointer">
              <Upload className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
              <p className="font-medium mb-1">Drop your source code ZIP here</p>
              <p className="text-sm text-muted-foreground mb-4">or click to browse files</p>
              <Button variant="outline" size="sm">Select File</Button>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Scan Modules Selection */}
      <Card>
        <CardHeader>
          <CardTitle>Scan Modules</CardTitle>
          <CardDescription>Select which security checks to perform</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-2">
            {scanModules.map(mod => (
              <Badge key={mod.id} variant={mod.color} className="cursor-pointer px-3 py-1.5 text-sm">
                {mod.label}
              </Badge>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Start Scan Button */}
      <div className="flex justify-end">
        <Button size="lg" className="gap-2">
          Start Security Scan
          <ChevronRight className="h-4 w-4" />
        </Button>
      </div>
    </div>
  )
}
```

- [ ] **Step 4: 创建 Scan Detail 页面 (src/app/scan/[id]/page.tsx)**

```tsx
"use client"

import { use } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Tabs } from "@/components/ui/tabs"
import { AlertTriangle, CheckCircle, Info, Shield, ChevronDown } from "lucide-react"

const mockVulnerabilities = [
  {
    id: "VULN-001",
    name: "SQL Injection in User Login",
    severity: "Critical" as const,
    location: "src/api/auth/login.ts:42",
    cve: "CVE-2024-21626",
    description: "User input from the 'username' field is directly concatenated into SQL query strings without parameterization, allowing an attacker to execute arbitrary SQL commands.",
    recommendation: "Use parameterized queries (prepared statements) instead of string concatenation. For PostgreSQL with Node.js, use the $1 placeholder syntax.",
    code: `// ❌ Vulnerable
const query = \`SELECT * FROM users WHERE username = '\${username}' AND password = '\${password}'\`;

// ✅ Fixed
const query = 'SELECT * FROM users WHERE username = $1 AND password = $2';
const result = await pool.query(query, [username, password]);`,
  },
  {
    id: "VULN-002",
    name: "Cross-Site Scripting (XSS)",
    severity: "Critical" as const,
    location: "src/components/Comment.tsx:28",
    cve: "CVE-2024-21887",
    description: "User comment content is rendered using dangerouslySetInnerHTML without sanitization, allowing stored XSS attacks.",
    recommendation: "Use DOMPurify to sanitize HTML content before rendering, or use a safe rendering library that escapes HTML by default.",
    code: `// ❌ Vulnerable
<div dangerouslySetInnerHTML={{ __html: comment.content }} />

// ✅ Fixed
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(comment.content) }} />`,
  },
  {
    id: "VULN-003",
    name: "Hardcoded API Key",
    severity: "High" as const,
    location: "src/config/constants.ts:15",
    cve: "—",
    description: "A Stripe secret API key is hardcoded directly in the source code, exposing sensitive credentials to anyone with access to the codebase.",
    recommendation: "Move secrets to environment variables. Use .env files locally and a secrets manager in production.",
    code: `// ❌ Vulnerable
const STRIPE_SECRET = 'sk_live_xxxxxxxxxxxxxxxxxxxxx';

// ✅ Fixed
const STRIPE_SECRET = process.env.STRIPE_SECRET_KEY;`,
  },
  {
    id: "VULN-004",
    name: "Missing CSRF Protection",
    severity: "High" as const,
    location: "src/api/payments/checkout.ts:1-50",
    cve: "—",
    description: "The payment checkout endpoint lacks CSRF token validation, allowing attackers to forge requests on behalf of authenticated users.",
    recommendation: "Implement CSRF tokens using a library like csurf or include anti-CSRF tokens in your framework's built-in protection.",
  },
  {
    id: "VULN-005",
    name: "Insecure Cookie Configuration",
    severity: "Medium" as const,
    location: "src/middleware.ts:22",
    cve: "—",
    description: "Session cookies are missing the Secure, HttpOnly, and SameSite flags, making them susceptible to theft via XSS or man-in-the-middle attacks.",
    recommendation: "Set cookie flags: Secure=true, HttpOnly=true, SameSite='Lax' or 'Strict'.",
    code: `// ❌ Vulnerable
res.cookie('session', token, { maxAge: 86400000 });

// ✅ Fixed
res.cookie('session', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'lax',
  maxAge: 86400000,
});`,
  },
  {
    id: "VULN-006",
    name: "Outdated Dependency: lodash",
    severity: "Medium" as const,
    location: "package.json:23",
    cve: "CVE-2024-25680",
    description: "lodash@4.17.20 has a known prototype pollution vulnerability. Current version is 3 major versions behind.",
    recommendation: "Update lodash to the latest version: npm install lodash@latest",
  },
]

function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, "destructive" | "warning" | "info" | "success"> = {
    Critical: "destructive",
    High: "warning",
    Medium: "info",
    Low: "success",
  }
  return <Badge variant={map[severity] || "outline"}>{severity}</Badge>
}

export default function ScanDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params)
  const critical = mockVulnerabilities.filter(v => v.severity === "Critical").length
  const high = mockVulnerabilities.filter(v => v.severity === "High").length
  const medium = mockVulnerabilities.filter(v => v.severity === "Medium").length

  return (
    <div className="space-y-6">
      {/* Scan Header */}
      <div className="flex items-start justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Scan Report: my-ai-app.com</h2>
          <p className="text-muted-foreground mt-1">Scan ID: {id} • Completed 2 minutes ago • 35 checks performed</p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="destructive" className="text-sm px-3 py-1">Risk Score: D</Badge>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid gap-4 grid-cols-4">
        <Card className="border-destructive/30">
          <CardContent className="p-4 text-center">
            <div className="text-3xl font-bold text-destructive">{critical}</div>
            <div className="text-xs text-muted-foreground mt-1">Critical</div>
          </CardContent>
        </Card>
        <Card className="border-amber-500/30">
          <CardContent className="p-4 text-center">
            <div className="text-3xl font-bold text-amber-500">{high}</div>
            <div className="text-xs text-muted-foreground mt-1">High</div>
          </CardContent>
        </Card>
        <Card className="border-blue-500/30">
          <CardContent className="p-4 text-center">
            <div className="text-3xl font-bold text-blue-500">{medium}</div>
            <div className="text-xs text-muted-foreground mt-1">Medium</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <div className="text-3xl font-bold text-emerald-500">8</div>
            <div className="text-xs text-muted-foreground mt-1">Passed</div>
          </CardContent>
        </Card>
      </div>

      {/* Vulnerabilities List */}
      <Card>
        <CardHeader>
          <CardTitle>Vulnerabilities</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {mockVulnerabilities.map(vuln => (
            <details key={vuln.id} className="group border border-border rounded-lg overflow-hidden">
              <summary className="flex items-center gap-3 p-4 cursor-pointer hover:bg-accent/50 transition-colors list-none">
                <ChevronDown className="h-4 w-4 text-muted-foreground group-open:rotate-180 transition-transform shrink-0" />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-medium">{vuln.name}</span>
                    <SeverityBadge severity={vuln.severity} />
                  </div>
                  <p className="text-xs text-muted-foreground mt-0.5 font-mono">{vuln.location}</p>
                </div>
                {vuln.cve !== "—" && (
                  <Badge variant="outline" className="text-[10px]">{vuln.cve}</Badge>
                )}
                <code className="text-xs text-muted-foreground">{vuln.id}</code>
              </summary>
              <div className="px-4 pb-4 border-t border-border pt-4 space-y-4">
                <div>
                  <h4 className="text-sm font-medium mb-1">Description</h4>
                  <p className="text-sm text-muted-foreground">{vuln.description}</p>
                </div>
                <div>
                  <h4 className="text-sm font-medium text-emerald-500 mb-1">Fix Recommendation</h4>
                  <p className="text-sm text-muted-foreground mb-2">{vuln.recommendation}</p>
                  {vuln.code && (
                    <pre className="bg-black/40 rounded-lg p-4 overflow-x-auto text-sm">
                      <code className="text-xs">{vuln.code}</code>
                    </pre>
                  )}
                </div>
              </div>
            </details>
          ))}
        </CardContent>
      </Card>
    </div>
  )
}
```

- [ ] **Step 5: 创建 Scan History 页面 (src/app/scan/history/page.tsx)**

```tsx
"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import Link from "next/link"
import { Search } from "lucide-react"
import { Input } from "@/components/ui/input"

const history = [
  { id: "1", target: "my-ai-app.com", type: "URL", status: "Completed", risk: "Critical", date: "2026-06-05 14:23" },
  { id: "2", target: "ecommerce-test.zip", type: "Source", status: "Scanning", risk: "—", date: "2026-06-05 14:08" },
  { id: "3", target: "blog-platform.vercel.app", type: "URL", status: "Completed", risk: "Secure", date: "2026-06-05 12:00" },
  { id: "4", target: "dashboard-app.zip", type: "Source", status: "Completed", risk: "High", date: "2026-06-05 09:15" },
  { id: "5", target: "api-gateway.test.com", type: "URL", status: "Completed", risk: "Medium", date: "2026-06-04 22:30" },
]

export default function ScanHistoryPage() {
  return (
    <div className="space-y-6">
      <div className="relative max-w-md">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input placeholder="Search scans..." className="pl-9" />
      </div>
      <Card>
        <CardContent className="p-0">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-muted-foreground text-xs uppercase tracking-wider">
                <th className="text-left font-medium p-4">Target</th>
                <th className="text-left font-medium p-4">Type</th>
                <th className="text-left font-medium p-4">Status</th>
                <th className="text-left font-medium p-4">Risk</th>
                <th className="text-left font-medium p-4">Date</th>
                <th className="text-right font-medium p-4">Action</th>
              </tr>
            </thead>
            <tbody>
              {history.map(scan => (
                <tr key={scan.id} className="border-b border-border/50 last:border-0 hover:bg-accent/30 transition-colors">
                  <td className="p-4 font-medium">{scan.target}</td>
                  <td className="p-4 text-muted-foreground">{scan.type}</td>
                  <td className="p-4">
                    <span className={scan.status === "Completed" ? "text-emerald-500" : "text-amber-500"}>
                      {scan.status}
                    </span>
                  </td>
                  <td className="p-4">
                    <Badge variant={
                      scan.risk === "Critical" ? "destructive" :
                      scan.risk === "High" ? "warning" :
                      scan.risk === "Medium" ? "info" :
                      scan.risk === "Secure" ? "success" : "outline"
                    }>{scan.risk}</Badge>
                  </td>
                  <td className="p-4 text-muted-foreground">{scan.date}</td>
                  <td className="p-4 text-right">
                    <Link href={`/scan/${scan.id}`} className="text-primary text-xs hover:underline">
                      View Report
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </CardContent>
      </Card>
    </div>
  )
}
```

- [ ] **Step 6: 创建 Reports 和 Settings 占位页面**

src/app/reports/page.tsx:
```tsx
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { FileText } from "lucide-react"

export default function ReportsPage() {
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Reports</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-center py-12 text-muted-foreground">
            <FileText className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p>No reports generated yet</p>
            <p className="text-sm mt-1">Run a scan to see reports here</p>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
```

src/app/settings/page.tsx:
```tsx
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Button } from "@/components/ui/button"

export default function SettingsPage() {
  return (
    <div className="max-w-2xl space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Scan Configuration</CardTitle>
          <CardDescription>Configure default scan behavior</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium">Max Scan Duration</p>
              <p className="text-sm text-muted-foreground">Maximum time for a single scan (minutes)</p>
            </div>
            <span className="text-sm font-mono">30</span>
          </div>
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium">Auto-report Generation</p>
              <p className="text-sm text-muted-foreground">Automatically generate reports on completion</p>
            </div>
            <span className="text-sm text-emerald-500">Enabled</span>
          </div>
          <Button variant="outline" size="sm">Save Changes</Button>
        </CardContent>
      </Card>
    </div>
  )
}
```

---

### Task 6: 创建 Python 扫描引擎（MVP 模拟版）

**Files:**
- Create: `D:/DEMO/aut/scan-engine/requirements.txt`
- Create: `D:/DEMO/aut/scan-engine/main.py`
- Create: `D:/DEMO/aut/scan-engine/Dockerfile`

- [ ] **Step 1: 创建 requirements.txt**

```
fastapi==0.111.0
uvicorn==0.29.0
redis==5.0.0
httpx==0.27.0
pydantic==2.7.0
```

- [ ] **Step 2: 创建 main.py (模拟扫描引擎)**

```python
"""
VulnGuard Scan Engine - MVP Simulation Mode
Returns mock vulnerability data for demo purposes.
"""

import json
import uuid
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="VulnGuard Scan Engine", version="0.1.0")

# In-memory scan storage (MVP)
scans: dict = {}


class ScanRequest(BaseModel):
    target: str
    mode: str  # "url" or "source"
    modules: list[str] = []


class ScanStatus(BaseModel):
    scan_id: str
    status: str
    progress: int
    target: str


# Mock vulnerability templates
MOCK_VULNS = [
    {
        "name": "SQL Injection",
        "severity": "Critical",
        "location": "src/api/auth/login.ts:42",
        "cve": "CVE-2024-21626",
        "description": "User input is directly concatenated into SQL query strings without parameterization.",
        "recommendation": "Use parameterized queries (prepared statements) instead of string concatenation.",
        "code_fix": "--safe\nconst query = 'SELECT * FROM users WHERE username = $1';\nawait pool.query(query, [username]);",
    },
    {
        "name": "Cross-Site Scripting (XSS)",
        "severity": "Critical",
        "location": "src/components/Comment.tsx:28",
        "cve": "CVE-2024-21887",
        "description": "User content rendered using dangerouslySetInnerHTML without sanitization.",
        "recommendation": "Use DOMPurify to sanitize HTML content before rendering.",
        "code_fix": "--safe\nimport DOMPurify from 'dompurify';\n<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }} />",
    },
    {
        "name": "Hardcoded API Key",
        "severity": "High",
        "location": "src/config/constants.ts:15",
        "cve": "—",
        "description": "Secret API key hardcoded in source code.",
        "recommendation": "Move secrets to environment variables.",
        "code_fix": "--safe\nconst API_KEY = process.env.API_KEY;",
    },
    {
        "name": "Missing CSRF Protection",
        "severity": "High",
        "location": "src/api/payments/checkout.ts:1-50",
        "cve": "—",
        "description": "Payment endpoint lacks CSRF token validation.",
        "recommendation": "Implement CSRF tokens using your framework's built-in protection.",
        "code_fix": "--safe\nimport { csrf } from '@/lib/csrf';\nexport const POST = csrf(async (req) => { ... });",
    },
    {
        "name": "Insecure Cookie Configuration",
        "severity": "Medium",
        "location": "src/middleware.ts:22",
        "cve": "—",
        "description": "Session cookies missing Secure, HttpOnly, and SameSite flags.",
        "recommendation": "Set cookie flags: Secure=true, HttpOnly=true, SameSite='Lax'.",
        "code_fix": "--safe\nres.cookie('session', token, {\n  httpOnly: true,\n  secure: true,\n  sameSite: 'lax',\n});",
    },
    {
        "name": "Outdated Dependency: lodash",
        "severity": "Medium",
        "location": "package.json:23",
        "cve": "CVE-2024-25680",
        "description": "lodash@4.17.20 has a known prototype pollution vulnerability.",
        "recommendation": "Update lodash to the latest version.",
        "code_fix": "--safe\nnpm install lodash@latest",
    },
]


@app.get("/health")
def health():
    return {"status": "ok", "version": "0.1.0"}


@app.post("/scans")
def create_scan(req: ScanRequest):
    scan_id = str(uuid.uuid4())[:8]
    scans[scan_id] = {
        "scan_id": scan_id,
        "target": req.target,
        "mode": req.mode,
        "status": "queued",
        "progress": 0,
        "created_at": datetime.utcnow().isoformat(),
        "vulnerabilities": [],
    }
    return {"scan_id": scan_id, "status": "queued"}


@app.get("/scans/{scan_id}")
def get_scan(scan_id: str):
    scan = scans.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")

    # Simulate scan completion
    if scan["status"] == "queued":
        scan["status"] = "completed"
        scan["progress"] = 100
        scan["completed_at"] = datetime.utcnow().isoformat()
        scan["vulnerabilities"] = MOCK_VULNS

    return scan


@app.get("/scans")
def list_scans():
    return [
        ScanStatus(
            scan_id=sid,
            status=s["status"],
            progress=s["progress"],
            target=s["target"],
        )
        for sid, s in scans.items()
    ]


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

- [ ] **Step 3: 创建 Dockerfile**

```dockerfile
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

---

### Task 7: 创建 LLM 分析引导模块（Prompt 框架）

**Files:**
- Create: `D:/DEMO/aut/scan-engine/llm_analyzer/prompt_templates.py`
- Create: `D:/DEMO/aut/scan-engine/llm_analyzer/__init__.py`
- Create: `D:/DEMO/aut/scan-engine/llm_analyzer/owasp_context.py`
- Create: `D:/DEMO/aut/scan-engine/llm_analyzer/result_parser.py`

**说明:** 此模块提供专业的结构化引导框架，供后续接入 DeepSeek 等通用大模型时使用。VulnGuard 本身不直接调用 LLM，而是输出标准化的 Prompt 模板和上下文，你是集成方，将这些引导材料输入给 DeepSeek 即可获得专业级安全审计结果。

- [ ] **Step 1: 创建 __init__.py**

```python
"""
LLM 分析引导模块

此模块提供专业的安全审计 Prompt 框架和结构化上下文，
用于引导通用大模型（如 DeepSeek）进行深度安全分析。

使用方式:
    1. 调用 build_security_prompt() 获取完整的审计引导
    2. 将返回的 prompt 输入给 DeepSeek
    3. 解析 LLM 返回的结构化结果
"""
```

- [ ] **Step 2: 创建 owasp_context.py — OWASP 专业上下文库**

```python
"""
OWASP 安全审计上下文库

为 LLM 提供专业的漏洞检测上下文和评判标准，
引导大模型像专业安全工程师一样思考。
"""

# OWASP Top 10 (2021) 详细检测引导
OWASP_TOP_10_PROMPTS = {
    "A01_broken_access": """
## [A01:2021 – Broken Access Control]
### 检测重点
1. 是否存在未授权访问保护
2. URL/API 路径是否校验权限
3. IDOR (Insecure Direct Object Reference) 漏洞
4. 是否遵循最小权限原则

### 检查清单
- [ ] 越权访问: 普通用户能否访问管理员 API
- [ ] ID 枚举: 通过修改 URL 中的 ID 参数能否访问他人数据
- [ ] 角色提升: 能否通过修改请求头/参数提升权限
- [ ] HTTP 方法覆盖: DELETE/PUT 等危险方法是否受限
""",

    "A02_cryptographic_failure": """
## [A02:2021 – Cryptographic Failures]
### 检测重点
1. 敏感数据是否在传输过程中加密 (TLS)
2. 密码存储是否使用强哈希 (bcrypt/argon2)
3. 是否使用弱加密算法 (MD5, SHA1, DES)
4. JWT 签名算法是否安全配置

### 检查清单
- [ ] 敏感字段: 密码/Token/Key 是否硬编码
- [ ] HTTPS: 是否全站强制 HTTPS
- [ ] 密码哈希: 是否使用 bcrypt/argon2/scrypt
- [ ] JWT 算法: 是否限制为 RS256 并验证签名
""",

    "A03_injection": """
## [A03:2021 – Injection]
### 检测重点
1. SQL 查询是否使用参数化查询
2. NoSQL 查询是否做输入消毒
3. OS 命令是否由用户输入拼接
4. 模版引擎 SSTI 注入检测

### 检查清单
- [ ] SQL 拼接: 是否存在字符串拼接 SQL 查询
- [ ] 输入验证: 用户输入是否做类型和格式校验
- [ ] ORM 使用: ORM 查询是否存在原生 SQL 注入风险
- [ ] 命令执行: exec/eval/system 等函数是否处理用户输入
""",

    "A04_insecure_design": """
## [A04:2021 – Insecure Design]
### 检测重点
1. 是否缺少速率限制
2. 密码重置逻辑是否安全
3. 多步骤流程是否存在跳过风险
4. 是否存在批量赋值 (Mass Assignment) 漏洞

### 检查清单
- [ ] 速率限制: 登录/注册/API 是否限流
- [ ] 批量赋值: 用户能否修改非预期的字段
- [ ] 密码重置: Token 是否可预测/过期时间是否合理
- [ ] 业务逻辑: 多步骤流程是否存在校验缺失
""",

    "A05_security_misconfig": """
## [A05:2021 – Security Misconfiguration]
### 检测重点
1. 是否开启 debug/错误栈信息
2. CORS 配置是否过于宽松
3. 不必要的端口/服务是否暴露
4. 默认凭据是否修改

### 检查清单
- [ ] CORS: Access-Control-Allow-Origin 是否设置为 *
- [ ] 错误处理: 生产环境是否暴露详细错误信息
- [ ] 安全头: CSP/X-Frame-Options/HSTS 是否配置
- [ ] 默认配置: 框架默认密钥/密码是否修改
""",

    "A06_vulnerable_components": """
## [A06:2021 – Vulnerable and Outdated Components]
### 检测重点
1. 第三方依赖版本是否过时
2. 已知 CVE 漏洞的依赖
3. 未使用的依赖
4. 依赖来源是否可信

### 检查清单
- [ ] 过时依赖: package.json/go.mod/requirements.txt 中的版本
- [ ] CVE 匹配: 运行时依赖是否存在已知漏洞
- [ ] 废弃包: 是否使用了不再维护的包
- [ ] 传递依赖: 间接依赖是否存在风险
""",

    "A07_identification_auth": """
## [A07:2021 – Identification and Authentication Failures]
### 检测重点
1. 密码策略是否足够强
2. 会话管理是否安全
3. 多因素认证是否支持
4. 认证日志是否完善

### 检查清单
- [ ] 会话超时: Token/Session 是否存在合理过期
- [ ] 密码策略: 最小长度/复杂度要求
- [ ] 暴力破解: 是否有登录尝试限制
- [ ] 会话固定: 登录后是否重新生成 session ID
""",

    "A08_integrity_failure": """
## [A08:2021 – Software and Data Integrity Failures]
### 检测重点
1. CI/CD 管道安全
2. 软件签名/完整性校验
3. 不安全的反序列化
4. 供应链安全

### 检查清单
- [ ] 反序列化: JSON.parse/eval/unserialize 是否处理不可信数据
- [ ] 完整性: 是否验证更新包/插件的签名
- [ ] 供应链: package-lock.json / yarn.lock 是否锁定版本
""",

    "A09_monitoring_logging": """
## [A09:2021 – Security Logging and Monitoring Failures]
### 检测重点
1. 是否记录安全事件日志
2. 日志是否包含敏感信息
3. 告警机制是否完善

### 检查清单
- [ ] 日志记录: 登录失败/权限拒绝 是否有日志
- [ ] 敏感数据: 日志是否包含密码/Token
- [ ] 告警: 异常请求是否有告警机制
""",

    "A10_ssrf": """
## [A10:2021 – Server-Side Request Forgery (SSRF)]
### 检测重点
1. 用户能否控制请求的 URL
2. URL 是否做了白名单校验
3. 内网地址是否被禁止访问

### 检查清单
- [ ] URL 输入: 是否由用户提供完整的 URL
- [ ] 白名单: 是否校验请求域名/IP
- [ ] 内网保护: 是否阻止 127.0.0.1/10.0.0.0/172.16.0.0/192.168.0.0
- [ ] URL 解析: 是否存在 URL 解析差异绕过
""",
}

# AI 生成代码专项检测引导
AI_CODE_SPECIFIC_PROMPTS = {
    "halucination_api": """
## AI 生成代码专项: 幻觉 API 调用
### 说明
AI 模型可能产生调用不存在的 API 或库的代码。
- 检查 import/require 的包是否真实存在
- 检查调用的 API 方法和参数是否有效
- 检查文档链接是否可访问
""",

    "insecure_defaults": """
## AI 生成代码专项: 不安全默认值
### 说明
AI 模型可能默认使用不安全的配置。
- 检查默认关闭的安全选项（如 CSP、Helmet）
- 检查硬编码的测试凭据
- 检查默认的宽松 CORS 配置
""",

    "context_leakage": """
## AI 生成代码专项: 上下文泄露
### 说明
AI 模型可能在注释或代码中保留上下文中出现的敏感信息。
- 检查注释中的 URL/Token/IP
- 检查示例代码中的假密钥是否被用于生产
""",
}

# 抗攻击能力检测引导
ATTACK_RESISTANCE_PROMPTS = {
    "rate_limiting": """
## 抗攻击测试: 速率限制
### 检测要点
1. API 是否有请求频率限制
2. 限制是基于 IP 还是用户
3. 限制阈值是否合理

### 测试方法
- 在短时间内发送大量请求，观察是否被限制
- 检查响应头中是否包含 RateLimit-*
""",

    "waf_detection": """
## 抗攻击测试: WAF 检测
### 检测要点
1. 是否存在 WAF/CDN 防护
2. WAF 类型识别
3. WAF 规则是否严格

### 检测特征
- 响应头中是否包含 WAF 标识
- 请求被拦截时返回的状态码
- 是否存在 Cloudflare/AWS WAF/ModSecurity 特征
""",

    "ddos_protection": """
## 抗攻击测试: DDoS 防护
### 检测要点
1. 是否有 CDN 加速
2. 是否有连接数限制
3. 是否有流量清洗机制

### 检测指标
- 响应时间在不同并发下的变化
- TCP 连接是否有限制
- 是否存在验证码/challenge 机制
""",
}


def get_full_audit_context() -> str:
    """获取完整的审计上下文，作为 LLM 的系统提示词部分"""
    sections = [
        "# Security Audit Expert System Prompt",
        "You are a professional security code reviewer with 15+ years of experience in penetration testing and secure code review.",
        "You specialize in OWASP Top 10, CVE analysis, and AI-generated code security assessment.",
        "",
        "## Analysis Requirements",
        "1. Be thorough and specific - point to exact code locations",
        "2. Provide actionable fix recommendations with code examples",
        "3. Rate severity using CVSS 3.1 standards",
        "4. Consider both automated findings and business logic context",
        "",
        "## Severity Classification (CVSS 3.1)",
        "- **Critical (9.0-10.0)**: Remote code execution, SQL injection, auth bypass",
        "- **High (7.0-8.9)**: XSS, SSRF, IDOR, sensitive data exposure",
        "- **Medium (4.0-6.9)**: Missing security headers, outdated deps, info disclosure",
        "- **Low (0.1-3.9)**: Best practice violations, minor config issues",
        "",
    ]

    for key in OWASP_TOP_10_PROMPTS:
        sections.append(OWASP_TOP_10_PROMPTS[key])

    for key in AI_CODE_SPECIFIC_PROMPTS:
        sections.append(AI_CODE_SPECIFIC_PROMPTS[key])

    for key in ATTACK_RESISTANCE_PROMPTS:
        sections.append(ATTACK_RESISTANCE_PROMPTS[key])

    return "\n\n".join(sections)
```

- [ ] **Step 3: 创建 prompt_templates.py — 结构化 Prompt 模板**

```python
"""
Prompt 模板生成器

为不同类型的审计场景生成结构化的 Prompt 模板，
引导 LLM 输出标准化的分析结果。
"""

from enum import Enum
from typing import Optional


class AnalysisType(Enum):
    FULL_AUDIT = "full_audit"
    CODE_REVIEW = "code_review"
    VULN_VERIFICATION = "vuln_verification"
    COMPLIANCE_CHECK = "compliance_check"


def build_scan_analysis_prompt(
    target_name: str,
    scan_mode: str,
    source_snippet: Optional[str] = None,
    findings: Optional[list[dict]] = None,
) -> str:
    """
    生成扫描分析引导 Prompt。

    参数:
        target_name: 扫描目标名称
        scan_mode: "url" 或 "source"
        source_snippet: 源码片段（可选）
        findings: 传统工具发现的潜在漏洞（可选）

    返回:
        结构化的 Prompt，可直接作为 LLM 的输入
    """

    prompt = f"""# Security Analysis Request

## Target
- **Name:** {target_name}
- **Scan Mode:** {"Live URL Scan" if scan_mode == "url" else "Source Code Analysis"}

## Instructions
You are acting as a professional security auditor. Analyze the target above for security vulnerabilities.

Please follow this analysis structure:

### 1. Vulnerability Analysis
For each vulnerability found, provide:

| Field | Description |
|-------|-------------|
| **name** | Vulnerability name (e.g., "SQL Injection in Login") |
| **severity** | critical / high / medium / low |
| **location** | File path:line number or URL path |
| **cve** | CVE ID if applicable (null if none) |
| **description** | Detailed explanation of the vulnerability |
| **impact** | What an attacker can achieve |
| **fix_recommendation** | Specific steps to fix |
| **code_example** | Before/after code showing the fix |

### 2. Security Score
Rate the overall security: A+ (excellent) through F (very poor)

### 3. Risk Summary
- Critical: count
- High: count
- Medium: count
- Low: count

### 4. Top 3 Priority Fixes
List the 3 most critical issues that must be fixed first.

### 5. Compliance Notes
Any relevant compliance frameworks (OWASP Top 10, PCI-DSS, GDPR, etc.)

---

"""
    if findings:
        prompt += "## Initial Findings (from automated scanners)\n\n"
        prompt += "The following potential issues were detected by automated tools. Please verify and deep-dive:\n\n"
        for f in findings[:10]:
            prompt += f"- [{f.get('severity', 'info').upper()}] {f.get('name', 'Unknown')} at {f.get('location', 'N/A')}\n"
        prompt += "\n## Additional Analysis Required\n"
        prompt += "Beyond the findings above, please also check for:\n"
        prompt += "1. Business logic vulnerabilities (not detectable by automated tools)\n"
        prompt += "2. Authentication/authorization flaws\n"
        prompt += "3. Cryptographic implementation issues\n"
        prompt += "4. Race conditions and concurrency issues\n"
        prompt += "5. AI-generated code specific patterns (hallucinations, insecure defaults)\n\n"

    if source_snippet:
        prompt += f"## Source Code for Review\n\n```\n{source_snippet[:5000]}\n```\n\n"

    prompt += """
## Output Format
Return your analysis in JSON format:

```json
{
  "summary": {
    "score": "B+",
    "total_vulnerabilities": 0,
    "critical_count": 0,
    "high_count": 0,
    "medium_count": 0,
    "low_count": 0
  },
  "vulnerabilities": [
    {
      "name": "string",
      "severity": "critical|high|medium|low",
      "location": "string",
      "cve": "string|null",
      "description": "string",
      "impact": "string",
      "fix_recommendation": "string",
      "code_example": "string"
    }
  ],
  "top_p3_fixes": ["string"],
  "compliance": ["string"]
}
```
"""
    return prompt


def build_vuln_verification_prompt(
    vuln_name: str,
    vuln_location: str,
    source_context: str,
) -> str:
    """
    生成漏洞验证 Prompt。

    用于对传统工具发现的潜在漏洞进行深度验证，
    由独立验证器判断是否为真实漏洞，降低误报。
    """

    return f"""# Vulnerability Verification Request

## Suspected Vulnerability
- **Name:** {vuln_name}
- **Location:** {vuln_location}

## Context (surrounding source code)
```{source_context[:3000]}
```

## Task
Verify whether this is a REAL vulnerability or a FALSE POSITIVE.

### Analysis Steps:
1. Is the data source user-controllable? (Check entry points)
2. Is there proper sanitization/validation? (Check filters)
3. Is the sink dangerous in this context? (Check execution)
4. Are there compensating controls? (WAF, CSP, etc.)

### Decision:
- **REAL VULNERABILITY** - Provide exploitation scenario and fix
- **FALSE POSITIVE** - Explain why it's not exploitable
- **UNCERTAIN** - What additional information is needed?

Return as JSON:
```json
{{
  "verdict": "real|false_positive|uncertain",
  "confidence": 0.0-1.0,
  "reasoning": "detailed explanation",
  "exploitation_scenario": "if real",
  "fix": "if real"
}}
```"""


__all__ = [
    "AnalysisType",
    "build_scan_analysis_prompt",
    "build_vuln_verification_prompt",
]
```

- [ ] **Step 4: 创建 result_parser.py — LLM 结果解析器**

```python
"""
LLM 输出结果解析器

将 LLM 返回的 JSON 格式分析结果解析为 VulnGuard 内部数据结构。
支持 DeepSeek 及其他兼容 OpenAI API 格式的大模型输出。
"""

import json
import re
from typing import Optional


class LLMResultParser:
    """解析 LLM 返回的安全分析结果"""

    @staticmethod
    def extract_json(text: str) -> Optional[dict]:
        """从 LLM 回复中提取 JSON 内容"""
        # Try direct JSON parse
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Try extracting JSON from code blocks
        json_match = re.search(r'```(?:json)?\s*\n(.+?)\n```', text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass

        # Try finding JSON object
        json_match = re.search(r'\{.*"vulnerabilities".*\}', text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(0))
            except json.JSONDecodeError:
                pass

        return None

    @staticmethod
    def parse_vulnerabilities(llm_response: str) -> list[dict]:
        """
        从 LLM 回复中提取漏洞列表。

        返回标准化格式:
        [
            {
                "name": str,
                "severity": str,
                "location": str,
                "cve": str | None,
                "description": str,
                "impact": str,
                "fix_recommendation": str,
                "code_example": str,
            }
        ]
        """
        data = LLMResultParser.extract_json(llm_response)
        if not data:
            return []

        vulns = data.get("vulnerabilities", data.get("findings", []))
        if isinstance(vulns, list):
            return vulns

        return []

    @staticmethod
    def parse_score(llm_response: str) -> Optional[str]:
        """提取安全评分 (A+ ~ F)"""
        data = LLMResultParser.extract_json(llm_response)
        if data:
            summary = data.get("summary", data)
            score = summary.get("score")
            if score:
                return score

        # Fallback: regex search
        score_match = re.search(r'\b([A-F][+-]?)\b', llm_response)
        if score_match:
            return score_match.group(1)

        return None


__all__ = ["LLMResultParser"]
```

- [ ] **Step 5: 更新 scan-engine/main.py，添加 LLM 引导资源端点**

在 main.py 文件末尾（`if __name__ == "__main__":` 之前）添加:

```python
# ============================================================
# LLM 分析引导资源端点
# ============================================================

@app.get("/llm-context/full-audit")
def get_llm_audit_context():
    """获取完整的安全审计 LLM 引导上下文"""
    from llm_analyzer.owasp_context import get_full_audit_context
    return {
        "type": "system_prompt",
        "description": "Use this as system prompt for LLM security audit",
        "content": get_full_audit_context(),
    }


@app.post("/llm-context/build-prompt")
def build_llm_prompt(target: str, mode: str = "url", findings: list[dict] | None = None):
    """为特定扫描任务构建分析 Prompt"""
    from llm_analyzer.prompt_templates import build_scan_analysis_prompt
    prompt = build_scan_analysis_prompt(
        target_name=target,
        scan_mode=mode,
        findings=findings or [],
    )
    return {"prompt": prompt, "tokens_estimate": len(prompt.split())}


@app.post("/llm-context/parse-result")
def parse_llm_result(llm_response: str):
    """解析 LLM 返回的分析结果"""
    from llm_analyzer.result_parser import LLMResultParser
    return {
        "vulnerabilities": LLMResultParser.parse_vulnerabilities(llm_response),
        "score": LLMResultParser.parse_score(llm_response),
    }
```

- [ ] **Step 6: 更新 requirements.txt**

在 `D:/DEMO/aut/scan-engine/requirements.txt` 末尾添加:
```
# LLM Analysis (optional - for DeepSeek integration)
openai==1.30.0
```

---

### Task 8: 创建 Docker Compose 配置

**Files:**
- Create: `D:/DEMO/aut/docker-compose.yml`

- [ ] **Step 1: 创建 docker-compose.yml**

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: vulnguard
      POSTGRES_PASSWORD: vulnguard
      POSTGRES_DB: vulnguard
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U vulnguard"]
      interval: 5s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 5

  scan-engine:
    build: ./scan-engine
    ports:
      - "8000:8000"
    depends_on:
      redis:
        condition: service_healthy
    environment:
      - REDIS_URL=redis://redis:6379

volumes:
  postgres_data:
```

---

### Task 9: 配置 Prisma 数据模型

**Files:**
- Create: `D:/DEMO/aut/prisma/schema.prisma`

- [ ] **Step 1: 创建 Prisma Schema**

```prisma
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

model Project {
  id        String   @id @default(cuid())
  name      String
  target    String   // URL or filename
  mode      String   // "url" | "source"
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
  scans     Scan[]
}

model Scan {
  id              String          @id @default(cuid())
  projectId       String
  project         Project         @relation(fields: [projectId], references: [id])
  status          String          @default("queued")  // queued, running, completed, failed
  progress        Int             @default(0)
  riskScore       String?         // A+, A, B+, B, C, D, F
  totalVulns      Int             @default(0)
  criticalCount   Int             @default(0)
  highCount       Int             @default(0)
  mediumCount     Int             @default(0)
  lowCount        Int             @default(0)
  createdAt       DateTime        @default(now())
  completedAt     DateTime?
  vulnerabilities Vulnerability[]
}

model Vulnerability {
  id             String   @id @default(cuid())
  scanId         String
  scan           Scan     @relation(fields: [scanId], references: [id])
  name           String
  severity       String   // Critical, High, Medium, Low
  location       String?  // File path or URL
  cve            String?
  description    String
  recommendation String
  codeFix        String?
  createdAt      DateTime @default(now())
}
```

- [ ] **Step 2: 初始化 Prisma**

Run: `cd /d/DEMO/aut && npx prisma generate`

---

### Task 10: 启动验证

- [ ] **Step 1: 启动开发服务器**

Run: `cd /d/DEMO/aut && npm run dev`

验证：
- 访问 http://localhost:3000 确认 Dashboard 显示
- 访问 http://localhost:3000/scan/new 确认扫描表单
- 访问 http://localhost:3000/scan/1 确认报告详情
- 扫描引擎运行在 http://localhost:8000

- [ ] **Step 2: 创建 README**

**Files:**
- Create: `D:/DEMO/aut/README.md`

```markdown
# VulnGuard - Security Vulnerability Scanner

自动化代码安全审查平台，专为检测 AI 开发的网站项目中的安全漏洞而设计。

## 快速开始

```bash
# 安装依赖
npm install

# 启动开发服务器
npm run dev

# 启动扫描引擎 (另一个终端)
cd scan-engine
pip install -r requirements.txt
python main.py
```

## 功能

- URL 扫描 + 源码分析双模式
- OWASP Top 10 漏洞检测
- 依赖安全分析 (SCA)
- 基础设施安全配置审计
- 业务逻辑漏洞检测
- 抗攻击能力测试
- 详细安全报告 + 修复建议

## 技术栈

- **Frontend:** Next.js 14, Tailwind CSS, shadcn/ui, Recharts
- **Engine:** Python FastAPI
- **Infra:** PostgreSQL, Redis, Docker
```
