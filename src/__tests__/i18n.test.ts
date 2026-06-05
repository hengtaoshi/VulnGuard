import { describe, it, expect } from "vitest"

describe("i18n dictionaries", () => {
  it("zh and en have matching structure", async () => {
    const [zh, en] = await Promise.all([
      import("@/lib/i18n/zh").then(m => m.zh),
      import("@/lib/i18n/en").then(m => m.en),
    ])

    function keys(obj: Record<string, unknown>, prefix = ""): string[] {
      return Object.entries(obj).flatMap(([k, v]) =>
        typeof v === "string" ? [`${prefix}${k}`] : keys(v as Record<string, unknown>, `${prefix}${k}.`),
      )
    }

    const zhKeys = keys(zh)
    const enKeys = keys(en)

    expect(zhKeys.sort()).toEqual(enKeys.sort())
  })

  it("zh translations are non-empty", async () => {
    const { zh } = await import("@/lib/i18n/zh")

    function checkNonEmpty(obj: Record<string, unknown>, path = ""): string[] {
      return Object.entries(obj).flatMap(([k, v]) => {
        const p = path ? `${path}.${k}` : k
        if (typeof v === "string") return v.trim() ? [] : [p]
        return checkNonEmpty(v as Record<string, unknown>, p)
      })
    }

    const empty = checkNonEmpty(zh)
    expect(empty).toEqual([])
  })
})
