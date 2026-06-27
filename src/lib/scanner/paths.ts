/**
 * Scanner paths — single source of truth for scanner tool locations.
 *
 * In dev/web mode: tools are at <project>/tools/
 * In Electron:     tools are at <userData>/tools/ (set via VULNGUARD_DATA_DIR)
 */
import { join } from "path"

const BASE = process.env.VULNGUARD_DATA_DIR || process.cwd()

export const TOOLS_DIR = join(BASE, "tools")
export const TOOLS_BIN = join(TOOLS_DIR, "bin")

export function toolPath(...segments: string[]) {
  return join(TOOLS_DIR, ...segments)
}
