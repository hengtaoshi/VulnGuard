/**
 * VulnGuard global type declarations
 *
 * These are shared across all components. Keep in sync with electron/preload.js
 */

interface VulnguardUpdateInfo {
  version: string
}

interface VulnguardProgress {
  percent: number
}

interface VulnguardScannerProgress {
  percent: number
  done?: boolean
  ok?: boolean
  error?: string
  scanner?: string
  bytes?: number
  total?: number
}

interface VulnguardResult {
  ok: boolean
  error?: string
  canUpdate?: boolean
  version?: string
  skipped?: boolean
}

interface VulnguardStatus {
  scanEngine: boolean
  toolsDir: string
}

interface Window {
  vulnguard?: {
    version: string
    platform: string
    arch: string
    getDataDir: () => Promise<string>
    getScannerStatus: () => Promise<VulnguardStatus>
    openFileDialog: () => Promise<string[] | null>

    // Updates
    checkForUpdates: () => Promise<VulnguardResult>
    startUpdate: () => Promise<VulnguardResult>
    onUpdateAvailable: (cb: (info: VulnguardUpdateInfo) => void) => () => void
    onUpdateProgress: (cb: (p: VulnguardProgress) => void) => () => void
    onUpdateDownloaded: (cb: () => void) => () => void

    // Scanner installation
    downloadScanner: (name: string) => Promise<VulnguardResult>
    onScannerProgress: (cb: (data: VulnguardScannerProgress) => void) => () => void
  }
}
