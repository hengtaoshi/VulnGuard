/**
 * VulnGuard Desktop - Preload Script
 *
 * Exposes a safe API to the renderer process via contextBridge.
 */
const { contextBridge, ipcRenderer } = require("electron")

contextBridge.exposeInMainWorld("vulnguard", {
  // App info
  platform: process.platform,
  arch: process.arch,
  version: process.env.npm_package_version || "0.1.0",

  // IPC helpers for future use
  getDataDir: () => ipcRenderer.invoke("get-data-dir"),
  downloadScanner: (url, name) => ipcRenderer.invoke("download-scanner", url, name),
  getScannerStatus: () => ipcRenderer.invoke("get-scanner-status"),

  // File dialogs
  openFileDialog: () => ipcRenderer.invoke("open-file-dialog"),

  // Event listeners
  onScannerProgress: (callback) => {
    const handler = (_event, data) => callback(data)
    ipcRenderer.on("scanner-progress", handler)
    return () => ipcRenderer.removeListener("scanner-progress", handler)
  },
})
