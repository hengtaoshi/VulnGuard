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
  version: process.env.npm_package_version || "0.3.0",

  // IPC helpers for future use
  getDataDir: () => ipcRenderer.invoke("get-data-dir"),
  downloadScanner: (url, name) => ipcRenderer.invoke("download-scanner", url, name),
  getScannerStatus: () => ipcRenderer.invoke("get-scanner-status"),

  // Updates
  checkForUpdates: () => ipcRenderer.invoke("check-for-updates"),
  startUpdate: () => ipcRenderer.invoke("start-update"),
  onUpdateAvailable: (callback) => {
    const handler = (_event, data) => callback(data)
    ipcRenderer.on("update-available", handler)
    return () => ipcRenderer.removeListener("update-available", handler)
  },
  onUpdateProgress: (callback) => {
    const handler = (_event, data) => callback(data)
    ipcRenderer.on("update-progress", handler)
    return () => ipcRenderer.removeListener("update-progress", handler)
  },
  onUpdateDownloaded: (callback) => {
    const handler = (_event, data) => callback(data)
    ipcRenderer.on("update-downloaded", handler)
    return () => ipcRenderer.removeListener("update-downloaded", handler)
  },

  // File dialogs
  openFileDialog: () => ipcRenderer.invoke("open-file-dialog"),

  // Event listeners
  onScannerProgress: (callback) => {
    const handler = (_event, data) => callback(data)
    ipcRenderer.on("scanner-progress", handler)
    return () => ipcRenderer.removeListener("scanner-progress", handler)
  },
})
