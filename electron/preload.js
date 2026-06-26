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
  // 动态从 main process 获取版本，避免打包后 process.env.npm_package_version 不可用
  version: require("electron").ipcRenderer.sendSync("get-version-sync") || "0.0.0",

  // IPC helpers for future use
  getDataDir: () => ipcRenderer.invoke("get-data-dir"),
  downloadScanner: (name) => ipcRenderer.invoke("download-scanner", name),
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
