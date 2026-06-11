import { exec } from "child_process"

export interface ExecResult {
  stdout: string
  stderr: string
}

/**
 * Async version of execSync — runs a command without blocking the event loop.
 * Throws on non-zero exit code, just like execSync.
 */
export function execAsync(command: string, options: { timeout?: number; maxBuffer?: number; cwd?: string; env?: NodeJS.ProcessEnv } = {}): Promise<ExecResult> {
  const { timeout = 30000, maxBuffer = 10 * 1024 * 1024, cwd, env } = options

  return new Promise((resolve, reject) => {
    const child = exec(command, { timeout, maxBuffer, cwd, env: env as any }, (err, stdout, stderr) => {
      if (err) {
        // Node.js 24+ 不再把 stdout/stderr 挂载到 error 对象上，
        // 但很多扫描器（bandit、semgrep 等）在非零退出时有有效输出需要读取。
        // 手动挂载上去，确保下游 catch 块能取到。
        ;(err as any).stdout = stdout
        ;(err as any).stderr = stderr
        reject(err)
      } else {
        resolve({ stdout, stderr })
      }
    })
  })
}
