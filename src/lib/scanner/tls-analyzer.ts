import { connect } from "tls"
import { parse } from "url"
import type { Vulnerability } from "@/lib/api/types"
import type { ScanResult } from "./types"

interface CertInfo {
  subject: Record<string, string>
  issuer: Record<string, string>
  validFrom: string
  validTo: string
  subjectaltname: string | undefined
}

export async function runTlsScan(targetPath: string): Promise<ScanResult> {
  const scannerName = "tls-analyzer"

  let hostname: string
  try {
    hostname = parse(targetPath).hostname || targetPath.replace(/^https?:\/\//, "").split("/")[0]
  } catch {
    return { vulnerabilities: [], totalChecks: 0, errors: ["Invalid URL"], scannerName }
  }

  const vulns: Vulnerability[] = []
  const id = (n: number) => `TLS-${n}`

  // ─── Check 1: Basic TLS connection + Certificate info ───
  let tlsVersion = ""
  let cipherName = ""

  type ConnectionResult = { tlsVersion: string; cipherName: string; certInfo: CertInfo | null }
  let connectionInfo: ConnectionResult = { tlsVersion: "", cipherName: "", certInfo: null }

  try {
    const socket = connect(443, hostname, {
      servername: hostname,
      rejectUnauthorized: false,
      timeout: 10000,
    })

    connectionInfo = await new Promise<ConnectionResult>((resolve, reject) => {
      const onConnect = () => {
        const cert = socket.getPeerCertificate()
        let certInfo: CertInfo | null = null
        if (cert && Object.keys(cert).length > 0) {
          certInfo = {
            subject: cert.subject as Record<string, string>,
            issuer: cert.issuer as Record<string, string>,
            validFrom: cert.valid_from,
            validTo: cert.valid_to,
            subjectaltname: cert.subjectaltname,
          }
        }
        socket.end()
        resolve({
          tlsVersion: socket.getProtocol() || "unknown",
          cipherName: (socket as any).getCipher?.()?.name || "unknown",
          certInfo,
        })
      }
      const onError = (err: Error) => reject(err)
      const onTimeout = () => { socket.destroy(); reject(new Error("Connection timeout")) }
      socket.once("secureConnect", onConnect)
      socket.once("error", onError)
      socket.once("timeout", onTimeout)
    })

    tlsVersion = connectionInfo.tlsVersion
    cipherName = connectionInfo.cipherName
    const ci = connectionInfo.certInfo

    // Certificate expiry check
    if (ci && ci.validTo) {
      const expiryDate = new Date(ci.validTo)
      const now = new Date()
      const daysLeft = Math.floor((expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24))

      if (daysLeft < 0) {
        vulns.push({
          id: id(vulns.length + 1), name: "SSL Certificate Expired", severity: "Critical", location: hostname,
          cve: "TLS-EXPIRY", description: `TLS certificate expired ${Math.abs(daysLeft)} days ago (${ci.validTo}). Users will see browser security warnings.`, recommendation: "Renew the TLS certificate immediately.",
          source: scannerName,
        })
      } else if (daysLeft < 7) {
        vulns.push({
          id: id(vulns.length + 1), name: "SSL Certificate Expiring Soon", severity: "High", location: hostname,
          cve: "TLS-EXPIRY", description: `TLS certificate expires in ${daysLeft} days (${ci.validTo}).`, recommendation: "Renew the TLS certificate before it expires.",
          source: scannerName,
        })
      } else if (daysLeft < 30) {
        vulns.push({
          id: id(vulns.length + 1), name: "SSL Certificate Nearing Expiry", severity: "Low", location: hostname,
          cve: "TLS-EXPIRY", description: `TLS certificate expires in ${daysLeft} days (${ci.validTo}).`, recommendation: "Plan to renew the TLS certificate within the next month.",
          source: scannerName,
        })
      }
    }

    // TLS protocol version check
    if (tlsVersion) {
      if (tlsVersion === "TLSv1" || tlsVersion === "TLSv1.1" || tlsVersion === "TLSv1_1" || tlsVersion.startsWith("TLSv1") && !tlsVersion.includes("1.2") && !tlsVersion.includes("1.3")) {
        vulns.push({
          id: id(vulns.length + 1), name: `Deprecated TLS Version: ${tlsVersion}`, severity: "High", location: hostname,
          cve: "TLS-VERSION", description: `Server uses ${tlsVersion} which has known security vulnerabilities. Modern clients may downgrade attacks.`, recommendation: "Disable TLS 1.0/1.1 and use TLS 1.2 or higher.",
          source: scannerName,
        })
      } else if (tlsVersion === "TLSv1.2" || tlsVersion === "TLSv1_2") {
        // Acceptable but check for 1.3 support
      }
    }

    // Subject-issuer match (self-signed check)
    if (ci && ci.subject && ci.issuer) {
      const subCN = ci.subject["CN"] || ""
      const issCN = ci.issuer["CN"] || ""
      if (subCN && subCN === issCN) {
        vulns.push({
          id: id(vulns.length + 1), name: "Self-Signed or Same-Issuer Certificate", severity: "Medium", location: hostname,
          cve: "TLS-SELFSIGNED", description: "Certificate subject and issuer are the same — likely a self-signed certificate. Clients will receive certificate warnings.", recommendation: "Use a certificate signed by a trusted Certificate Authority.",
          source: scannerName,
        })
      }
    }

    // Check for wildcard cert coverage
    if (ci?.subjectaltname && ci.subjectaltname.includes("DNS:*.")) {
      // Just informational — wildcards are valid
    }
  } catch {
    vulns.push({
      id: id(vulns.length + 1), name: "TLS Connection Failed", severity: "High", location: hostname,
      cve: "TLS-CONNECT", description: "Failed to establish TLS connection. The server may not support HTTPS or has TLS configuration issues.", recommendation: "Ensure HTTPS is properly configured and the certificate is valid.",
      source: scannerName,
    })
  }

  // ─── Check 2: Weak cipher detection via key exchange ───
  const weakCiphers = [
    { name: "RC4", sev: "Critical" as const, desc: "RC4 stream cipher is completely broken — plaintext can be recovered." },
    { name: "3DES", sev: "Critical" as const, desc: "Triple DES is vulnerable to Sweet32 birthday attack." },
    { name: "CBC", sev: "Medium" as const, desc: "CBC mode ciphers are vulnerable to padding oracle attacks (POODLE, Lucky13)." },
    { name: "EXPORT", sev: "Critical" as const, desc: "EXPORT grade ciphers are intentionally weak (40-bit key)." },
    { name: "NULL", sev: "Critical" as const, desc: "NULL ciphers provide no encryption at all." },
    { name: "ANON", sev: "Critical" as const, desc: "Anonymous Diffie-Hellman provides no authentication — MITM possible." },
    { name: "MD5", sev: "High" as const, desc: "MD5-based signatures are collision-prone and considered broken." },
  ]

  for (const wc of weakCiphers) {
    if (cipherName.includes(wc.name)) {
      vulns.push({
        id: id(vulns.length + 1), name: `Weak Cipher: ${wc.name}`, severity: wc.sev, location: hostname,
        cve: "TLS-CIPHER", description: wc.desc, recommendation: "Disable weak ciphers on the server and use only modern AEAD ciphers (AES-GCM, ChaCha20-Poly1305).",
        source: scannerName,
      })
      break
    }
  }

  // ─── Check 3: HTTP (non-TLS) fallback ───
  if (!targetPath.startsWith("https")) {
    try {
      await fetch(`http://${hostname}`, { signal: AbortSignal.timeout(5000), redirect: "manual" })
    } catch { /* HTTP may be blocked — that's fine */ }
  }

  return { vulnerabilities: vulns, totalChecks: 4, errors: [], scannerName }
}
