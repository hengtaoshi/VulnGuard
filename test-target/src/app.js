// test-app.js — JS/TS 测试文件，包含多种漏洞模式
const express = require("express")
const { exec } = require("child_process")
const app = express()

// 硬编码密钥 — 测试 Gitleaks / TruffleHog
const AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"
const SLACK_TOKEN = "xoxb-123456789012-1234567890123-abc123def456ghi789jkl012"

// 命令注入 — 测试 Semgrep / CodeQL
app.get("/ping", (req, res) => {
  const ip = req.query.ip
  exec("ping " + ip, (err, stdout) => {
    res.send(stdout)
  })
})

// SQL 注入 — 测试 Semgrep / CodeQL
app.get("/user", (req, res) => {
  const id = req.query.id
  const query = "SELECT * FROM users WHERE id = " + id
  db.query(query, (err, rows) => {
    res.json(rows)
  })
})

// 路径遍历 — 测试 Semgrep / CodeQL
app.get("/file", (req, res) => {
  const fileName = req.query.file
  res.sendFile("/var/www/" + fileName)
})

// XSS — 测试 Nuclei / Semgrep
app.get("/search", (req, res) => {
  const q = req.query.q
  res.send("<html><body>搜索结果: " + q + "</body></html>")
})

// 不安全的随机数 — 测试 CodeQL
function generateToken() {
  return Math.random().toString(36)
}

app.listen(3000)
