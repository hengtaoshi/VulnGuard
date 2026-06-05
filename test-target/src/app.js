const express = require("express")
const app = express()

// SQL Injection
app.get("/user", (req, res) => {
  const id = req.query.id
  const query = `SELECT * FROM users WHERE id = '${id}'`
  db.query(query, (err, result) => {
    res.json(result)
  })
})

// Hardcoded secret
const API_KEY = "sk-1234567890abcdef"

// XSS
app.get("/search", (req, res) => {
  const q = req.query.q
  res.send(`<div>Search results for: ${q}</div>`)
})

// Command Injection
app.get("/ping", (req, res) => {
  const host = req.query.host
  require("child_process").exec(`ping -c 1 ${host}`, (err, stdout) => {
    res.send(stdout)
  })
})

// Insecure JWT
const jwt = require("jsonwebtoken")
app.post("/login", (req, res) => {
  const token = jwt.sign({ user: "admin", role: "admin" }, "hardcoded-secret")
  res.json({ token })
})

// Path Traversal
app.get("/read", (req, res) => {
  const fs = require("fs")
  const file = req.query.file
  fs.readFile(`/var/www/${file}`, "utf8", (err, data) => {
    res.send(data)
  })
})

// No rate limiting
app.post("/api/transfer", (req, res) => {
  const { to, amount } = req.body
  executeTransfer(to, amount)
  res.json({ success: true })
})

// Insecure crypto
const crypto = require("crypto")
function encrypt(data) {
  const cipher = crypto.createCipher("des", "password123")
  let encrypted = cipher.update(data, "utf8", "hex")
  encrypted += cipher.final("hex")
  return encrypted
}

// Open redirect
app.get("/redirect", (req, res) => {
  const url = req.query.url
  res.redirect(url)
})

// Prototype pollution
app.post("/config", (req, res) => {
  Object.assign(app.config, req.body)
  res.json({ ok: true })
})

app.listen(3000)
