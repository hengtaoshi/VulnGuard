# Python 测试文件 — 包含漏洞模式
import os
import subprocess
from flask import Flask, request

app = Flask(__name__)

# 硬编码密钥
DB_PASSWORD = "SuperSecret123!"
API_KEY = "sk-live-abcdefghijklmnopqrstuvwxyz123456"

# 命令注入
@app.route("/ping")
def ping():
    ip = request.args.get("ip", "")
    result = os.system("ping " + ip)
    return str(result)

# 不安全的文件操作
@app.route("/read")
def read_file():
    filename = request.args.get("file", "")
    with open("/var/data/" + filename) as f:
        return f.read()

# eval 注入
@app.route("/calc")
def calc():
    expr = request.args.get("expr", "")
    result = eval(expr)
    return str(result)
