@echo off
set HTTPS_PROXY=http://127.0.0.1:7897
set HTTP_PROXY=http://127.0.0.1:7897
"D:\demo\cm\vuln-guard\tools\bin\codeql\codeql\codeql.exe" pack download codeql/javascript-queries codeql/python-queries codeql/java-queries codeql/go-queries codeql/cpp-queries codeql/csharp-queries codeql/ruby-queries codeql/swift-queries
echo [%date% %time%] Download complete!
