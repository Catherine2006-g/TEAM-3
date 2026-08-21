from scanner import MalwareScanner

scanner = MalwareScanner()
result = scanner.scan("sample.exe")

print(result)
