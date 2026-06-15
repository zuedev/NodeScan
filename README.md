# 🔍 NodeScan

> Speedy port scanner with service fingerprinting for Node.js

A fast, lightweight port scanner with service fingerprinting, built in Node.js. Designed for network administrators and security learners to audit their own systems.

---

## ⚠️ Legal Disclaimer

**Only scan systems you own or have explicit written permission to test.** Unauthorized port scanning may violate the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), and equivalent laws in your jurisdiction. The authors assume no liability for misuse.

---

## ✨ Features

- ⚡ **Concurrent scanning** with configurable connection limits
- 🎯 **Port range support** (e.g., `1-1024`, `80,443,8080`)
- 🔎 **Service fingerprinting** — identifies common services via banner grabbing
- ⏱️ **Configurable timeouts** for slow or filtered hosts
- 📊 **Clean tabular output** with optional JSON export
- 🪶 **Zero heavy dependencies** — uses Node's built-in `net` module

---

## 📦 Installation

```bash
git clone https://github.com/yourusername/nodescan.git
cd nodescan
npm install
```

Or install globally:

```bash
npm install -g .
```

---

## 🚀 Usage

### Basic scan

```bash
node scanner.js --host 192.168.1.1 --ports 1-1024
```

### Scan specific ports

```bash
node scanner.js --host example.com --ports 22,80,443,8080
```

### Adjust concurrency and timeout

```bash
node scanner.js --host 10.0.0.5 --ports 1-65535 --concurrency 200 --timeout 1500
```

### Export results to JSON

```bash
node scanner.js --host 192.168.1.1 --ports 1-1024 --output results.json
```

---

## ⚙️ Options

| Flag            | Alias | Description                              | Default  |
| --------------- | ----- | ---------------------------------------- | -------- |
| `--host`        | `-h`  | Target hostname or IP address (required) | —        |
| `--ports`       | `-p`  | Port range or comma-separated list       | `1-1024` |
| `--concurrency` | `-c`  | Max simultaneous connections             | `100`    |
| `--timeout`     | `-t`  | Connection timeout in milliseconds       | `2000`   |
| `--output`      | `-o`  | Export results to a JSON file            | none     |
| `--help`        | —     | Show help menu                           | —        |

---

## 📋 Example Output

```
Scanning 192.168.1.1 (ports 1-1024)...

PORT     STATE    SERVICE
22/tcp   open     SSH (OpenSSH 8.9)
80/tcp   open     HTTP (nginx 1.18.0)
443/tcp  open     HTTPS
3306/tcp open     MySQL

Scan complete: 4 open ports found in 3.2s
```

---

## 🛠️ How It Works

NodeScan uses Node's built-in `net.Socket` to attempt TCP connections against target ports. For each open port, it:

1. Establishes a connection within the configured timeout.
2. Attempts **banner grabbing** by reading initial server response data.
3. Matches banners against a fingerprint database to identify the service.

Concurrency is managed via a connection pool to avoid overwhelming the target or the host's file descriptor limits.

---

## 🗺️ Roadmap

- [x] Concurrent TCP scanning with a connection pool
- [x] Service fingerprinting via banner grabbing
- [x] Port ranges and lists (`1-1024`, `80,443,8080`)
- [x] JSON export
- [x] Test suite backed by a local mock server
- [ ] UDP scanning support
- [ ] Configurable fingerprint database (JSON-based)
- [ ] CIDR range scanning (e.g., `192.168.1.0/24`)
- [ ] Rate limiting to reduce network noise
- [ ] HTML report generation

---

## 🧪 Testing

```bash
npm test
```

Tests use a local mock server to validate scanning logic without external network calls.

---

## 🤝 Contributing

Contributions are welcome! Please open an issue first to discuss major changes. Make sure tests pass before submitting a PR.

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## 🙋 Author

Built by [Your Name](https://github.com/yourusername) as part of a hands-on security learning portfolio.
