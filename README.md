# 🔍 NodeJS-PortScanner

> Speedy port scanner with service fingerprinting for Node.js

A fast, lightweight port scanner with service fingerprinting, built in Node.js. Designed for network administrators and security learners to audit their own systems.

---

## ⚠️ Legal Disclaimer

**Only scan systems you own or have explicit written permission to test.** Unauthorized port scanning may violate the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), and equivalent laws in your jurisdiction. The authors assume no liability for misuse.

---

## ✨ Features

- ⚡ **Concurrent scanning** with configurable connection limits
- 🌐 **TCP and UDP** scanning (`--protocol tcp|udp`)
- 🎯 **Port range support** (e.g., `1-1024`, `80,443,8080`)
- 🔎 **Service fingerprinting** — identifies common services via banner grabbing
- ⏱️ **Configurable timeouts** for slow or filtered hosts
- 🛡️ **Rate limiting** to reduce network noise (`--rate`)
- 📊 **Clean tabular output** with optional JSON or HTML export
- 🪶 **Zero heavy dependencies** — uses Node's built-in `net` and `dgram` modules

---

## 🐳 Run with Docker (recommended)

The quickest way to run NodeJS-PortScanner is the pre-built image on the GitHub Container Registry — no Node.js install or clone required. Any flags after the image name are passed straight to the scanner:

```bash
docker run --rm ghcr.io/zuedev/nodejs-portscanner --host example.com --ports 1-1024
docker run --rm ghcr.io/zuedev/nodejs-portscanner --help
```

### Scanning the host's own network

By default the container scans from its own isolated network namespace. On **Linux**, share the host network to reach the host's own interfaces or `localhost`:

```bash
docker run --rm --network host ghcr.io/zuedev/nodejs-portscanner --host 127.0.0.1 --ports 1-1024
```

> 🪟 **Windows & macOS (Docker Desktop):** `--network host` shares the network of Docker's internal Linux VM — **not** your machine — so `127.0.0.1` won't reach services running on your host. Drop `--network host` and target `host.docker.internal` instead, which Docker Desktop routes to the host:
>
> ```bash
> docker run --rm ghcr.io/zuedev/nodejs-portscanner --host host.docker.internal --ports 1-1024
> ```
>
> If a service is bound only to `127.0.0.1` on the host (rather than `0.0.0.0`), rebind it to all interfaces so the container can reach it.

### Saving a JSON report

Mount a writable directory and write the report into it:

```bash
docker run --rm -v "${PWD}:/data" ghcr.io/zuedev/nodejs-portscanner -h example.com -p 1-1024 -o /data/results.json
# On Linux, add --user "$(id -u):$(id -g)" so the file is owned by you.
```

### Building the image yourself

From a clone of the repo:

```bash
docker build -t nodejs-portscanner .
docker run --rm nodejs-portscanner --host example.com --ports 1-1024
```

---

## 📦 Install from source

```bash
git clone https://github.com/zuedev/nodejs-portscanner.git
cd nodejs-portscanner
npm install
```

Or install globally:

```bash
npm install -g .
```

---

## 🚀 Usage

> 💡 **Using Docker?** Replace `node scanner.js` with `docker run --rm ghcr.io/zuedev/nodejs-portscanner` in any example below.

### Basic scan

```bash
node scanner.js --host 192.168.1.1 --ports 1-1024
```

### Scan specific ports

```bash
node scanner.js --host example.com --ports 22,80,443,8080
```

### Scan UDP ports

```bash
node scanner.js --host 192.168.1.1 --protocol udp --ports 53,123,161
```

UDP is connectionless, so ports that never reply are reported as `open|filtered`
(open or firewalled) rather than `open`. Tailored probes are sent to common
services (DNS, NTP) to encourage a response.

### Adjust concurrency and timeout

```bash
node scanner.js --host 10.0.0.5 --ports 1-65535 --concurrency 200 --timeout 1500
```

### Limit the scan rate

```bash
node scanner.js --host 192.168.1.1 --ports 1-1024 --rate 50
```

Caps how many new probes are started each second across all workers, reducing
network noise and load on the target. Unlimited by default.

### Export results to JSON

```bash
node scanner.js --host 192.168.1.1 --ports 1-1024 --output results.json
```

### Export results to an HTML report

```bash
node scanner.js --host 192.168.1.1 --ports 1-1024 --output report.html
```

The format is chosen from the file extension: `.html` (or `.htm`) writes a
self-contained, styled HTML report you can open in any browser; any other
extension writes JSON. Banner text is HTML-escaped, so reports are safe to open
even after scanning untrusted hosts.

---

## ⚙️ Options

| Flag            | Alias | Description                                                      | Default   |
| --------------- | ----- | ---------------------------------------------------------------- | --------- |
| `--host`        | `-h`  | Target hostname or IP address (required)                         | —         |
| `--ports`       | `-p`  | Port range or comma-separated list                               | `1-1024`  |
| `--protocol`    | `-P`  | Transport protocol (`tcp` or `udp`)                              | `tcp`     |
| `--concurrency` | `-c`  | Max simultaneous connections                                     | `100`     |
| `--timeout`     | `-t`  | Connection timeout in milliseconds                               | `2000`    |
| `--rate`        | `-r`  | Max new probes started per second                                | unlimited |
| `--output`      | `-o`  | Export results to a file (`.html` → HTML report, otherwise JSON) | none      |
| `--help`        | —     | Show help menu                                                   | —         |

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

NodeJS-PortScanner uses Node's built-in `net.Socket` to attempt TCP connections against target ports. For each open port, it:

1. Establishes a connection within the configured timeout.
2. Attempts **banner grabbing** by reading initial server response data.
3. Matches banners against a fingerprint database to identify the service.

Concurrency is managed via a connection pool to avoid overwhelming the target or the host's file descriptor limits.

UDP scans (`--protocol udp`) use Node's `dgram` module instead. Since UDP has no handshake, each port is classified by the target's response:

- a **datagram reply** → `open`
- an **ICMP port-unreachable** error → `closed`
- **silence** until the timeout → `open|filtered` (open or firewalled)

---

## 🗺️ Roadmap

- [x] Concurrent TCP scanning with a connection pool
- [x] Service fingerprinting via banner grabbing
- [x] Port ranges and lists (`1-1024`, `80,443,8080`)
- [x] JSON export
- [x] Test suite backed by a local mock server
- [x] UDP scanning support
- [ ] Configurable fingerprint database (JSON-based)
- [ ] CIDR range scanning (e.g., `192.168.1.0/24`)
- [x] Rate limiting to reduce network noise
- [x] HTML report generation

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

This project is licensed under the Unlicense — see the [LICENSE](LICENSE) file for details.

---

## 🙋 Author

Built by [zuedev](https://github.com/zuedev) as part of a hands-on security learning portfolio.
