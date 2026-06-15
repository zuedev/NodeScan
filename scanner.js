#!/usr/bin/env node
/**
 * NodeScan — a fast, lightweight TCP port scanner with service fingerprinting.
 *
 * The module exports small, pure-ish building blocks (port parsing, argument
 * parsing, fingerprinting, formatting) alongside the network primitives
 * (`scanPort`, `scanPorts`) so the logic can be unit-tested against a local
 * mock server without any real network access. When executed directly it runs
 * as a CLI.
 */

import net from "node:net";
import dgram from "node:dgram";
import { writeFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

/** Default option values, shared between the CLI and programmatic API. */
export const DEFAULTS = Object.freeze({
    ports: "1-1024",
    protocol: "tcp",
    concurrency: 100,
    timeout: 2000,
});

/** Largest banner (in bytes) we are willing to buffer per connection. */
const MAX_BANNER_BYTES = 4096;

/** How long to keep reading after the first banner byte arrives (ms). */
const BANNER_SETTLE_MS = 60;

// ---------------------------------------------------------------------------
// Port parsing
// ---------------------------------------------------------------------------

const MIN_PORT = 1;
const MAX_PORT = 65535;

/**
 * Convert a single textual port into a validated number.
 * @param {string} value
 * @param {string} original - the original token, used for error messages
 * @returns {number}
 */
function toPort(value, original) {
    if (!/^\d+$/.test(value)) {
        throw new Error(
            `Invalid port: "${original}" (must be an integer between ${MIN_PORT} and ${MAX_PORT})`,
        );
    }
    const port = Number(value);
    if (port < MIN_PORT || port > MAX_PORT) {
        throw new Error(
            `Invalid port: "${original}" (must be between ${MIN_PORT} and ${MAX_PORT})`,
        );
    }
    return port;
}

/**
 * Parse a port specification into a sorted, de-duplicated list of ports.
 * Supports comma-separated values and inclusive ranges, e.g.
 * `"1-1024"`, `"80,443,8080"`, or `"22,80,8000-8010"`.
 *
 * @param {string} spec
 * @returns {number[]}
 */
export function parsePorts(spec) {
    if (typeof spec !== "string" || spec.trim() === "") {
        throw new Error("Port specification must be a non-empty string");
    }

    const ports = new Set();
    const tokens = spec
        .split(",")
        .map((t) => t.trim())
        .filter((t) => t.length > 0);

    if (tokens.length === 0) {
        throw new Error("Port specification must contain at least one port");
    }

    for (const token of tokens) {
        if (token.includes("-")) {
            const bounds = token.split("-");
            if (bounds.length !== 2) {
                throw new Error(`Invalid port range: "${token}"`);
            }
            const start = toPort(bounds[0].trim(), token);
            const end = toPort(bounds[1].trim(), token);
            if (start > end) {
                throw new Error(`Invalid port range (start > end): "${token}"`);
            }
            for (let p = start; p <= end; p++) {
                ports.add(p);
            }
        } else {
            ports.add(toPort(token, token));
        }
    }

    return [...ports].sort((a, b) => a - b);
}

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

const ALIASES = Object.freeze({
    "-h": "--host",
    "-p": "--ports",
    "-P": "--protocol",
    "-c": "--concurrency",
    "-t": "--timeout",
    "-o": "--output",
});

/**
 * Require that an option was supplied a value.
 * @param {string} flag
 * @param {string|undefined} value
 * @returns {string}
 */
function requireValue(flag, value) {
    if (value === undefined) {
        throw new Error(`Option "${flag}" requires a value`);
    }
    return value;
}

/**
 * Parse a positive integer option value.
 * @param {string} value
 * @param {string} flag
 * @returns {number}
 */
function toPositiveInt(value, flag) {
    if (!/^\d+$/.test(value) || Number(value) < 1) {
        throw new Error(
            `Option "${flag}" requires a positive integer (got "${value}")`,
        );
    }
    return Number(value);
}

/**
 * Validate and normalise the transport protocol option.
 * @param {string} value
 * @param {string} flag
 * @returns {("tcp"|"udp")}
 */
function toProtocol(value, flag) {
    const normalized = String(value).toLowerCase();
    if (normalized !== "tcp" && normalized !== "udp") {
        throw new Error(
            `Option "${flag}" must be "tcp" or "udp" (got "${value}")`,
        );
    }
    return normalized;
}

/**
 * Parse CLI arguments (everything after `node scanner.js`).
 *
 * @param {string[]} argv
 * @returns {{host: string|null, ports: string, protocol: ("tcp"|"udp"),
 *   concurrency: number, timeout: number, output: string|null,
 *   help: boolean}}
 */
export function parseArgs(argv) {
    const options = {
        host: null,
        ports: DEFAULTS.ports,
        protocol: DEFAULTS.protocol,
        concurrency: DEFAULTS.concurrency,
        timeout: DEFAULTS.timeout,
        output: null,
        help: false,
    };

    for (let i = 0; i < argv.length; i++) {
        let flag = argv[i];

        // Support `--flag=value` syntax by splitting on the first `=`.
        let inlineValue;
        const eq = flag.indexOf("=");
        if (flag.startsWith("--") && eq !== -1) {
            inlineValue = flag.slice(eq + 1);
            flag = flag.slice(0, eq);
        }

        if (ALIASES[flag]) {
            flag = ALIASES[flag];
        }

        const nextValue = () =>
            inlineValue !== undefined
                ? inlineValue
                : requireValue(flag, argv[++i]);

        switch (flag) {
            case "--help":
                options.help = true;
                break;
            case "--host":
                options.host = nextValue();
                break;
            case "--ports":
                options.ports = nextValue();
                break;
            case "--protocol":
                options.protocol = toProtocol(nextValue(), flag);
                break;
            case "--concurrency":
                options.concurrency = toPositiveInt(nextValue(), flag);
                break;
            case "--timeout":
                options.timeout = toPositiveInt(nextValue(), flag);
                break;
            case "--output":
                options.output = nextValue();
                break;
            default:
                throw new Error(`Unknown option: "${argv[i]}"`);
        }
    }

    return options;
}

// ---------------------------------------------------------------------------
// Service fingerprinting
// ---------------------------------------------------------------------------

/** Map of well-known ports to a default service label. */
export const WELL_KNOWN_PORTS = Object.freeze({
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
    // Commonly UDP-only services.
    123: "NTP",
    137: "NetBIOS-NS",
    161: "SNMP",
    500: "ISAKMP",
    514: "Syslog",
    1900: "SSDP",
    5353: "mDNS",
});

/**
 * Ordered banner signatures. The first matching pattern wins, so more specific
 * patterns must come before more generic ones.
 * @type {Array<{pattern: RegExp, label: (m: RegExpMatchArray) => string}>}
 */
export const BANNER_SIGNATURES = Object.freeze([
    {
        pattern: /SSH-\d+(?:\.\d+)?-OpenSSH[_/-]?([\d.]+)/i,
        label: (m) => `SSH (OpenSSH ${m[1]})`,
    },
    { pattern: /SSH-\d/i, label: () => "SSH" },
    {
        pattern: /server:\s*nginx(?:\/([\d.]+))?/i,
        label: (m) => (m[1] ? `HTTP (nginx ${m[1]})` : "HTTP (nginx)"),
    },
    {
        pattern: /server:\s*Apache(?:\/([\d.]+))?/i,
        label: (m) => (m[1] ? `HTTP (Apache ${m[1]})` : "HTTP (Apache)"),
    },
    { pattern: /HTTP\/\d\.\d/i, label: () => "HTTP" },
    {
        pattern: /vsftpd\s*([\d.]+)?/i,
        label: (m) => (m[1] ? `FTP (vsFTPd ${m[1]})` : "FTP"),
    },
    { pattern: /220[\s-].*(?:ftp|filezilla|pure-ftpd)/i, label: () => "FTP" },
    { pattern: /220[\s-].*(?:smtp|esmtp)/i, label: () => "SMTP" },
    { pattern: /\+OK.*pop3/i, label: () => "POP3" },
    { pattern: /\*\s*OK.*IMAP/i, label: () => "IMAP" },
    {
        pattern: /mysql_native_password|mariadb|\bmysql\b/i,
        label: () => "MySQL",
    },
    { pattern: /-ERR.*redis|redis_version/i, label: () => "Redis" },
]);

/**
 * Identify the service running on a port using its banner (preferred) and a
 * well-known-port fallback.
 *
 * @param {number} port
 * @param {string} [banner]
 * @returns {string}
 */
export function fingerprint(port, banner = "") {
    const text = String(banner ?? "");
    if (text.length > 0) {
        for (const sig of BANNER_SIGNATURES) {
            const match = text.match(sig.pattern);
            if (match) {
                return sig.label(match);
            }
        }
    }
    return WELL_KNOWN_PORTS[port] ?? "unknown";
}

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

/**
 * @typedef {Object} ScanResult
 * @property {number} port
 * @property {("tcp"|"udp")} protocol
 * @property {boolean} open - true only when the state is definitively "open"
 * @property {("open"|"closed"|"open|filtered")} state
 * @property {string} banner
 * @property {string|null} service
 */

/**
 * Attempt a TCP connection to a single port and, when open, grab any banner
 * the server volunteers in order to fingerprint the service.
 *
 * Always resolves (never rejects) with a {@link ScanResult}.
 *
 * @param {string} host
 * @param {number} port
 * @param {{timeout?: number, grabBanner?: boolean, bannerTimeout?: number}} [options]
 * @returns {Promise<ScanResult>}
 */
export function scanPort(host, port, options = {}) {
    const {
        timeout = DEFAULTS.timeout,
        grabBanner = true,
        bannerTimeout = Math.min(750, timeout),
    } = options;

    return new Promise((resolve) => {
        const socket = new net.Socket();
        let banner = "";
        let connected = false;
        let settled = false;
        let bannerTimer = null;

        const finish = (open) => {
            if (settled) return;
            settled = true;
            if (bannerTimer) clearTimeout(bannerTimer);
            socket.destroy();
            const trimmed = banner.trim();
            resolve({
                port,
                protocol: "tcp",
                open,
                state: open ? "open" : "closed",
                banner: trimmed,
                service: open ? fingerprint(port, trimmed) : null,
            });
        };

        socket.setTimeout(timeout);

        socket.once("connect", () => {
            connected = true;
            // Connection succeeded; the connect timeout no longer applies. From here
            // we only wait a short window for an optional banner.
            socket.setTimeout(0);
            if (!grabBanner) {
                finish(true);
                return;
            }
            bannerTimer = setTimeout(() => finish(true), bannerTimeout);
        });

        socket.on("data", (chunk) => {
            banner += chunk.toString("utf8");
            if (banner.length >= MAX_BANNER_BYTES) {
                finish(true);
                return;
            }
            // Keep collecting briefly in case the banner spans multiple packets.
            if (bannerTimer) clearTimeout(bannerTimer);
            bannerTimer = setTimeout(() => finish(true), BANNER_SETTLE_MS);
        });

        // A connect timeout means the port is filtered/closed; once connected the
        // timeout is disabled so this only fires before a successful connection.
        socket.once("timeout", () => finish(false));
        socket.once("error", () => finish(false));
        socket.once("close", () => finish(connected));

        socket.connect(port, host);
    });
}

// ---------------------------------------------------------------------------
// UDP scanning
// ---------------------------------------------------------------------------

/** Choose a dgram socket type based on the target's address family. */
function udpSocketType(host) {
    return net.isIPv6(host) ? "udp6" : "udp4";
}

/**
 * A minimal DNS query (root NS record, recursion desired) used to coax a
 * response out of a resolver listening on UDP/53.
 */
const DNS_PROBE = Buffer.from([
    0x12,
    0x34, // transaction ID
    0x01,
    0x00, // flags: standard query, recursion desired
    0x00,
    0x01, // QDCOUNT = 1
    0x00,
    0x00, // ANCOUNT = 0
    0x00,
    0x00, // NSCOUNT = 0
    0x00,
    0x00, // ARCOUNT = 0
    0x00, // QNAME = root
    0x00,
    0x02, // QTYPE = NS
    0x00,
    0x01, // QCLASS = IN
]);

/** An NTPv3 client request (mode 3) used to probe UDP/123. */
const NTP_PROBE = (() => {
    const buf = Buffer.alloc(48);
    buf[0] = 0x1b; // LI = 0, Version = 3, Mode = 3 (client)
    return buf;
})();

/** Fallback payload for UDP ports without a tailored probe. */
const DEFAULT_UDP_PROBE = Buffer.from("\r\n");

/**
 * Select a probe payload for a UDP port. Tailored probes elicit replies from
 * services that ignore arbitrary data; everything else gets a generic nudge.
 * @param {number} port
 * @returns {Buffer}
 */
function udpProbe(port) {
    switch (port) {
        case 53:
            return DNS_PROBE;
        case 123:
            return NTP_PROBE;
        default:
            return DEFAULT_UDP_PROBE;
    }
}

/**
 * Probe a single UDP port. Because UDP is connectionless there is no handshake
 * to observe, so the state is inferred from how the target responds:
 *
 * - a datagram reply  -> `"open"`
 * - an ICMP port-unreachable (ECONNREFUSED / ECONNRESET) -> `"closed"`
 * - silence until the timeout -> `"open|filtered"` (open or firewalled)
 *
 * Always resolves (never rejects) with a {@link ScanResult}.
 *
 * @param {string} host
 * @param {number} port
 * @param {{timeout?: number}} [options]
 * @returns {Promise<ScanResult>}
 */
export function scanUdpPort(host, port, options = {}) {
    const { timeout = DEFAULTS.timeout } = options;

    return new Promise((resolve) => {
        const socket = dgram.createSocket(udpSocketType(host));
        let response = "";
        let settled = false;
        let timer = null;

        const finish = (state) => {
            if (settled) return;
            settled = true;
            if (timer) clearTimeout(timer);
            try {
                socket.close();
            } catch {
                // The socket may already be closing; nothing to do.
            }
            const banner = response.trim();
            resolve({
                port,
                protocol: "udp",
                open: state === "open",
                state,
                banner,
                service: state === "closed" ? null : fingerprint(port, banner),
            });
        };

        // An ICMP "port unreachable" surfaces as ECONNREFUSED on POSIX and
        // ECONNRESET on Windows: that means the port is closed. Treat anything
        // else (e.g. a DNS failure) as inconclusive.
        const classifyError = (err) => {
            const code = err && err.code;
            finish(
                code === "ECONNREFUSED" || code === "ECONNRESET"
                    ? "closed"
                    : "open|filtered",
            );
        };

        socket.on("message", (msg) => {
            response += msg.toString("utf8");
            finish("open");
        });
        socket.on("error", classifyError);

        // No reply within the timeout: UDP cannot distinguish a silent-but-open
        // service from a dropped packet, so report the ambiguous state.
        timer = setTimeout(() => finish("open|filtered"), timeout);

        // Connecting the socket lets the OS deliver ICMP errors back to us, which
        // is what makes closed-port detection possible.
        socket.connect(port, host, () => {
            socket.send(udpProbe(port), (err) => {
                if (err) classifyError(err);
            });
        });
    });
}

/**
 * Scan many ports concurrently using a bounded worker pool so we never exceed
 * the configured number of simultaneous connections.
 *
 * @param {string} host
 * @param {number[]} ports
 * @param {{protocol?: ("tcp"|"udp"), concurrency?: number, timeout?: number,
 *   grabBanner?: boolean, onResult?: (result: ScanResult) => void}} [options]
 * @returns {Promise<ScanResult[]>} results sorted ascending by port
 */
export async function scanPorts(host, ports, options = {}) {
    const {
        concurrency = DEFAULTS.concurrency,
        protocol = DEFAULTS.protocol,
        onResult,
    } = options;
    const scanOne = protocol === "udp" ? scanUdpPort : scanPort;
    const results = [];
    let next = 0;

    const worker = async () => {
        // `next++` runs synchronously before any await, so there is no race
        // between workers grabbing the same index.
        while (next < ports.length) {
            const port = ports[next++];
            const result = await scanOne(host, port, options);
            results.push(result);
            if (onResult) onResult(result);
        }
    };

    const poolSize = Math.max(1, Math.min(concurrency, ports.length));
    await Promise.all(Array.from({ length: poolSize }, () => worker()));

    results.sort((a, b) => a.port - b.port);
    return results;
}

// ---------------------------------------------------------------------------
// Output formatting
// ---------------------------------------------------------------------------

/**
 * Resolve a result's textual state, tolerating results that only carry the
 * older boolean `open` flag.
 * @param {{state?: string, open?: boolean}} result
 * @returns {("open"|"closed"|"open|filtered")}
 */
function stateOf(result) {
    if (result.state) return result.state;
    return result.open ? "open" : "closed";
}

/**
 * Render the open ports as an aligned table matching the documented output.
 * @param {ScanResult[]} results
 * @returns {string}
 */
export function formatTable(results) {
    const rows = results
        .filter((r) => stateOf(r) !== "closed")
        .map((r) => ({
            port: `${r.port}/${r.protocol ?? "tcp"}`,
            state: stateOf(r),
            service: r.service || "unknown",
        }));

    const portWidth = Math.max(
        "PORT".length,
        ...rows.map((r) => r.port.length),
    );
    const stateWidth = Math.max(
        "STATE".length,
        ...rows.map((r) => r.state.length),
    );

    const lines = [
        `${"PORT".padEnd(portWidth)}  ${"STATE".padEnd(stateWidth)}  SERVICE`,
    ];
    for (const row of rows) {
        lines.push(
            `${row.port.padEnd(portWidth)}  ${row.state.padEnd(stateWidth)}  ${row.service}`,
        );
    }
    return lines.join("\n");
}

/**
 * Build the one-line summary, e.g. `Scan complete: 4 open ports found in 3.2s`.
 * @param {ScanResult[]} results
 * @param {number} elapsedMs
 * @returns {string}
 */
export function formatSummary(results, elapsedMs) {
    const open = results.filter((r) => stateOf(r) === "open").length;
    const filtered = results.filter(
        (r) => stateOf(r) === "open|filtered",
    ).length;
    const seconds = (elapsedMs / 1000).toFixed(1);
    const noun = open === 1 ? "open port" : "open ports";
    let summary = `Scan complete: ${open} ${noun} found in ${seconds}s`;
    if (filtered > 0) {
        const filteredNoun = filtered === 1 ? "port" : "ports";
        summary += `, ${filtered} open|filtered ${filteredNoun}`;
    }
    return summary;
}

/**
 * Build a structured, JSON-serialisable report of a scan.
 * @param {{host: string, protocol?: ("tcp"|"udp"), ports: string,
 *   results: ScanResult[], elapsedMs: number}} params
 * @returns {object}
 */
export function buildJsonReport({
    host,
    protocol = "tcp",
    ports,
    results,
    elapsedMs,
}) {
    const toEntry = (r) => ({
        port: r.port,
        protocol: r.protocol ?? protocol,
        state: stateOf(r),
        service: r.service,
        banner: r.banner || null,
    });
    const open = results.filter((r) => stateOf(r) === "open");
    const openFiltered = results.filter((r) => stateOf(r) === "open|filtered");
    return {
        host,
        protocol,
        ports,
        scannedAt: new Date().toISOString(),
        durationMs: elapsedMs,
        totalScanned: results.length,
        openCount: open.length,
        open: open.map(toEntry),
        openFilteredCount: openFiltered.length,
        openFiltered: openFiltered.map(toEntry),
    };
}

/** The CLI help / usage text. */
export function helpText() {
    return `NodeScan — a fast, lightweight TCP port scanner.

Usage:
  node scanner.js --host <target> [options]

Options:
  -h, --host <host>          Target hostname or IP address (required)
  -p, --ports <spec>         Port range or list, e.g. 1-1024 or 80,443,8080
                             (default: ${DEFAULTS.ports})
  -P, --protocol <tcp|udp>   Transport protocol to scan (default: ${DEFAULTS.protocol})
  -c, --concurrency <n>      Max simultaneous connections (default: ${DEFAULTS.concurrency})
  -t, --timeout <ms>         Connection timeout in milliseconds (default: ${DEFAULTS.timeout})
  -o, --output <file>        Export results to a JSON file
      --help                 Show this help menu

Examples:
  node scanner.js --host 192.168.1.1 --ports 1-1024
  node scanner.js --host example.com --ports 22,80,443,8080
  node scanner.js --host 10.0.0.5 --ports 1-65535 -c 200 -t 1500
  node scanner.js --host 192.168.1.1 --ports 1-1024 --output results.json
  node scanner.js --host 192.168.1.1 --protocol udp --ports 53,123,161

UDP ports that never reply are reported as "open|filtered", because UDP cannot
distinguish a silent-but-open service from a firewalled one.

Only scan systems you own or have explicit written permission to test.`;
}

// ---------------------------------------------------------------------------
// CLI entry point
// ---------------------------------------------------------------------------

/**
 * Run the command-line interface. Output is injected so it can be captured in
 * tests, and the function resolves to a process exit code rather than calling
 * `process.exit` directly.
 *
 * @param {string[]} argv - arguments after `node scanner.js`
 * @param {{log?: (msg: string) => void, error?: (msg: string) => void}} [io]
 * @returns {Promise<number>} exit code
 */
export async function runCli(argv, io = {}) {
    const log = io.log ?? console.log;
    const errorLog = io.error ?? console.error;

    let options;
    try {
        options = parseArgs(argv);
    } catch (err) {
        errorLog(`Error: ${err.message}`);
        errorLog("Run with --help for usage.");
        return 1;
    }

    if (options.help) {
        log(helpText());
        return 0;
    }

    if (!options.host) {
        errorLog("Error: --host is required.");
        errorLog("Run with --help for usage.");
        return 1;
    }

    let ports;
    try {
        ports = parsePorts(options.ports);
    } catch (err) {
        errorLog(`Error: ${err.message}`);
        return 1;
    }

    log(
        `Scanning ${options.host} (${options.protocol.toUpperCase()} ports ${options.ports})...\n`,
    );

    const started = Date.now();
    const results = await scanPorts(options.host, ports, {
        protocol: options.protocol,
        concurrency: options.concurrency,
        timeout: options.timeout,
    });
    const elapsedMs = Date.now() - started;

    if (results.some((r) => stateOf(r) !== "closed")) {
        log(formatTable(results));
        log("");
    }
    log(formatSummary(results, elapsedMs));

    if (options.output) {
        const report = buildJsonReport({
            host: options.host,
            protocol: options.protocol,
            ports: options.ports,
            results,
            elapsedMs,
        });
        try {
            await writeFile(
                options.output,
                `${JSON.stringify(report, null, 2)}\n`,
                "utf8",
            );
            log(`\nResults written to ${options.output}`);
        } catch (err) {
            errorLog(
                `Error: could not write "${options.output}": ${err.message}`,
            );
            return 1;
        }
    }

    return 0;
}

/** True when this file is being executed directly (not imported). */
function isMainModule() {
    if (!process.argv[1]) return false;
    return import.meta.url === pathToFileURL(process.argv[1]).href;
}

if (isMainModule()) {
    runCli(process.argv.slice(2))
        .then((code) => {
            process.exitCode = code;
        })
        .catch((err) => {
            console.error(`Unexpected error: ${err?.message ?? err}`);
            process.exitCode = 1;
        });
}
