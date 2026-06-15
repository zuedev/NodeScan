#!/usr/bin/env node
/**
 * NodeJS-PortScanner — a fast, lightweight TCP port scanner with service fingerprinting.
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
    rate: 0,
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
    "-r": "--rate",
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
 *   concurrency: number, timeout: number, rate: number,
 *   output: string|null, help: boolean}}
 */
export function parseArgs(argv) {
    const options = {
        host: null,
        ports: DEFAULTS.ports,
        protocol: DEFAULTS.protocol,
        concurrency: DEFAULTS.concurrency,
        timeout: DEFAULTS.timeout,
        rate: DEFAULTS.rate,
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
            case "--rate":
                options.rate = toPositiveInt(nextValue(), flag);
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
 * Create a rate limiter that spaces acquisitions so no more than
 * `ratePerSecond` of them are released each second. A rate of `0` (or any
 * falsy value) disables limiting and resolves immediately.
 *
 * The returned function reserves its slot synchronously before awaiting, so it
 * stays correct when shared across the worker pool.
 *
 * @param {number} ratePerSecond
 * @returns {() => Promise<void>}
 */
export function createRateLimiter(ratePerSecond) {
    if (!ratePerSecond || ratePerSecond <= 0) {
        return () => Promise.resolve();
    }
    const interval = 1000 / ratePerSecond;
    let nextSlot = 0;
    return () => {
        const now = Date.now();
        const slot = Math.max(now, nextSlot);
        nextSlot = slot + interval;
        const delay = slot - now;
        return delay > 0
            ? new Promise((resolve) => setTimeout(resolve, delay))
            : Promise.resolve();
    };
}

/**
 * Scan many ports concurrently using a bounded worker pool so we never exceed
 * the configured number of simultaneous connections. An optional `rate` caps
 * how many new probes are started per second to reduce network noise.
 *
 * @param {string} host
 * @param {number[]} ports
 * @param {{protocol?: ("tcp"|"udp"), concurrency?: number, timeout?: number,
 *   rate?: number, grabBanner?: boolean,
 *   onResult?: (result: ScanResult) => void}} [options]
 * @returns {Promise<ScanResult[]>} results sorted ascending by port
 */
export async function scanPorts(host, ports, options = {}) {
    const {
        concurrency = DEFAULTS.concurrency,
        protocol = DEFAULTS.protocol,
        rate = DEFAULTS.rate,
        onResult,
    } = options;
    const scanOne = protocol === "udp" ? scanUdpPort : scanPort;
    const acquire = createRateLimiter(rate);
    const results = [];
    let next = 0;

    const worker = async () => {
        // `next++` runs synchronously before any await, so there is no race
        // between workers grabbing the same index.
        while (next < ports.length) {
            const port = ports[next++];
            await acquire();
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

/**
 * HTML-escape a value for safe interpolation into report markup.
 *
 * Banner and service text originate from the scanned host and are therefore
 * untrusted: a hostile target could embed `<script>` or other markup in its
 * banner. Escaping every dynamic value prevents that data from being treated
 * as HTML when the report is opened in a browser.
 *
 * @param {unknown} value
 * @returns {string}
 */
function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, (ch) => {
        switch (ch) {
            case "&":
                return "&amp;";
            case "<":
                return "&lt;";
            case ">":
                return "&gt;";
            case '"':
                return "&quot;";
            default:
                return "&#39;";
        }
    });
}

/** Map a port state to a CSS-class-safe slug (drops the `|` in open|filtered). */
function stateSlug(state) {
    if (state === "open") return "open";
    if (state === "open|filtered") return "filtered";
    return "closed";
}

/**
 * Render a scan as a standalone, self-contained HTML report.
 *
 * Reuses {@link buildJsonReport} for the underlying data so the HTML and JSON
 * reports always agree. Every dynamic value is passed through
 * {@link escapeHtml} because banners are attacker-controlled and must never be
 * rendered as markup.
 *
 * @param {{host: string, protocol?: ("tcp"|"udp"), ports: string,
 *   results: ScanResult[], elapsedMs: number}} params
 * @returns {string} a complete HTML document
 */
export function buildHtmlReport(params) {
    const report = buildJsonReport(params);
    const seconds = (report.durationMs / 1000).toFixed(1);

    const renderRows = (entries) =>
        entries
            .map(
                (e) => `          <tr>
            <td class="port">${e.port}/${escapeHtml(e.protocol)}</td>
            <td><span class="state state-${stateSlug(e.state)}">${escapeHtml(e.state)}</span></td>
            <td>${escapeHtml(e.service ?? "unknown")}</td>
            <td>${e.banner ? `<code>${escapeHtml(e.banner)}</code>` : '<span class="muted">—</span>'}</td>
          </tr>`,
            )
            .join("\n");

    const section = (title, entries) =>
        entries.length === 0
            ? ""
            : `      <h2>${escapeHtml(title)} <span class="count">${entries.length}</span></h2>
      <table>
        <thead>
          <tr><th>Port</th><th>State</th><th>Service</th><th>Banner</th></tr>
        </thead>
        <tbody>
${renderRows(entries)}
        </tbody>
      </table>`;

    const body =
        report.open.length === 0 && report.openFiltered.length === 0
            ? '      <p class="empty">No open ports found.</p>'
            : [
                  section("Open ports", report.open),
                  section("Open | filtered ports", report.openFiltered),
              ]
                  .filter(Boolean)
                  .join("\n");

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>NodeJS-PortScanner report — ${escapeHtml(report.host)}</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body {
    font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    margin: 0; padding: 2rem 1rem; line-height: 1.5;
    color: #1f2933; background: #eef1f5;
  }
  main { max-width: 60rem; margin: 0 auto; }
  header h1 { margin: 0 0 .25rem; font-size: 1.6rem; }
  .target { margin: 0; color: #52606d; }
  .target strong { color: #1f2933; }
  .meta { margin: 1.5rem 0; }
  .meta dl {
    display: grid; gap: 1px; margin: 0;
    grid-template-columns: repeat(auto-fit, minmax(8rem, 1fr));
    border: 1px solid #d2d9e0; border-radius: .5rem; overflow: hidden;
  }
  .meta dl > div { background: #fff; padding: .75rem 1rem; }
  .meta dt {
    font-size: .7rem; text-transform: uppercase; letter-spacing: .04em;
    color: #7b8794; margin-bottom: .15rem;
  }
  .meta dd { margin: 0; font-size: 1.1rem; font-weight: 600; }
  h2 { font-size: 1.15rem; margin: 1.75rem 0 .75rem; }
  h2 .count {
    display: inline-block; min-width: 1.5rem; padding: 0 .4rem;
    font-size: .8rem; text-align: center; border-radius: 1rem;
    background: #cbd2d9; color: #1f2933; vertical-align: middle;
  }
  table {
    width: 100%; border-collapse: collapse; background: #fff;
    border-radius: .5rem; overflow: hidden; box-shadow: 0 1px 2px rgba(0,0,0,.06);
  }
  th, td { text-align: left; padding: .6rem .85rem; border-bottom: 1px solid #e4e7eb; vertical-align: top; }
  th {
    font-size: .7rem; text-transform: uppercase; letter-spacing: .04em;
    color: #7b8794; background: #f5f7fa;
  }
  tr:last-child td { border-bottom: none; }
  .port { font-variant-numeric: tabular-nums; white-space: nowrap; font-weight: 600; }
  .state { display: inline-block; padding: .1rem .5rem; border-radius: 1rem; font-size: .8rem; font-weight: 600; }
  .state-open { background: #c1f2d0; color: #0b6b2f; }
  .state-filtered { background: #fce4b8; color: #8a5300; }
  .state-closed { background: #e4e7eb; color: #52606d; }
  code { font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; font-size: .85rem; word-break: break-all; }
  .muted { color: #9aa5b1; }
  .empty { padding: 2rem; text-align: center; color: #52606d; background: #fff; border-radius: .5rem; }
  footer { margin-top: 2rem; font-size: .8rem; color: #7b8794; }
  footer a { color: inherit; }
  @media (prefers-color-scheme: dark) {
    body { color: #e4e7eb; background: #1f2933; }
    .target { color: #9aa5b1; }
    .target strong { color: #f5f7fa; }
    .meta dl { border-color: #3e4c59; }
    .meta dl > div { background: #2a3744; }
    table { background: #2a3744; box-shadow: none; }
    th { background: #323f4b; color: #9aa5b1; }
    th, td { border-color: #3e4c59; }
    .empty { background: #2a3744; }
    h2 .count { background: #3e4c59; color: #e4e7eb; }
  }
</style>
</head>
<body>
  <main>
    <header>
      <h1>🔍 NodeJS-PortScanner report</h1>
      <p class="target"><strong>${escapeHtml(report.host)}</strong> · ${escapeHtml(report.protocol.toUpperCase())} · ports ${escapeHtml(report.ports)}</p>
    </header>
    <section class="meta">
      <dl>
        <div><dt>Scanned at</dt><dd>${escapeHtml(report.scannedAt)}</dd></div>
        <div><dt>Duration</dt><dd>${seconds}s</dd></div>
        <div><dt>Ports scanned</dt><dd>${report.totalScanned}</dd></div>
        <div><dt>Open</dt><dd>${report.openCount}</dd></div>
        <div><dt>Open | filtered</dt><dd>${report.openFilteredCount}</dd></div>
      </dl>
    </section>
    <section>
${body}
    </section>
    <footer>
      <p>Generated by <a href="https://github.com/zuedev/nodejs-portscanner">NodeJS-PortScanner</a>. Only scan systems you own or have explicit written permission to test.</p>
    </footer>
  </main>
</body>
</html>
`;
}

/**
 * Choose a report format from an output filename's extension. Files ending in
 * `.html` or `.htm` produce an HTML report; everything else is JSON.
 *
 * @param {string} outputPath
 * @returns {("html"|"json")}
 */
export function reportFormatFor(outputPath) {
    return /\.html?$/i.test(outputPath) ? "html" : "json";
}

/** The CLI help / usage text. */
export function helpText() {
    return `NodeJS-PortScanner — a fast, lightweight TCP port scanner.

Usage:
  node scanner.js --host <target> [options]

Options:
  -h, --host <host>          Target hostname or IP address (required)
  -p, --ports <spec>         Port range or list, e.g. 1-1024 or 80,443,8080
                             (default: ${DEFAULTS.ports})
  -P, --protocol <tcp|udp>   Transport protocol to scan (default: ${DEFAULTS.protocol})
  -c, --concurrency <n>      Max simultaneous connections (default: ${DEFAULTS.concurrency})
  -t, --timeout <ms>         Connection timeout in milliseconds (default: ${DEFAULTS.timeout})
  -r, --rate <n>             Max new probes started per second (default: unlimited)
  -o, --output <file>        Export results to a file; a .html (or .htm)
                             extension writes an HTML report, otherwise JSON
      --help                 Show this help menu

Examples:
  node scanner.js --host 192.168.1.1 --ports 1-1024
  node scanner.js --host example.com --ports 22,80,443,8080
  node scanner.js --host 10.0.0.5 --ports 1-65535 -c 200 -t 1500
  node scanner.js --host 192.168.1.1 --ports 1-1024 --output results.json
  node scanner.js --host 192.168.1.1 --ports 1-1024 --output report.html
  node scanner.js --host 192.168.1.1 --protocol udp --ports 53,123,161
  node scanner.js --host 192.168.1.1 --ports 1-1024 --rate 50

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
        rate: options.rate,
    });
    const elapsedMs = Date.now() - started;

    if (results.some((r) => stateOf(r) !== "closed")) {
        log(formatTable(results));
        log("");
    }
    log(formatSummary(results, elapsedMs));

    if (options.output) {
        const params = {
            host: options.host,
            protocol: options.protocol,
            ports: options.ports,
            results,
            elapsedMs,
        };
        const contents =
            reportFormatFor(options.output) === "html"
                ? buildHtmlReport(params)
                : `${JSON.stringify(buildJsonReport(params), null, 2)}\n`;
        try {
            await writeFile(options.output, contents, "utf8");
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
