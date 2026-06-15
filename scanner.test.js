import test from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import dgram from "node:dgram";
import { readFile, unlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
    parsePorts,
    parseArgs,
    fingerprint,
    scanPort,
    scanUdpPort,
    scanPorts,
    formatTable,
    formatSummary,
    buildJsonReport,
    helpText,
    runCli,
    DEFAULTS,
    WELL_KNOWN_PORTS,
} from "./scanner.js";

const HOST = "127.0.0.1";

// ---------------------------------------------------------------------------
// Mock-server helpers
// ---------------------------------------------------------------------------

/**
 * Start a local TCP server on an ephemeral port.
 * @param {(socket: net.Socket) => void} [onConnection]
 * @returns {Promise<{server: net.Server, port: number}>}
 */
function startServer(onConnection = () => {}) {
    return new Promise((resolve) => {
        const server = net.createServer((socket) => {
            // Swallow resets caused by the scanner destroying the connection.
            socket.on("error", () => {});
            onConnection(socket);
        });
        server.listen(0, HOST, () => {
            resolve({ server, port: server.address().port });
        });
    });
}

/** Close a server and wait for it to fully release the port. */
function closeServer(server) {
    return new Promise((resolve) => server.close(() => resolve()));
}

/** Obtain a port that is guaranteed to be closed (nothing listening). */
async function getClosedPort() {
    const { server, port } = await startServer();
    await closeServer(server);
    return port;
}

/**
 * Start a local UDP server on an ephemeral port.
 * @param {(server: dgram.Socket, msg: Buffer, rinfo: object) => void} [onMessage]
 * @returns {Promise<{server: dgram.Socket, port: number}>}
 */
function startUdpServer(onMessage = () => {}) {
    return new Promise((resolve) => {
        const server = dgram.createSocket("udp4");
        server.on("error", () => {});
        server.on("message", (msg, rinfo) => onMessage(server, msg, rinfo));
        server.bind(0, HOST, () => {
            resolve({ server, port: server.address().port });
        });
    });
}

/** Close a UDP server and wait for it to fully release the port. */
function closeUdpServer(server) {
    return new Promise((resolve) => server.close(() => resolve()));
}

/** Obtain a UDP port that is guaranteed to be closed (nothing listening). */
async function getClosedUdpPort() {
    const { server, port } = await startUdpServer();
    await closeUdpServer(server);
    return port;
}

// ---------------------------------------------------------------------------
// parsePorts
// ---------------------------------------------------------------------------

test("parsePorts expands an inclusive range", () => {
    assert.deepEqual(parsePorts("1-5"), [1, 2, 3, 4, 5]);
});

test("parsePorts handles comma-separated lists", () => {
    assert.deepEqual(parsePorts("80,443,8080"), [80, 443, 8080]);
});

test("parsePorts mixes ranges and lists", () => {
    assert.deepEqual(parsePorts("22,80,1000-1002"), [22, 80, 1000, 1001, 1002]);
});

test("parsePorts sorts and de-duplicates", () => {
    assert.deepEqual(parsePorts("5,1-3,2,3"), [1, 2, 3, 5]);
});

test("parsePorts tolerates surrounding whitespace", () => {
    assert.deepEqual(parsePorts(" 22 , 80 "), [22, 80]);
});

test("parsePorts accepts the full valid boundary", () => {
    assert.deepEqual(parsePorts("1"), [1]);
    assert.deepEqual(parsePorts("65535"), [65535]);
});

test("parsePorts rejects out-of-range and invalid input", () => {
    assert.throws(() => parsePorts("0"), /Invalid port/);
    assert.throws(() => parsePorts("65536"), /Invalid port/);
    assert.throws(() => parsePorts("abc"), /Invalid port/);
    assert.throws(() => parsePorts("80.5"), /Invalid port/);
    assert.throws(() => parsePorts(""), /non-empty/);
    assert.throws(() => parsePorts("5-1"), /start > end/);
    assert.throws(() => parsePorts("1-2-3"), /Invalid port range/);
});

// ---------------------------------------------------------------------------
// parseArgs
// ---------------------------------------------------------------------------

test("parseArgs returns defaults when only host is given", () => {
    const opts = parseArgs(["--host", "example.com"]);
    assert.equal(opts.host, "example.com");
    assert.equal(opts.ports, DEFAULTS.ports);
    assert.equal(opts.concurrency, DEFAULTS.concurrency);
    assert.equal(opts.timeout, DEFAULTS.timeout);
    assert.equal(opts.output, null);
    assert.equal(opts.help, false);
});

test("parseArgs supports short aliases", () => {
    const opts = parseArgs([
        "-h",
        "10.0.0.1",
        "-p",
        "1-10",
        "-c",
        "50",
        "-t",
        "500",
        "-o",
        "out.json",
    ]);
    assert.equal(opts.host, "10.0.0.1");
    assert.equal(opts.ports, "1-10");
    assert.equal(opts.concurrency, 50);
    assert.equal(opts.timeout, 500);
    assert.equal(opts.output, "out.json");
});

test("parseArgs supports --flag=value syntax", () => {
    const opts = parseArgs(["--host=localhost", "--ports=22,80"]);
    assert.equal(opts.host, "localhost");
    assert.equal(opts.ports, "22,80");
});

test("parseArgs recognises --help", () => {
    assert.equal(parseArgs(["--help"]).help, true);
});

test("parseArgs throws on unknown options", () => {
    assert.throws(() => parseArgs(["--bogus"]), /Unknown option/);
});

test("parseArgs throws when a value is missing", () => {
    assert.throws(() => parseArgs(["--host"]), /requires a value/);
});

test("parseArgs validates numeric options", () => {
    assert.throws(
        () => parseArgs(["--concurrency", "lots"]),
        /positive integer/,
    );
    assert.throws(() => parseArgs(["--timeout", "0"]), /positive integer/);
});

test("parseArgs defaults protocol to tcp", () => {
    assert.equal(parseArgs(["--host", "example.com"]).protocol, "tcp");
    assert.equal(
        parseArgs(["--host", "example.com"]).protocol,
        DEFAULTS.protocol,
    );
});

test("parseArgs parses the protocol option and its alias", () => {
    assert.equal(parseArgs(["--protocol", "udp"]).protocol, "udp");
    assert.equal(parseArgs(["-P", "udp"]).protocol, "udp");
    assert.equal(parseArgs(["--protocol=UDP"]).protocol, "udp");
    assert.equal(parseArgs(["--protocol", "TCP"]).protocol, "tcp");
});

test("parseArgs rejects an unknown protocol", () => {
    assert.throws(() => parseArgs(["--protocol", "icmp"]), /tcp.*udp/);
});

// ---------------------------------------------------------------------------
// fingerprint
// ---------------------------------------------------------------------------

test("fingerprint identifies OpenSSH from its banner", () => {
    assert.equal(
        fingerprint(22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"),
        "SSH (OpenSSH 8.9)",
    );
});

test("fingerprint identifies nginx from an HTTP banner", () => {
    const banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n";
    assert.equal(fingerprint(80, banner), "HTTP (nginx 1.18.0)");
});

test("fingerprint identifies Apache from an HTTP banner", () => {
    const banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n\r\n";
    assert.equal(fingerprint(80, banner), "HTTP (Apache 2.4.41)");
});

test("fingerprint falls back to the well-known port name", () => {
    assert.equal(fingerprint(443, ""), "HTTPS");
    assert.equal(fingerprint(3306, ""), "MySQL");
    assert.equal(WELL_KNOWN_PORTS[22], "SSH");
});

test('fingerprint returns "unknown" for unrecognised ports without a banner', () => {
    assert.equal(fingerprint(54321, ""), "unknown");
});

// ---------------------------------------------------------------------------
// scanPort
// ---------------------------------------------------------------------------

test("scanPort detects an open port and grabs its banner", async () => {
    const { server, port } = await startServer((socket) => {
        socket.write("SSH-2.0-OpenSSH_8.9p1\r\n");
    });
    try {
        const result = await scanPort(HOST, port, { timeout: 1000 });
        assert.equal(result.open, true);
        assert.equal(result.port, port);
        assert.match(result.banner, /OpenSSH_8\.9/);
        assert.equal(result.service, "SSH (OpenSSH 8.9)");
    } finally {
        await closeServer(server);
    }
});

test("scanPort detects an open port that sends no banner", async () => {
    const { server, port } = await startServer(() => {
        // Accept the connection but stay silent.
    });
    try {
        const result = await scanPort(HOST, port, {
            timeout: 1000,
            bannerTimeout: 100,
        });
        assert.equal(result.open, true);
        assert.equal(result.banner, "");
        // Ephemeral port has no well-known mapping.
        assert.equal(result.service, "unknown");
    } finally {
        await closeServer(server);
    }
});

test("scanPort reports a closed port", async () => {
    const port = await getClosedPort();
    const result = await scanPort(HOST, port, { timeout: 500 });
    assert.equal(result.open, false);
    assert.equal(result.service, null);
});

test("scanPort can skip banner grabbing", async () => {
    const { server, port } = await startServer((socket) => {
        socket.write("SSH-2.0-OpenSSH_8.9p1\r\n");
    });
    try {
        const result = await scanPort(HOST, port, {
            timeout: 1000,
            grabBanner: false,
        });
        assert.equal(result.open, true);
        assert.equal(result.banner, "");
    } finally {
        await closeServer(server);
    }
});

// ---------------------------------------------------------------------------
// scanUdpPort
// ---------------------------------------------------------------------------

test("scanUdpPort reports an open port when the server replies", async () => {
    const { server, port } = await startUdpServer((srv, msg, rinfo) => {
        srv.send("PONG", rinfo.port, rinfo.address);
    });
    try {
        const result = await scanUdpPort(HOST, port, { timeout: 1000 });
        assert.equal(result.open, true);
        assert.equal(result.state, "open");
        assert.equal(result.protocol, "udp");
        assert.equal(result.port, port);
        assert.match(result.banner, /PONG/);
    } finally {
        await closeUdpServer(server);
    }
});

test("scanUdpPort reports open|filtered when there is no reply", async () => {
    const { server, port } = await startUdpServer(() => {
        // Accept the datagram but never answer.
    });
    try {
        const result = await scanUdpPort(HOST, port, { timeout: 200 });
        assert.equal(result.open, false);
        assert.equal(result.state, "open|filtered");
        assert.equal(result.protocol, "udp");
    } finally {
        await closeUdpServer(server);
    }
});

test("scanUdpPort never reports a closed port as open", async () => {
    const port = await getClosedUdpPort();
    const result = await scanUdpPort(HOST, port, { timeout: 400 });
    // ICMP delivery for unconnected UDP is platform-dependent, so the state is
    // either a definitive "closed" or the ambiguous "open|filtered" — never a
    // false "open".
    assert.equal(result.open, false);
    assert.ok(["closed", "open|filtered"].includes(result.state));
    if (result.state === "closed") {
        assert.equal(result.service, null);
    }
});

// ---------------------------------------------------------------------------
// scanPorts
// ---------------------------------------------------------------------------

test("scanPorts finds the open port among closed ones and returns sorted results", async () => {
    const { server, port: openPort } = await startServer((socket) => {
        socket.write("hello\r\n");
    });
    const closedPort = await getClosedPort();
    try {
        const ports = [closedPort, openPort];
        const results = await scanPorts(HOST, ports, {
            concurrency: 5,
            timeout: 500,
        });

        assert.equal(results.length, 2);
        // Sorted ascending by port.
        assert.ok(results[0].port < results[1].port);

        const open = results.filter((r) => r.open);
        assert.equal(open.length, 1);
        assert.equal(open[0].port, openPort);
    } finally {
        await closeServer(server);
    }
});

test("scanPorts respects the concurrency limit", async () => {
    let active = 0;
    let maxActive = 0;
    const { server, port } = await startServer(() => {
        active++;
        maxActive = Math.max(maxActive, active);
        setTimeout(() => {
            active--;
        }, 30);
    });
    try {
        // Scan the same open port many times to exercise the worker pool.
        const ports = Array.from({ length: 20 }, () => port);
        await scanPorts(HOST, ports, {
            concurrency: 4,
            timeout: 500,
            bannerTimeout: 50,
        });
        assert.ok(
            maxActive <= 4,
            `expected <= 4 concurrent connections, saw ${maxActive}`,
        );
    } finally {
        await closeServer(server);
    }
});

test("scanPorts dispatches to UDP when protocol is udp", async () => {
    const { server, port: openPort } = await startUdpServer(
        (srv, msg, rinfo) => {
            srv.send("REPLY", rinfo.port, rinfo.address);
        },
    );
    const silent = await startUdpServer();
    try {
        const results = await scanPorts(HOST, [openPort, silent.port], {
            protocol: "udp",
            concurrency: 2,
            timeout: 300,
        });
        assert.equal(results.length, 2);
        assert.ok(results.every((r) => r.protocol === "udp"));
        const open = results.find((r) => r.state === "open");
        assert.equal(open.port, openPort);
    } finally {
        await closeUdpServer(server);
        await closeUdpServer(silent.server);
    }
});

// ---------------------------------------------------------------------------
// Formatting & reporting
// ---------------------------------------------------------------------------

const SAMPLE_RESULTS = [
    {
        port: 22,
        open: true,
        banner: "SSH-2.0-OpenSSH_8.9",
        service: "SSH (OpenSSH 8.9)",
    },
    { port: 80, open: true, banner: "", service: "HTTP (nginx 1.18.0)" },
    { port: 81, open: false, banner: "", service: null },
];

test("formatTable renders a header and only open ports", () => {
    const table = formatTable(SAMPLE_RESULTS);
    const lines = table.split("\n");
    assert.match(lines[0], /^PORT\s+STATE\s+SERVICE$/);
    assert.equal(lines.length, 3); // header + 2 open rows
    assert.match(table, /22\/tcp\s+open\s+SSH \(OpenSSH 8\.9\)/);
    assert.match(table, /80\/tcp\s+open\s+HTTP \(nginx 1\.18\.0\)/);
    assert.doesNotMatch(table, /81\/tcp/);
});

test("formatSummary pluralises and formats the duration", () => {
    assert.equal(
        formatSummary(SAMPLE_RESULTS, 3200),
        "Scan complete: 2 open ports found in 3.2s",
    );
    assert.equal(
        formatSummary([{ port: 22, open: true, service: "SSH" }], 1000),
        "Scan complete: 1 open port found in 1.0s",
    );
    assert.equal(
        formatSummary([], 500),
        "Scan complete: 0 open ports found in 0.5s",
    );
});

test("buildJsonReport produces a structured, serialisable report", () => {
    const report = buildJsonReport({
        host: "192.168.1.1",
        ports: "1-1024",
        results: SAMPLE_RESULTS,
        elapsedMs: 3200,
    });

    assert.equal(report.host, "192.168.1.1");
    assert.equal(report.ports, "1-1024");
    assert.equal(report.durationMs, 3200);
    assert.equal(report.totalScanned, 3);
    assert.equal(report.openCount, 2);
    assert.equal(report.open.length, 2);
    assert.deepEqual(report.open[0], {
        port: 22,
        protocol: "tcp",
        state: "open",
        service: "SSH (OpenSSH 8.9)",
        banner: "SSH-2.0-OpenSSH_8.9",
    });
    // Must round-trip through JSON without throwing.
    assert.doesNotThrow(() => JSON.stringify(report));
});

const SAMPLE_UDP_RESULTS = [
    {
        port: 53,
        protocol: "udp",
        open: true,
        state: "open",
        banner: "",
        service: "DNS",
    },
    {
        port: 123,
        protocol: "udp",
        open: false,
        state: "open|filtered",
        banner: "",
        service: "NTP",
    },
    {
        port: 7,
        protocol: "udp",
        open: false,
        state: "closed",
        banner: "",
        service: null,
    },
];

test("formatTable shows udp protocol and open|filtered, hides closed", () => {
    const table = formatTable(SAMPLE_UDP_RESULTS);
    assert.match(table, /53\/udp\s+open\s+DNS/);
    assert.match(table, /123\/udp\s+open\|filtered\s+NTP/);
    assert.doesNotMatch(table, /7\/udp/);
});

test("formatSummary counts open|filtered ports separately", () => {
    assert.equal(
        formatSummary(SAMPLE_UDP_RESULTS, 1500),
        "Scan complete: 1 open port found in 1.5s, 1 open|filtered port",
    );
});

test("buildJsonReport captures udp protocol and open|filtered ports", () => {
    const report = buildJsonReport({
        host: "10.0.0.5",
        protocol: "udp",
        ports: "7,53,123",
        results: SAMPLE_UDP_RESULTS,
        elapsedMs: 1500,
    });
    assert.equal(report.protocol, "udp");
    assert.equal(report.openCount, 1);
    assert.equal(report.open[0].port, 53);
    assert.equal(report.open[0].protocol, "udp");
    assert.equal(report.openFilteredCount, 1);
    assert.equal(report.openFiltered[0].port, 123);
    assert.equal(report.openFiltered[0].state, "open|filtered");
    assert.doesNotThrow(() => JSON.stringify(report));
});

test("helpText documents every option", () => {
    const text = helpText();
    for (const flag of [
        "--host",
        "--ports",
        "--protocol",
        "--concurrency",
        "--timeout",
        "--output",
        "--help",
    ]) {
        assert.ok(text.includes(flag), `help should mention ${flag}`);
    }
});

// ---------------------------------------------------------------------------
// runCli (integration)
// ---------------------------------------------------------------------------

/** Capture log/error output from runCli. */
function makeIo() {
    const out = [];
    const err = [];
    return {
        io: {
            log: (m) => out.push(String(m)),
            error: (m) => err.push(String(m)),
        },
        out,
        err,
    };
}

test("runCli prints help and exits 0", async () => {
    const { io, out } = makeIo();
    const code = await runCli(["--help"], io);
    assert.equal(code, 0);
    assert.match(out.join("\n"), /Usage:/);
});

test("runCli fails when --host is missing", async () => {
    const { io, err } = makeIo();
    const code = await runCli(["--ports", "1-10"], io);
    assert.equal(code, 1);
    assert.match(err.join("\n"), /--host is required/);
});

test("runCli reports invalid port specs", async () => {
    const { io, err } = makeIo();
    const code = await runCli(["--host", HOST, "--ports", "nope"], io);
    assert.equal(code, 1);
    assert.match(err.join("\n"), /Invalid port/);
});

test("runCli scans a mock server and reports the open port", async () => {
    const { server, port } = await startServer((socket) => {
        socket.write("SSH-2.0-OpenSSH_8.9p1\r\n");
    });
    const { io, out } = makeIo();
    try {
        const code = await runCli(
            ["--host", HOST, "--ports", String(port), "--timeout", "800"],
            io,
        );
        const text = out.join("\n");
        assert.equal(code, 0);
        assert.match(
            text,
            new RegExp(`${port}/tcp\\s+open\\s+SSH \\(OpenSSH 8\\.9\\)`),
        );
        assert.match(text, /Scan complete: 1 open port found/);
    } finally {
        await closeServer(server);
    }
});

test("runCli scans a mock server over UDP", async () => {
    const { server, port } = await startUdpServer((srv, msg, rinfo) => {
        srv.send("PONG", rinfo.port, rinfo.address);
    });
    const { io, out } = makeIo();
    try {
        const code = await runCli(
            [
                "--host",
                HOST,
                "--protocol",
                "udp",
                "--ports",
                String(port),
                "--timeout",
                "500",
            ],
            io,
        );
        const text = out.join("\n");
        assert.equal(code, 0);
        assert.match(text, /UDP ports/);
        assert.match(text, new RegExp(`${port}/udp\\s+open`));
        assert.match(text, /Scan complete: 1 open port found/);
    } finally {
        await closeUdpServer(server);
    }
});

test("runCli writes a JSON report when --output is given", async () => {
    const { server, port } = await startServer((socket) => {
        socket.write("SSH-2.0-OpenSSH_8.9p1\r\n");
    });
    const outFile = join(
        tmpdir(),
        `nodescan-test-${process.pid}-${Date.now()}.json`,
    );
    const { io } = makeIo();
    try {
        const code = await runCli(
            [
                "--host",
                HOST,
                "--ports",
                String(port),
                "--timeout",
                "800",
                "--output",
                outFile,
            ],
            io,
        );
        assert.equal(code, 0);

        const report = JSON.parse(await readFile(outFile, "utf8"));
        assert.equal(report.host, HOST);
        assert.equal(report.openCount, 1);
        assert.equal(report.open[0].port, port);
        assert.equal(report.open[0].service, "SSH (OpenSSH 8.9)");
    } finally {
        await closeServer(server);
        await unlink(outFile).catch(() => {});
    }
});
