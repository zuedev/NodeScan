# syntax=docker/dockerfile:1

# NodeJS-PortScanner — a fast, dependency-free TCP port scanner, packaged for `docker run`.
#
# Build:
#   docker build -t nodejs-portscanner .
#
# Run (any flags after the image name are passed straight to the scanner):
#   docker run --rm nodejs-portscanner --host example.com --ports 1-1024
#   docker run --rm nodejs-portscanner --help
#
# Scanning the host's own interfaces/localhost needs the host network — without
# it the scan runs from the container's isolated network namespace:
#   docker run --rm --network host nodejs-portscanner --host 127.0.0.1 --ports 1-1024
#
# Saving a JSON report to the host (mount a writable directory and write there):
#   docker run --rm -v "${PWD}:/data" nodejs-portscanner -h example.com -p 1-1024 -o /data/results.json
#   # On Linux, add --user "$(id -u):$(id -g)" so the file is owned by you.

# Pinned to the major version required by package.json (engines: node >= 25).
# Alpine keeps the image small; NodeJS-PortScanner relies only on Node's built-in `net`
# module, so there are no native add-ons that would need glibc.
FROM node:25-alpine

# Application code lives in /app.
WORKDIR /app

# NodeJS-PortScanner has zero runtime dependencies, so there is nothing to install.
# package.json is still required at runtime because its "type": "module" field
# is what makes Node load scanner.js as an ES module.
COPY package.json ./
COPY scanner.js ./

# Never run as root: use the unprivileged `node` user that ships with the image.
# The application files stay owned by root (read-only to this user), which keeps
# the running code immutable.
USER node

# Pass-through entrypoint: arguments given to `docker run <image> ...` become the
# scanner's CLI flags. With no arguments, print the help screen.
ENTRYPOINT ["node", "scanner.js"]
CMD ["--help"]
