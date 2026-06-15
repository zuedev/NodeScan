# Contributing to NodeScan

Thanks for your interest in improving NodeScan! This project is a small, dependency-free TCP port scanner, and contributions of all sizes are welcome.

This guide describes a simple issue-and-pull-request workflow. Please read it before opening a pull request.

## Code of conduct

Be respectful and constructive. Assume good intent, keep discussion focused on the work, and help keep this a welcoming project for newcomers.

## Responsible use

NodeScan is a security tool. Only ever test it against systems you own or have explicit written permission to scan. Do not open issues or pull requests that include scan data from third-party systems, and never use the project to facilitate unauthorized scanning. See the legal disclaimer in the [README](README.md) for details.

## Ways to contribute

- Report a bug or unexpected behavior
- Suggest a feature (see the Roadmap in the [README](README.md))
- Improve documentation
- Submit code via a pull request

## Reporting issues

**Open an issue before starting significant work.** This lets us discuss the approach before you invest time, and avoids duplicated effort.

When filing an issue, please include:

- What you expected to happen and what actually happened
- Steps to reproduce (the exact `node scanner.js` command and flags help)
- Your Node.js version (`node --version`) and operating system
- Relevant output or error messages

## Development setup

Requirements: Node.js **>= 25**.

```bash
git clone https://github.com/zuedev/nodescan.git
cd nodescan
npm install
```

Run the scanner locally:

```bash
node scanner.js --host 127.0.0.1 --ports 1-1024
```

Run the test suite (uses Node's built-in test runner against a local mock server — no external network access):

```bash
npm test
```

## Pull request workflow

1. **Open or comment on an issue** describing the change.
2. **Fork** the repository and create a topic branch from `main`:
   ```bash
   git checkout -b fix/short-description
   ```
3. **Make your change.** Keep pull requests focused on a single concern.
4. **Add or update tests** in `scanner.test.js` to cover your change.
5. **Run the suite** and make sure everything passes:
   ```bash
   npm test
   ```
6. **Commit** with a clear message and **push** your branch.
7. **Open a pull request** against `main`. Reference the related issue (e.g. `Closes #12`) and describe what changed and why.

## Review and merge policy

> **All pull requests require a review and approval from [@zuedev](https://github.com/zuedev) before they can be merged.**

- Every PR must be reviewed and explicitly approved by @zuedev prior to merge — no PR is merged without it.
- All checks (including `npm test`) must pass.
- Please respond to review feedback by pushing additional commits to the same branch.
- A maintainer will merge once the PR is approved; please do not merge your own pull requests.

## Coding guidelines

- The project uses **ES modules** (`import`/`export`) and targets Node.js >= 25.
- Keep NodeScan **dependency-free** — prefer Node's built-in modules (`net`, `fs`, etc.). Open an issue first if you believe a dependency is genuinely needed.
- Match the existing style: clear names, small focused functions, and exported logic that can be unit-tested without real network calls.
- Add tests for new behavior and keep the suite green.

By contributing, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).
