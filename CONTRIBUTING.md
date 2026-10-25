# Contribution Guidelines

Thank you for your interest in contributing to MirageMesh. We welcome bug reports, documentation enhancements, test cases, and feature contributions from the community.

---

## 1. Getting Started

Before contributing, please read:
- [OPEN_SOURCE.md](OPEN_SOURCE.md): Our open-source contract and licensing guarantees.
- [AGENTS.md](AGENTS.md): Architecture principles and workflow contracts.
- [docs/architecture/ADR-0003-open-source-local-first.md](docs/architecture/ADR-0003-open-source-local-first.md): Core local-first principles.

### Development Environment Setup
1. Clone your fork and enter the directory:
   ```sh
   git clone https://github.com/<your-username>/Miragemesh.git
   cd Miragemesh
   ```
2. Run the bootstrap setup:
   ```sh
   npm run setup
   ```
3. Run the doctor tool to verify your environment:
   ```sh
   npm run doctor
   ```

---

## 2. Roadmap Tasks & Development Lifecycle

MirageMesh follows a deterministic, dependency-ordered roadmap. Work units correspond to roadmap commit cards:

1. Check current roadmap status:
   ```sh
   npm run plan -- status
   npm run plan -- next
   ```
2. Read the designated task card in `plans/commits/Cxx.md` in full before making any code changes.
3. Adhere strictly to the targets, actions, resources, fixtures, acceptance criteria, and negative cases declared in the task card.
4. Implement one real, dependency-ready work unit per commit or pull request.

---

## 3. Protected Files & Architectural Invariants

> [!CAUTION]
> **Permanent Maintainer Restrictions:**
> Contributors must **never** modify:
> - Database schemas or SQL migrations
> - `.env` files or environment variable templates
> - `Dockerfile` or container build configurations
>
> All features must use compatible local filesystem adapters and rootless Podman execution per ADR-0003.

### Clean Boundary Separation
- **Domain Logic**: Belongs in the Go engine (`engine/`).
- **User Interface**: Belongs in `apps/web/` using React and standard vanilla CSS tokens.
- **Adapters**: Reside at boundary layers (`internal/storage/`, `internal/podman/`).
- **No Sibling Imports**: Do not add imports or dependencies outside this repository checkout.

---

## 4. Quality Gates & Verification

Every contribution must be accompanied by automated verification:

### Required Checks
Run the primary check command before opening a Pull Request:
```sh
npm run check
```
This runs:
1. `npm run validate:plan`: Ensures roadmap metadata and dependency integrity validate.
2. `npm run build`: Compiles web assets and the Go engine binary.
3. `npm test`: Executes the Node test runner across web, contracts, and engineering suites.

### Additional Verification Suites
- **Contract Tests**: `npm run test:contracts`
- **Browser Accessibility & UI**: `npm run test:browser` (requires Playwright Chromium)
- **Clean Clone Smoke Test**: `npm run test:clone`

### Testing Invariants
- **No Mock-Only Verification**: Do not replace real storage, cryptographic validation, or provider interfaces with superficial mocks.
- **Never Disable Checks**: Fixing a test by commenting it out, deleting it, or adding broad analysis ignores is strictly prohibited.
- **Meaningful Negatives**: Always implement and verify negative failure cases (e.g. malformed inputs, interrupted connections, empty states, 503 provider outages).

---

## 5. Developer Certificate of Origin (DCO)

All commits must include a `Signed-off-by` trailer certifying agreement with the [Developer Certificate of Origin (DCO)](DCO.md):
```sh
git commit -s -m "docs(oss): complete installation usage contribution and support guides"
```

Use [Conventional Commits](https://www.conventionalcommits.org/) syntax for commit messages:
- `feat(...)`: New features
- `fix(...)`: Bug fixes
- `docs(...)`: Documentation changes
- `test(...)`: Adding or modifying tests
- `refactor(...)`: Code refactoring without behavior change

---

## 6. Reporting Issues & Security

- **Bug Reports & Feedback**: Please open an issue on GitHub detailing the steps to reproduce, observed behavior, and system environment.
- **Security Vulnerabilities**: Do **not** open public GitHub issues for security issues. Follow our private disclosure process in [SECURITY.md](SECURITY.md).
