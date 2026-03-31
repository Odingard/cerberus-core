# Contributing to Cerberus

Thank you for your interest in contributing to Cerberus. This document provides guidelines for contributing to the project.

## Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/Odingard/cerberus.git
   cd cerberus
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Run the test suite**
   ```bash
   npm test
   ```

4. **Run type checking and linting**
   ```bash
   npm run typecheck
   npm run lint
   ```

## Branch Strategy

- `main` — protected, always deployable
- `develop` — integration branch, all features merge here first
- `feature/*` — one branch per feature or sub-process
- `research/*` — isolated research branches

## Making Changes

1. Create a branch from `develop`:
   ```bash
   git checkout -b feature/your-feature develop
   ```

2. Write your code following the project standards:
   - TypeScript strict mode — no `any` types
   - All function parameters and return types explicitly typed
   - External data validated with Zod schemas at system boundaries

3. Write tests for your changes:
   - Every module requires a corresponding test file
   - Minimum 80% code coverage
   - Deterministic inputs — no random data in tests

4. Commit using the project convention:
   ```
   feat(layer): description     — new feature
   fix(engine): description     — bug fix
   research(l4): description    — research findings
   docs(api): description       — documentation
   test(correlation): description — test coverage
   ```

5. Push and open a PR against `develop`.

## Code Quality

- `strict: true` in TypeScript — non-negotiable
- All exports have JSDoc comments
- Security-critical paths have inline comments explaining why
- No type assertions (`as Type`) except in tests with justification

## Pull Request Process

1. Ensure CI passes (type check + lint + test)
2. Update documentation if your change affects the API
3. Request review from a maintainer
4. PRs require at least one approval before merge

## Reporting Issues

- Use the bug report template for bugs
- Use the feature request template for enhancements
- For security vulnerabilities, see [SECURITY.md](SECURITY.md)
