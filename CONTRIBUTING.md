# Contributing to VC Knots

First off, thank you for considering contributing to VC Knots! We truly appreciate your interest and effort.

This document outlines our guidelines for contributions. Please take a moment to review it to ensure a smooth and effective collaboration.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Enhancements](#suggesting-enhancements)
  - [Pull Requests](#pull-requests)
- [Development Setup](#development-setup)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [License](#license)

## Code of Conduct

We are committed to fostering an open and welcoming environment. All contributors are expected to read and adhere to our [Code of Conduct](./CODE_OF_CONDUCT.md). Please report any unacceptable behavior.

## How Can I Contribute?

There are many ways to contribute, from writing code and documentation to reporting bugs and suggesting new features.

### Reporting Bugs

If you find a bug, please ensure it hasn't already been reported by searching our [GitHub Issues]([https://github.com/trustknots/vcknots/issues]).

If you can't find an existing issue, please open a new one. Be sure to include:
- A clear and descriptive title.
- Steps to reproduce the bug.
- The expected behavior.
- The actual behavior (and screenshots, if applicable).
- Your environment details (OS, vcknots version, etc.).

### Suggesting Enhancements

We welcome suggestions for new features or improvements. Please open an issue in [GitHub Issues]([https://github.com/trustknots/vcknots/issues]) to discuss your idea.
- Explain the "why": What problem does this solve? What is the use case?
- Be as specific as possible in your description.

### Pull Requests

Code contributions are highly welcome! If you plan to make a significant change, please open an issue to discuss it first. This helps prevent duplicated or unnecessary work.

For small changes or bug fixes, you can submit a Pull Request (PR) directly.

## Development Setup

Ready to contribute code? Here’s how to set up VC Knots for local development.

### Repository Setup

1. **Fork** the repository.
2. **Clone** your fork locally:
  ```bash
  git clone https://github.com/your-username/your-repo-name.git
  cd your-repo-name
  ```

3. (Optional but Recommended) Add the original repository as an `upstream` remote:
  ```bash
  git remote add upstream https://github.com/trustknots/vcknots.git
  ```

### Wallet Setup

TODO

### Issuer and Verifier Setup

1. **Install dependencies**.
  ```bash
  # Make sure you use pnpm instead of npm
  pnpm install
  ```

2. **Run tests** to ensure everything is working correctly.
  ```bash
  pnpm test
  ```

## Pull Request Process

1. **Create a new branch** from the `main` (or `master`) branch.
  (Make sure to pull the latest changes from `upstream` first: `git pull upstream main`)
  ```bash
  # Example for a new feature
  git switch -c feat/your-new-feature

  # Example for a bug fix
  git switch -c fix/describe-the-fix
  ```

2. **Make your changes** and add your code.
  - Add or update tests for your changes.
  - Ensure all tests pass.

3. **Commit** your changes. Please write clear and descriptive commit messages by following [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
  ```bash
  git add .
  git commit -m "feat(wallet): Add amazing new feature"
  ```

4. **Push** your branch to your fork:
    ```bash
    git push origin feat/your-new-feature
    ```

5.  **Open a Pull Request** (PR) from your fork to the original repository's `main` branch.
    - Link any relevant issues (e.g., "Closes #123").
    - Provide a clear description of your changes.

6.  **Wait for review.** A maintainer will review your PR. We may request changes. Once approved, your PR will be merged. Thank you for your contribution!

## Coding Standards

To maintain code consistency, we use [Biome](https://biomejs.dev/). Please run the linter/formatter before submitting your PR.

```bash
pnpm run lint
pnpm run format
```

## License

By contributing to VC Knots, you agree that your contributions will be licensed under Apache License 2.0 (see [LICENSE](./LICENSE) file).
