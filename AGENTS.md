# AGENTS.md

zinoh is a Zenoh client written in Zig 0.16.0 using async primitives with io_uring backed `std.Io.Evented` runtime.

## Build & Run

```bash
zig build              # Build
zig build run          # Run
zig build test         # Run tests
```

## Code Style

- Use Zig idioms (defer for cleanup, error unions)
- Accept allocator as parameter in functions
- Keep modules focused and testable
- Use descriptive names
- Don't create temporary files to pass information to a different process - handle without temporary files
- Use native Zig functions from the standard library to interact with the OS instead of using raw C functions

## Commit Conventions

Use [Conventional Commits](https://www.conventionalcommits.org/) format:

- `feat:` - New features
- `fix:` - Bug fixes
- `test:` - Adding or updating tests
- `chore:` - Maintenance tasks
- `ci:` - CI/CD changes
- `docs:` - Documentation changes
- `refactor:` - Code refactoring

Example: `feat: add support for parsing handshake message`
