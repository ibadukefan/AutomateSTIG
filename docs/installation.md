# Installation

## Prerequisites

- Rust toolchain, stable channel.

## Build

From the repository root:

```bash
cargo build --release --workspace
```

The workspace builds two binaries:

- `automatestig`
- `automatestig-gui`

## Run The GUI

```bash
cargo run --release --bin automatestig-gui
```

Or run the built `automatestig-gui` binary from the release target directory.

The GUI:

- Binds to `127.0.0.1` on a random port, or uses the `PORT` environment variable.
- Opens the browser automatically.
- Stores local data under `~/.automatestig`.

The data directory contains:

- `data.db`
- `library/`

## Run The CLI

```bash
cargo run --release --bin automatestig -- --help
cargo run --release --bin automatestig -- status
```

Use the built binary directly after a release build:

```bash
./target/release/automatestig status
```

## Container

A `Dockerfile` and `railway.toml` exist for hosted deployment.

```bash
docker build -t automatestig .
```

For non-loopback hosted binds, `/api/*` requires an explicit `AUTOMATESTIG_AUTH_TOKEN` of at least 16 characters. `/api/status` is the only unauthenticated API route.
