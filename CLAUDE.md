# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Purpose

This is a Go daemon that monitors r/CrackWatch on Reddit for daily game release posts, enriches each game entry with metadata from IGDB (Internet Game Database), and posts the results as threaded messages to a Matrix room with cover art and screenshots.

## Build & Run

```bash
# Build
go build -o reddit-to-matrix-crackwatcher

# Run directly
go run main.go utils.go

# Run built binary
./reddit-to-matrix-crackwatcher

# Sync dependencies
go mod tidy
```

Requires SQLite3 dev libraries (`libsqlite3-dev` / `sqlite-devel`) due to `go-sqlite3` using CGo.

## Configuration

Copy `sample.config.json` to `config.json` and fill in credentials. The app reads `config.json` at startup and writes back to it to persist refreshed Matrix access tokens. Both `config.json` and `processed_posts.db` are gitignored and never committed.

Required credentials: Reddit OAuth app credentials, IGDB (Twitch) client ID/secret, Matrix homeserver URL + user/password/access token + room ID.

## Architecture

Two source files:

- **`main.go`** — all core logic: config I/O, Reddit polling, IGDB querying, image processing, Matrix messaging, SQLite tracking
- **`utils.go`** — formatting helpers: Markdown table → HTML, Markdown links → HTML anchors, IGDB info → Matrix-ready HTML

**Data flow:**
1. `main()` loads config, authenticates with Matrix (validating/refreshing the stored access token), opens SQLite DB
2. `monitorReddit()` loops every 60±10 seconds, fetching 10 newest r/CrackWatch posts
3. Posts titled "daily release*" are parsed — `extractGamesFromTable()` pulls game rows from the embedded Markdown table
4. Already-processed posts are skipped via the `processed_posts` SQLite table
5. For each game: IGDB is queried via `fetchIGDBInfo()` → cover and screenshots fetched in parallel → images downloaded, thumbnailed (max 400px, aspect-ratio-preserving), blurhashed, and uploaded to Matrix → posted as a Matrix thread (cover+info as thread root, screenshots as replies)

**IGDB matching:** `findBestMatch()` scores candidates via `calculateMatchScore()` using token overlap and exact/partial name matching on a 0–1 scale.

**Matrix threading:** Each game becomes one thread. `sendMatrixImage` / `sendMatrixHTML` accept `threadRootID` and `replyID` parameters to set `m.relates_to` on outgoing events.

**Authentication:**
- Reddit: OAuth2 client credentials via `go-reddit`
- IGDB: Twitch OAuth client credentials, token stored in `Config.IGDBAccessToken`
- Matrix: password login with token caching; `getMatrixClient()` validates the existing token first, re-authenticates if needed, and saves the new token back to `config.json`
