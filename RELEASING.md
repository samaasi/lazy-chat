# Releasing lazy-chat

Releases are built, signed and published by CI when a version tag is pushed.
Nothing is built or signed on a developer machine.

```
git tag v1.2.3
git push origin v1.2.3
```

The `release` job in [.github/workflows/build.yml](.github/workflows/build.yml) then runs the tests and
a vulnerability scan, and [GoReleaser](https://goreleaser.com) ([.goreleaser.yaml](.goreleaser.yaml)):

- builds `CGO_ENABLED=0` binaries for Linux, macOS and Windows on amd64 and arm64,
- packs them as `lazy-chat_<version>_<os>_<arch>.tar.gz` (`.zip` on Windows),
- writes `checksums.txt` (SHA-256) and signs it with cosign into `checksums.txt.sig`,
- creates the GitHub release, and updates the Homebrew cask (macOS) and the Scoop manifest. Homebrew casks are aimed at macOS; Linux users install with `scripts/install.sh`.

Pull requests run the same build as a dry run (no signing, no publishing), so a broken
configuration is caught before a release.

Tags containing `-` (for example `v1.3.0-rc.1`) are published as prereleases. The updater and the
install scripts ignore prereleases unless a version is requested explicitly.

## One-time setup

### 1. The signing key

The checksums are signed with a private key that only CI holds. The matching public key is
compiled into every release, and `lazy-chat update` refuses anything it does not verify.

```
cosign generate-key-pair          # writes cosign.key (encrypted) and cosign.pub
cp cosign.pub internal/update/release.pub
git add internal/update/release.pub && git commit -m "chore: release signing key"
```

Then add these repository secrets (Settings, Secrets and variables, Actions):

| Secret | Value |
| --- | --- |
| `COSIGN_PRIVATE_KEY` | the full contents of `cosign.key` |
| `COSIGN_PASSWORD` | the password you chose for it |
| `TAP_GITHUB_TOKEN` | a token that can push to the two repositories below |

Keep `cosign.key` somewhere safe and offline, and never commit it. Until `release.pub` holds a real key,
the release job refuses to run, and a build made from source cannot install updates (it can still look
for them).

### 2. Homebrew and Scoop repositories

Create two empty public repositories, `samaasi/homebrew-tap` and `samaasi/scoop-bucket`, and give
`TAP_GITHUB_TOKEN` write access to both (a fine-grained token with "Contents: read and write" on them is
enough). A package manager cannot be pushed to with the workflow's own token because it only covers this
repository. If you do not want one of them, delete its block from `.goreleaser.yaml`.

## Checking a release by hand

```
curl -fsSLO https://github.com/samaasi/lazy-chat/releases/download/v1.2.3/checksums.txt
curl -fsSLO https://github.com/samaasi/lazy-chat/releases/download/v1.2.3/checksums.txt.sig
openssl base64 -d -A -in checksums.txt.sig -out sig.der
openssl dgst -sha256 -verify internal/update/release.pub -signature sig.der checksums.txt
sha256sum --check --ignore-missing checksums.txt
```

(or `cosign verify-blob --key internal/update/release.pub --signature checksums.txt.sig checksums.txt`).
The release job runs the openssl check itself against the key in the source tree, right after publishing.

## Rotating the key

Installed copies trust only the key they were built with, so a new key must first reach them in a
release signed with the old one: put the new `release.pub` in the source, publish one release signed with
the old key, and only then switch the `COSIGN_PRIVATE_KEY` secret. Users who skip that release have to
reinstall with the install script.
