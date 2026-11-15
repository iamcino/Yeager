# Build and release

**English** · [Tiếng Việt](BUILD.vi.md)

How to build Yeager from source, sign it, publish a release on GitLab and mirror
it to GitHub. For how Yeager works inside, see the [design document](DESIGN.md).

## Build from source

You need Windows 11, the [Rust toolchain](https://rustup.rs) and a resource
compiler for the embedded icon and administrator manifest: the Windows SDK
`rc.exe` for the MSVC toolchain, or `windres` from
[w64devkit](https://github.com/skeeto/w64devkit) or MSYS2 for the GNU toolchain.

```powershell
./build.ps1                      # builds and copies the app to dist\yeager.exe
                                 # AND the DNS recovery service to
                                 # dist\yeager-dns-recovery.exe (U09: both ship)

cargo build --release            # target\release\yeager.exe
cargo build --release -p dns-recovery  # target\release\yeager-dns-recovery.exe
cargo build --release -p levi    # target\release\levi.exe, the command-line engine
cargo test --workspace --exclude levi
```

The `yeager` tests need an administrator shell, because the test binary
carries the same administrator manifest as the app.

Build the installer with [Inno Setup](https://jrsoftware.org/isinfo.php) 6 or later
(`C:\Program Files (x86)\Inno Setup 6\ISCC.exe` on garen-pc — a PATH miss is
not a missing ISCC). The pinned thumbprint is derived at build time from
`docs/signing/Yeager-codesign.cer` via `tools/signing/common.ps1`
`Get-PinnedThumbprint` (the same source the signing tooling loads), never
hand-typed; the helper SHA-256 is hashed at build time. `setup.iss` fails
closed without `/DPINNED_THUMBPRINT`:

```powershell
. .\tools\signing\common.ps1
$pinned = Get-PinnedThumbprint
$helperSha = (Get-FileHash dist\yeager-dns-recovery.exe -Algorithm SHA256).Hash.ToLowerInvariant()
iscc installer\setup.iss /DAppVersion=1.1.6 /DNumericVersion=1.1.6.0 "/DPINNED_THUMBPRINT=$pinned" "/DHELPER_SHA256=$helperSha"
# dist\Yeager-Setup-<version>.exe
```

From Linux you can type-check the Windows build with
`cargo check --target x86_64-pc-windows-gnu` (needs `mingw-w64`).

The logo is the vector `assets/logo/yeager.svg`. `tools/make_icons.py` renders
it to the 1024 px master and every icon size (needs Pillow, numpy and
`rsvg-convert`).

## Code signing

Releases are signed with the project's self-issued certificate (ECDSA P-256,
SHA-256, RFC 3161 timestamps). The public certificate is
[`docs/signing/Yeager-codesign.cer`](signing/Yeager-codesign.cer); its
thumbprint pins every signature, so the signing scripts refuse a file signed
by any other key. Current thumbprint: `9131F99C0B198E81FBA0F5818D0637B4A14D4CF1`.

The scripts are in `tools/signing`:

| Script | What it does |
|---|---|
| `new-cert.ps1` | Creates a new certificate: the key goes into `CurrentUser\My` (not exportable), a PFX copy into `.signing\` (git-ignored) with a random password kept in `%LOCALAPPDATA%\Yeager-signing` (DPAPI), and the public `.cer` into `docs\signing\`. |
| `sign.ps1` | Signs and timestamps a file, with the key from the certificate store or `-PfxPath`. |
| `verify.ps1` | Checks the signature against the pinned thumbprint and can write a JSON report. |
| `ci-secrets.ps1` | Puts the CI values (`CODESIGN_PFX_BASE64`, `CODESIGN_PFX_PASSWORD`, `CODESIGN_EXPECTED_THUMBPRINT`) on the clipboard one at a time for pasting, then clears it. |
| `trust-dev.ps1` | Trusts the certificate on a development machine only. |

> [!IMPORTANT]
> Keep a backup of the PFX and its password somewhere safe, such as a
> password manager. The DPAPI copy can only be read by the same Windows user
> on the same machine, and a lost password means rotating to a new
> certificate, as happened in November 2026.

**Rotating the certificate:** run `new-cert.ps1 -Force`, commit the new
`.cer`, update the thumbprint in `SECURITY.md`, the READMEs and the changelog,
then update the GitLab CI/CD variables `CODESIGN_PFX_BASE64` and
`CODESIGN_PFX_PASSWORD`. Keep the old thumbprint listed in `SECURITY.md`
so older downloads can still be checked.

## Where Yeager lives

| | |
|---|---|
| [gitlab.com/cino-group/yeager](https://gitlab.com/cino-group/yeager) | The main repository: merge requests, CI (on the self-hosted Garen-PC runner) and releases. |
| [github.com/iamcino/Yeager](https://github.com/iamcino/Yeager) | An exact mirror: the same `master` commits and the same `v*` tags, and releases with the same files. Nothing is committed or released on GitHub directly. |

`tools/sync-github.ps1` keeps GitHub in step. Run it after each merge to
GitLab `master` and after each release:

```powershell
.\tools\sync-github.ps1          # show what would be pushed
.\tools\sync-github.ps1 -Push    # push GitLab master and any new v* tags to GitHub
```

It never forces a push, so GitHub `master` must always be an ancestor of
GitLab `master`. It expects the remotes `gl` (GitLab) and `origin` (GitHub);
pass `-GitLab` / `-GitHub` for other names.

## Release checklist

1. Set the version in `Cargo.toml` (`[workspace.package] version`).
2. Write the entry in both `CHANGELOG.md` and `CHANGELOG.vi.md` under a
   `## [x.y.z] - YYYY-MM-DD` heading. The release notes are taken from these.
3. Merge to GitLab `master` and wait for the `check` job to pass.
4. Publish on GitLab with `tools/release-gitlab.ps1` (below). It creates tag `vx.y.z`.
5. Run `.\tools\sync-github.ps1 -Push`. The new tag starts the GitHub release
   workflow, which publishes the same release on GitHub.

Every release ships the same set of files on both sites: `Yeager-Setup-<version>.exe`,
`Yeager-<version>-portable-x64.zip` (which carries the signed
`yeager-dns-recovery.exe` inside — the portable provisions the persistent
service via its elevated bootstrap, Q2 ruled), the bare `yeager.exe` the in-app updater
downloads, the bare `yeager-dns-recovery.exe` service binary, `SHA256SUMS.txt`
(hashes for the installer, the portable, the GUI and the helper),
the `*-signature.json` reports (one per signed binary including the helper
and the installer), `Yeager-codesign.cer`, `LICENSE` and `THIRD-PARTY-NOTICES.md`. On GitHub a
VirusTotal report (`virustotal-v<version>.json`) is added afterwards.

The helper and the installer are verified under the same hash +
pinned-signature trust policy as the app binaries: the release scripts sign
every binary (`tools/signing/sign.ps1`) and record its hash
(`*-signature.json` via `tools/signing/verify.ps1 -JsonPath`), and the GitHub
mirror checks every file against `SHA256SUMS.txt`, the pinned signature, and
the byte-identical helper/portable contents (the portable's helper must hash
exactly like the standalone helper artifact).

## DNS service evidence (U09) and service-changing migration

U09-REV ships the DNS recovery service (`crates/dns-recovery`, installer
`[Code]` calling the `--install-service`/`--enter-maintenance`/
`--recover-offline`/`--inspect`/`--leave-maintenance` seams, portable Q2
bootstrap in `crates/app/src/main.rs`, updater gate with real manifest +
pipe versions). The fake-backed gates
(`dns-recovery/src/provision.rs` installer/uninstall/portable planner plus
schema/compat checks, `crates/app/src/updater.rs` service gate incl.
pre-replacement `verify_restore`) run in the normal
`cargo test --workspace` suite — `cargo test` never mutates real NICs. The
controlled real cycle through the built installer plus portable first run
(clean install registers/starts with Hello/inspection of the NEW binary,
upgrade replaces with a DIFFERENT binary while a real journal payload
survives, forced start failure rolls back exe + registration, maintenance
round-trip completes through the seams, clean uninstall leaves the machine
as found, NIC snapshots identical, no DNS takeover) is recorded in
`C:\projects\yeager-dns-pkg\U09-EVIDENCE.md`. Real NIC mutation, destructive
faults and power-loss simulation are U10's disposable-VM gate.

**Service-changing updates:** if the installed Yeager predates the recovery
service (or the release `manifest.json` names a service/protocol/schema
change), update with the signed installer, not the in-app single-exe update.
The single-exe updater fetches the target release's real requirements from
its `manifest.json` sidecar (fail-closed to the installer), reads the
service's actual versions from the pipe Hello, restores/verifies BEFORE any
exe replacement (and again before restart), refuses service-changing
replacements with directions to the installer, and cancels the restart on a
failed cleanup. See `docs/DNS-RECOVERY.md` for the full operator reference.

## Publishing on GitLab

Releases on [gitlab.com/cino-group/yeager](https://gitlab.com/cino-group/yeager/-/releases)
are made by `tools/release-gitlab.ps1`. It builds from a clean temporary
worktree of the ref you give, so your own checkout is untouched, and always
signs with the current checkout's signing scripts and certificate. It uploads
the files to the GitLab generic package registry and creates the release with
notes from both changelogs, English first. `levi.exe` is never shipped.

The stable link to the newest installer is
`https://gitlab.com/cino-group/yeager/-/releases/permalink/latest/downloads/Yeager-Setup.exe`
(and `Yeager-portable-x64.zip` for the portable build).

**From your own machine** (Rust, Inno Setup, Windows SDK and the signing key installed):

```powershell
.\tools\release-gitlab.ps1 -Ref master -DryRun   # build and sign only; files kept in target\release-gitlab\out-<version>
.\tools\release-gitlab.ps1 -Ref master           # build, sign and publish
.\tools\release-gitlab.ps1 -Ref v1.1.5 -AssetsDir D:\yeager-1.1.5   # publish files you already have
```

| Option | Meaning |
|---|---|
| `-Ref` | Branch, tag or commit to build. The version comes from its `Cargo.toml`; the tag is `v<version>`. |
| `-DryRun` | Build and sign, upload nothing. |
| `-SkipTests` | Skip `cargo test`. Needed in a shell without administrator rights. |
| `-AssetsDir` | Don't build; check and republish existing release files (signature and `SHA256SUMS.txt` must match). |
| `-PfxPath` | Sign with this PFX when the key is not in `CurrentUser\My`. |
| `-Prerelease` | Allow a version like `1.2.0-rc1`. GitLab has no pre-release flag, so it becomes the latest release. |

The GitLab token (a project access token with the `api` scope) is read from
`GITLAB_TOKEN`, from `%LOCALAPPDATA%\Yeager-signing\gitlab-token.clixml`, or
asked for when the script starts. Save it once with:

```powershell
Read-Host -AsSecureString | Export-Clixml "$env:LOCALAPPDATA\Yeager-signing\gitlab-token.clixml"
```

The script refuses to overwrite an existing GitLab release; delete it first or
raise the version.

**From GitLab CI:** `.gitlab-ci.yml` runs tests and a release build (`check`)
on every push and merge request, on the self-hosted Windows runner tagged
`yeager-windows` (Garen-PC). The `release` job runs only when started by hand,
on `master` or a `v*` tag, and needs the protected CI/CD variables
`CODESIGN_PFX_BASE64` and `CODESIGN_PFX_PASSWORD`.

## Publishing on GitHub

GitHub releases are never built on GitHub. `.github/workflows/release.yml`
runs when a `v*` tag arrives (from `sync-github.ps1`) and calls
`tools/release-github.ps1`, which downloads the GitLab release, checks every
file against `SHA256SUMS.txt` and the pinned signature, and creates the GitHub
release with the same name, notes and files. It needs no signing secrets. If
the workflow cannot run, do the same by hand on a machine where `gh` is signed in:

```powershell
.\tools\release-github.ps1 -Tag v1.1.5
```

The `VirusTotal reference` workflow then scans the GitHub release and attaches
its report.