# Build and release

**English** · [Tiếng Việt](BUILD.vi.md)

How to build Yeager from source, sign it, and publish a release on GitHub and
GitLab. For how Yeager works inside, see the [design document](DESIGN.md).

## Build from source

You need Windows 11, the [Rust toolchain](https://rustup.rs) and a resource
compiler for the embedded icon and administrator manifest: the Windows SDK
`rc.exe` for the MSVC toolchain, or `windres` from
[w64devkit](https://github.com/skeeto/w64devkit) or MSYS2 for the GNU toolchain.

```powershell
./build.ps1                      # builds and copies the app to dist\yeager.exe

cargo build --release            # target\release\yeager.exe
cargo build --release -p levi    # target\release\levi.exe, the command-line engine
cargo test --workspace --exclude levi
```

The `yeager` tests need an administrator shell, because the test binary
carries the same administrator manifest as the app.

Build the installer with [Inno Setup](https://jrsoftware.org/isinfo.php) 6 or later:

```powershell
iscc installer\setup.iss         # dist\Yeager-Setup-<version>.exe
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
then update the CI secrets and the GitHub variable
`CODESIGN_EXPECTED_THUMBPRINT`. Keep the old thumbprint listed in `SECURITY.md`
so older downloads can still be checked.

## Release checklist

1. Set the version in `Cargo.toml` (`[workspace.package] version`).
2. Write the entry in both `CHANGELOG.md` and `CHANGELOG.vi.md` under a
   `## [x.y.z] - YYYY-MM-DD` heading. The release notes are taken from these.
3. Merge to `master`.
4. Publish on GitHub, then on GitLab, as below. Both use tag `vx.y.z`.

Every release ships the same set of files: `Yeager-Setup-<version>.exe`,
`Yeager-<version>-portable-x64.zip`, the bare `yeager.exe` the in-app updater
downloads, `SHA256SUMS.txt`, the `*-signature.json` reports,
`Yeager-codesign.cer`, `LICENSE` and `THIRD-PARTY-NOTICES.md`.

## Publishing on GitHub

`.github/workflows/release.yml` runs on a `windows-2022` runner. Pushing a
`v*` tag builds, tests, signs and publishes the release; running the workflow
by hand produces the same files as an artifact, and ticking **publish** also
creates the tag. It needs the repository secrets `CODESIGN_PFX_BASE64` and
`CODESIGN_PFX_PASSWORD` and the variable `CODESIGN_EXPECTED_THUMBPRINT`.
A VirusTotal report (`virustotal-v<version>.json`) is attached afterwards.

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
.\tools\release-gitlab.ps1 -Ref v1.2.0           # build, sign and publish
.\tools\release-gitlab.ps1 -FromGitHub           # publish exactly the files of the GitHub release
.\tools\release-gitlab.ps1 -Ref v1.2.0 -AssetsDir D:\yeager-1.2.0   # publish files you already have
```

| Option | Meaning |
|---|---|
| `-Ref` | Branch, tag or commit to build. The version comes from its `Cargo.toml`; the tag is `v<version>`. |
| `-DryRun` | Build and sign, upload nothing. |
| `-SkipTests` | Skip `cargo test`. Needed in a shell without administrator rights. |
| `-FromGitHub` / `-AssetsDir` | Don't build; check and republish existing release files (signature and `SHA256SUMS.txt` must match). |
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

**From GitLab CI:** `.gitlab-ci.yml` runs tests and a release build on every
push and merge request, and the release job on a `v*` tag or by hand on
`master`. It needs a self-hosted Windows runner tagged `yeager-windows` with
the same tools, and the protected CI/CD variables `CODESIGN_PFX_BASE64` and
`CODESIGN_PFX_PASSWORD`.
