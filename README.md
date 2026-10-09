# Wixal tools

Controlled source references and build candidates for the [native Wixal tools library](https://github.com/TheJhyeFactor/Wixal). This repository tracks the eleven tools already in that library. The application owns adapters, permission checks, parsers, package installation and trust bootstrap.

This is a source and build setup. RustScan is the first managed-package pilot. Existing external providers keep their existing integration; no tool or model receives release qualification from being forked.

| Tool | Controlled fork | Integration |
| --- | --- | --- |
| RustScan | [TheJhyeFactor/RustScan](https://github.com/TheJhyeFactor/RustScan) | Managed pilot; bounded TCP discovery |
| Nmap | [TheJhyeFactor/nmap](https://github.com/TheJhyeFactor/nmap) | External provider; discovery and service inspection |
| ffuf | [TheJhyeFactor/ffuf](https://github.com/TheJhyeFactor/ffuf) | External provider; supplied wordlist |
| Nuclei | [TheJhyeFactor/nuclei](https://github.com/TheJhyeFactor/nuclei) | External provider; selected templates |
| Wireshark / TShark | [TheJhyeFactor/wireshark](https://github.com/TheJhyeFactor/wireshark) | External provider; saved capture analysis |
| Trivy | [TheJhyeFactor/trivy](https://github.com/TheJhyeFactor/trivy) | External provider; local project assessment |
| OSV-Scanner | [TheJhyeFactor/osv-scanner](https://github.com/TheJhyeFactor/osv-scanner) | External provider; dependency advisories |
| testssl.sh | [TheJhyeFactor/testssl.sh](https://github.com/TheJhyeFactor/testssl.sh) | External provider; scoped TLS checks |
| mitmproxy | [TheJhyeFactor/mitmproxy](https://github.com/TheJhyeFactor/mitmproxy) | Specialist setup remains explicit |
| ZAP | [TheJhyeFactor/zaproxy](https://github.com/TheJhyeFactor/zaproxy) | Specialist setup remains explicit |
| Metasploit Framework | [TheJhyeFactor/metasploit-framework](https://github.com/TheJhyeFactor/metasploit-framework) | Specialist setup remains explicit |

[`tools.lock.json`](tools.lock.json) records exact upstream commits, fork provenance, immutable license-file references and hashes, integration state and qualification limits. Release tags are resolved to commits when available. A source snapshot is labelled explicitly when upstream has no suitable GitHub release. Default branches and tags never choose the build input. All inherited Actions workflows in these forks are disabled. Source changes are empty for the RustScan recipe.

Wireshark's GitHub repository is the [official read-only mirror](https://github.com/wireshark/wireshark) of its [GitLab repository](https://gitlab.com/wireshark/wireshark). Nmap's GitHub repository mirrors its SVN source. Preserve these distinctions when proposing upstream changes.

## Build and checks

```sh
python3 scripts/validate.py
python3 -m unittest discover -s tests -v
# With GitHub CLI authenticated as the repository owner:
python3 scripts/validate.py --live
```

The Source contracts workflow runs the local checks for pushes and pull requests. It rejects floating source references, recipe/source mismatches and attempts to treat forks as release qualification.

The manually dispatched **RustScan arm64 build candidate** workflow builds the pinned source with Rust 1.90.0 and a hash-pinned Cargo.lock on arm64 macOS. Dependencies are vendored before an offline locked build. The output retains the upstream and vendored source, licenses, executable digest, recipe/compiler/platform identity, system-library inspection, inventory and a real loopback listener smoke check. A tar archive preserves executable permissions through GitHub's artifact ZIP transport. The artifact is unsigned and retained for 14 days. One build is not proof of reproducibility or complete compatibility. No workflow holds production signing keys or publishes a release.

To run it from the CLI:

```sh
gh workflow run rustscan-candidate.yml --repo TheJhyeFactor/wixal-tools --ref main
gh run list --repo TheJhyeFactor/wixal-tools --workflow rustscan-candidate.yml
```

## Distribution and promotion

The repository has immutable releases enabled for future reviewed releases. [`contracts/promotion.json`](contracts/promotion.json) records the remaining signing, custody, licensing and acceptance gates. [`contracts/acceptance-suite.json`](contracts/acceptance-suite.json) retains the application's 104 mandatory scenario families. Candidate artifacts never become approved catalogue entries automatically.

The app still needs a separately approved public TUF catalogue, trusted root embedded in the matching app, exact artifact identities and allowed download hosts. Ordinary app builds remain on external providers until that configuration exists. GitHub release assets redirect to download hosts; the current application fetcher rejects redirects, so simply pasting a release URL cannot configure a working repository.

Nmap requires review against the [Nmap Public Source License](https://nmap.org/npsl/) and any relevant [OEM redistribution terms](https://nmap.org/oem/) before managed binary packaging. A fork does not settle redistribution rights. Each tool and its dependencies retain their upstream licenses; GitHub's SPDX detection is recorded as evidence, not a legal determination. This repository does not relicense upstream software.

For implementation and measured local acceptance, see Wixal's [managed tools status](https://github.com/TheJhyeFactor/Wixal/blob/main/native/MANAGED_TOOLS_IMPLEMENTATION_STATUS.md). Report package, application, platform and model evidence separately.
