---
attack_type: containers-supply-chain
category_id: containers-supply-chain
name: Containers, CI/CD & Software Supply Chain
description: container escapes, poisoned images and compromised build pipelines
version: 1
os_coverage: [linux, windows, macos, cloud]
sub_types_covered: 10
sub_types:
  - container-escape-to-host
  - poisoned-or-backdoored-base-image
  - malicious-overlay2-layer
  - compromised-ci-runner-artifacts
  - dependency-or-package-tampering
  - secrets-leaked-in-image-layers
  - registry-push-of-trojaned-image
  - tampered-image-manifest-or-config
  - build-cache-or-pipeline-script-poisoning
  - runtime-container-persistence
validated_on: []
maturity: draft
variables:
  image_path:
    default: /cases/active/evidence/disk.E01
    derive: "Step 0 — first disk-evidence image (E01/dd/raw/vmdk) of the container HOST or BUILD runner enumerated under the evidence directory named in the case brief"
  mount_root:
    default: /cases/active/mount
    derive: "Step 0 — directory where the host file system is mounted READ-ONLY (or where icat-extracted overlay2/docker artifacts land when mounting fails); the docker root is usually #{mount_root}/var/lib/docker"
  case_out:
    default: /cases/active/out
    derive: "Step 0 — writable case output directory from the case brief; Step 0 creates #{case_out}/receipts/ and #{case_out}/extracted/"
  ntfs_offset_sectors:
    default: 0
    derive: "Step 0 — start sector of the relevant partition from `mmls #{image_path}` (largest data partition holding /var/lib/docker; usually an ext4/xfs partition for a Linux container host)"
  time_window:
    default: 1970-01-01..2099-12-31
    derive: "case brief if it names one; else first confirmed malicious timestamp (image build/pull or CI job) +/-48h once a step pins one — then re-scope wide sweeps to it"
---

## In one line
Someone tampered with the software factory: they hid a backdoor inside a container image or a build pipeline, or they broke out of a container onto the host. This playbook reads the on-disk leftovers of Docker images, their stacked file-system layers, and CI build outputs to prove what was poisoned, when, and by whom.

## Use this when (triggers)
- A host runs Docker/containerd and you suspect a **container broke out onto the host** (a process or file appeared on the host that should have stayed inside a container).
- A deployed **base image looks wrong** — an unexpected binary, an extra layer, or a hash that does not match the upstream/official image.
- A **CI/CD build runner** (Jenkins, GitLab Runner, GitHub Actions self-hosted) was breached and you need to know which build artifacts were tampered with on disk.
- A **dependency or package** baked into an image was swapped for a malicious one (typosquat, poisoned cache, altered lockfile).
- You suspect **secrets** (keys, tokens, `.env` files) were leaked inside an image layer and shipped to a registry.
- A **trojaned image was pushed** to a registry, or an image **manifest/config was edited** to point at a malicious layer.

## Quick path (the 90% case)
1. **Timeline-first.** Build a file-system timeline of the docker root and CI workspaces with `fls -r -m` over `#{mount_root}/var/lib/docker` (and the runner home) into a bodyfile, render it with `mactime`, OR fold the whole host into a super-timeline with `log2timeline.py` (it carries a Docker layer/config parser) + `psort.py`. Skim it inside `#{time_window}` BEFORE committing to a story — the order of image-pull / layer-write / build-job / host-write is the case.
2. **Inventory the images and layers.** List `#{mount_root}/var/lib/docker/image/overlay2/imagedb/` configs and the `overlay2/` layer dirs; read each image config JSON with `python3 -m json.tool` to recover the layer `diff_id` chain, the entrypoint/cmd, and the build history.
3. **Hash every layer and compare to a known-good baseline.** Run `sha256deep -r` over each `overlay2/<id>/diff` tree and over the image configs; a `diff_id` or layer-tar hash that does NOT match the official upstream digest = a poisoned/backdoored base image (the strongest single finding).
4. **Diff the layers for the malicious add.** The top (most recent) overlay2 layer is the attacker's add-on; `fls`/`icat` its `diff` tree, `srch_strings`/`bstrings` it for URLs/IPs/keys, and scan dropped binaries with `pe-scanner` / `page-brute` (python3-yara) to find the implant.
5. **Corroborate the escape/push.** Match a host-side write (a file on the host owned by a container UID, a `runc`/`containerd` exploit artifact) or a registry-push record in the Docker daemon log to the same time and the same hash. One layer hash is a lead, not a fact.

If a tampered layer/hash, a malicious file inside it, the build/pull time, and a corroborating host or daemon-log event all line up on one timeline → you are mostly done. Otherwise drop into the full Steps.

## How it unfolds (the story)
An attacker poisons the supply chain at one of three on-disk choke points. They may **backdoor a base image** — add a layer carrying a webshell, a reverse shell, or a swapped dependency, then push the trojaned image to a registry so every downstream pull inherits it. They may **compromise a CI runner** — alter a build script, lockfile, or cached artifact so the malicious code is baked in at build time and signed as legitimate. Or, at runtime, they **escape the container** — abuse a privileged/misconfigured container or a `runc`/kernel flaw to write to the host file system and establish persistence outside the container boundary. Every one of these leaves disk evidence: new or altered overlay2 layers, mismatched image/layer hashes, edited manifests/configs, tampered build outputs, leaked secrets in a layer, and host-side files written by a containerized process — all reconstructable from the docker root, the CI workspace, and the daemon log.

## Theories to test (and how to rule each out)
| Theory (who / why) | If true, you'd find… | Rule it out if… |
|---|---|---|
| **Supply-chain (poisoned/backdoored base image)** | an image whose layer `diff_id` chain or config history contains an EXTRA layer not in the official upstream; a layer hash mismatching the published digest; a dropped binary/webshell inside the top layer | every layer hash matches the official upstream digest AND the history shows only expected build steps — image is pristine |
| **Supply-chain (dependency/package tampering)** | a lockfile/package whose hash differs from the registry-pinned hash; a swapped/typosquatted module inside a layer; a build cache containing an unexpected artifact | dependency hashes match the pinned lockfile and the upstream package registry — no swap |
| **External-targeted (container escape to host)** | host-side files written by a container UID/GID; a privileged container config; `runc`/containerd exploit residue; a host persistence unit dropped from inside a container near a container start time | no host file traces back to a container process; no privileged/host-mount container; host writes all have ordinary host-user provenance |
| **Insider / other-insider (build pipeline operator abuse)** | a CI build script, Dockerfile, or pipeline config edited by a build account to inject a step; a credential reused to push a trojaned image; the change made from the runner itself | the pipeline change has a sanctioned change-control record AND the pushing identity + source are expected for that repo/registry |
| **External-commodity (cryptominer/opportunistic image)** | a public image pulled that bundles a miner/coinminer in a layer; outbound mining-pool strings in a layer; high-entropy packed binary dropped by the entrypoint | no miner/pool indicators; entrypoint and layers are benign and match the documented application |
| **Innocent / benign (NOT an attack)** | extra layers and new hashes explained by a legitimate `docker build`/CI run; a vendor-signed base image; secrets present but only in a build-arg layer that was correctly squashed/removed | a sanctioned build record explains every new layer/hash AND the image came from a trusted, signed source → benign cause confirmed; reclassify |

*(>=1 benign + >=1 malicious, each ACTIVELY refuted. Attacker types mapped: insider · other-insider · external-commodity · external-targeted · supply-chain · innocent.)*

## Evidence → Tool → What it reveals (per OS)
| Evidence | SIFT tool | What it tells you *for this attack* | OS |
|---|---|---|---|
| `/var/lib/docker/image/overlay2/imagedb/content/sha256/*` (image config JSON) | `python3 -m json.tool` (stdlib) / `srch_strings` | The image identity: layer `diff_id` chain, entrypoint/cmd, env (leaked secrets), and the build `history` — extra/unexplained steps name the poisoning | Linux |
| `/var/lib/docker/image/overlay2/repositories.json` | `python3 -m json.tool` / `srch_strings` | Which repo:tag maps to which image digest — a trojaned-image push or a tag re-pointed to a malicious digest | Linux |
| `/var/lib/docker/overlay2/<id>/diff` (per-layer file trees) | `fls` / `icat` / `istat` (TSK over the layer dir or the image offset) | The actual files each layer ADDED — diff the top layer to isolate the attacker's add; `istat` $SI vs ctime catches timestomp on a planted file | Linux |
| Each layer `diff` tree + each image config | `sha256deep -r` / `md5deep -r` | Hash of every layer and config to compare against the official upstream digest — a mismatch IS the poisoned-base / tampered-layer finding | all |
| Dropped binaries / scripts inside a layer | `pe-scanner` (python3-yara, +entropy) / `page-brute` (python3-yara over a file) / `densityscout` | A planted PE/ELF implant, packer/high entropy, or a YARA-rule match for a known webshell/backdoor inside the layer | all |
| A layer `diff` tree (strings sweep) | `srch_strings` / `bstrings` / `bulk_extractor` | URLs, IPs, mining pools, base64 cradles, and leaked keys/tokens spilled into a layer file | all |
| `daemon.json` log / `/var/lib/docker/containers/<id>/<id>-json.log` + `config.v2.json` | `srch_strings` / `python3 -m json.tool` / `log2timeline.py` (docker parser) | Container start/stop, the trojaned-image PULL/PUSH, mounts (host-path binds = escape risk), and privileged flag | Linux |
| CI runner workspace + build artifacts (Jenkins/GitLab/Actions home) | `fls`/`mactime`, `sha256deep -r`, `srch_strings` | Tampered build outputs: an artifact whose hash differs from the pinned build, an edited pipeline script, a poisoned cache | all |
| Whole host fused | `log2timeline.py` (Docker layer/config + filestat parsers) + `psort.py` (+ `pinfo.py`) | One chronology placing image pull/build → layer write → CI job → host write/escape in order | all |
| Host file system outside the docker root | `fls` / `mactime` / `usnjls` (NTFS) | Host-side files written by a container process (escape) — and the persistence (cron/systemd unit on Linux, Run key/service on Windows) it dropped | all |
| Raw image (FS-independent feature sweep) | `bulk_extractor` | Emails/URLs/IPs/keys across unallocated and deleted layer tars a mounted scan would miss | all |
| RAM image (if captured) | `vol` (Volatility 3) | Live container/`runc`/`containerd` processes, an escaped process now on the host, and in-memory layer paths not yet flushed | Linux* |

*Linux memory analysis in `vol` needs a matching symbol table — ⚠️verify availability before relying on it. The `yara` CLI is ABSENT on this box; all YARA-rule scanning runs through the python3-yara library inside `pe-scanner`/`page-brute`.*

## Step 0 — evidence inventory & access bootstrap
- n: 0
  tool: |
    mkdir -p "#{case_out}/receipts" "#{case_out}/extracted" && ls -laR "#{mount_root}" > "#{case_out}/receipts/00.txt" 2>&1 ; img_stat "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; mmls "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; fsstat -o #{ntfs_offset_sectors} "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; ls -la "#{mount_root}/var/lib/docker/image/overlay2/imagedb/content/sha256" >> "#{case_out}/receipts/00.txt" 2>&1 ; ls -la "#{mount_root}/var/lib/docker/overlay2" >> "#{case_out}/receipts/00.txt" 2>&1
  expect: every evidence file classified; #{image_path}, #{mount_root}, #{ntfs_offset_sectors}, #{case_out} bound; read-only access proven; the docker root (/var/lib/docker with image/overlay2/imagedb and the overlay2 layer dirs) and any CI runner workspace are enumerated, or their absence is recorded
  check: |
    test -r "#{mount_root}" -o -n "$(ls "#{case_out}/extracted" 2>/dev/null)"
  falsify: evidence dir empty/unreadable, or no supported image format found, or no partition holding a file system for fsstat
  on_result: {expect_met: goto 1, falsify_met: STOP report acquisition/access failure; pivot acquisition-custody, neither: try the icat-extract fallback (fls to find /var/lib/docker inodes, icat each image config and the top overlay2 layer files into #{case_out}/extracted); if that also fails treat as falsify_met}
  emits: [key_artifacts]
  serves: [container-escape-to-host, poisoned-or-backdoored-base-image, malicious-overlay2-layer, compromised-ci-runner-artifacts, dependency-or-package-tampering, secrets-leaked-in-image-layers, registry-push-of-trojaned-image, tampered-image-manifest-or-config, build-cache-or-pipeline-script-poisoning, runtime-container-persistence]
  provenance: {receipt_id: 00, artifact: evidence directory listing + docker root enumeration, offset_or_row: full listing, literal_cited: image filename + overlay2 layer dir list}

## Steps (executable — decision-driven)
- n: 1
  precondition: "exists #{mount_root}/var/lib/docker"
  tool: |
    fls -r -m / -o #{ntfs_offset_sectors} "#{image_path}" > "#{case_out}/dockerfs.body" 2>"#{case_out}/receipts/01.txt" ; mactime -b "#{case_out}/dockerfs.body" -d > "#{case_out}/dockerfs_timeline.csv" 2>>"#{case_out}/receipts/01.txt" ; grep -iE "var/lib/docker|/diff/|imagedb|repositories.json" "#{case_out}/dockerfs_timeline.csv" | head -n 500 >> "#{case_out}/receipts/01.txt" 2>&1
  expect: a file-system timeline of the docker root inside #{time_window}, showing the write order of overlay2 layer dirs, image configs, and repositories.json — the most-recently-written layer dir is the lead for the attacker's add
  check: |
    test -s "#{case_out}/dockerfs_timeline.csv" && grep -qiE "overlay2|var/lib/docker" "#{case_out}/receipts/01.txt"
  falsify: no /var/lib/docker entries in the timeline (no Docker on this host, or the docker root was wiped) — record the absence as a finding
  on_result: {expect_met: note the newest overlay2 layer dir + its mtime; goto 2, falsify_met: if there is no docker root check for containerd (/var/lib/containerd) or Podman (/var/lib/containers); if none record absence and pivot disk-filesystem, neither: re-run fls without -m as -rp to confirm the paths exist; widen #{time_window}}
  emits: [timeline_events]
  serves: [malicious-overlay2-layer, runtime-container-persistence]
  provenance: {receipt_id: 01, artifact: docker root file-system timeline, offset_or_row: dockerfs_timeline.csv overlay2 rows, literal_cited: newest overlay2 layer dir path + mtime}

- n: 2
  precondition: "exists #{mount_root}/var/lib/docker/image/overlay2/imagedb/content/sha256"
  tool: |
    for f in "#{mount_root}"/var/lib/docker/image/overlay2/imagedb/content/sha256/* ; do echo "=== $f ===" >> "#{case_out}/receipts/02.txt" ; python3 -m json.tool "$f" >> "#{case_out}/receipts/02.txt" 2>&1 ; done ; python3 -m json.tool "#{mount_root}/var/lib/docker/image/overlay2/repositories.json" > "#{case_out}/repositories.json.txt" 2>>"#{case_out}/receipts/02.txt" ; grep -iE "diff_id|created_by|repotags|entrypoint|\"cmd\"|env" "#{case_out}/receipts/02.txt" | head -n 400 >> "#{case_out}/receipts/02.txt" 2>&1
  expect: each image config parsed: the rootfs.diff_ids layer chain, the build history (created_by steps), entrypoint/cmd, and env — an EXTRA history step (a curl|sh, an ADD of a binary, a swapped package) or a secret in env is the poisoning lead; repositories.json maps the repo:tag to the image digest
  check: |
    grep -qiE "diff_id|diff_ids|rootfs" "#{case_out}/receipts/02.txt"
  falsify: configs parse but the history matches a clean expected build exactly AND no extra layer/secret/odd entrypoint appears — image identity looks pristine at this layer
  on_result: {expect_met: record the diff_id chain + any suspicious history step/env secret; goto 3, falsify_met: record image as clean-by-config; still hash layers at goto 3 to confirm the bytes match the config, neither: dump the raw config with srch_strings if json.tool errors on a malformed file; widen the search to all imagedb configs}
  emits: [key_artifacts, key_iocs]
  serves: [poisoned-or-backdoored-base-image, tampered-image-manifest-or-config, secrets-leaked-in-image-layers, registry-push-of-trojaned-image]
  provenance: {receipt_id: 02, artifact: image config JSON + repositories.json, offset_or_row: receipt 02 diff_ids/history block, literal_cited: the extra history created_by step or the diff_id chain}

- n: 3
  precondition: "exists #{mount_root}/var/lib/docker/overlay2"
  tool: |
    sha256deep -r "#{mount_root}/var/lib/docker/image/overlay2/imagedb/content/sha256" > "#{case_out}/image_config_hashes.txt" 2>>"#{case_out}/receipts/03.txt" ; for d in "#{mount_root}"/var/lib/docker/overlay2/*/diff ; do sha256deep -r "$d" >> "#{case_out}/layer_file_hashes.txt" 2>>"#{case_out}/receipts/03.txt" ; done ; wc -l "#{case_out}/layer_file_hashes.txt" >> "#{case_out}/receipts/03.txt" 2>&1 ; head -n 200 "#{case_out}/layer_file_hashes.txt" >> "#{case_out}/receipts/03.txt" 2>&1
  expect: a SHA-256 for every image config and every file in every overlay2 layer diff tree — these are compared (next) against the official upstream digests / a known-good baseline; the config sha256 filename IS the published image-config digest, so a content hash that does not equal its own filename means the config was edited
  check: |
    test -s "#{case_out}/layer_file_hashes.txt" && test -s "#{case_out}/image_config_hashes.txt"
  falsify: no overlay2 diff trees readable to hash (layers extracted/deleted, or permission denied) — fall back to icat over the layer inodes
  on_result: {expect_met: goto 4, falsify_met: icat-extract the layer files from the image offset into #{case_out}/extracted then sha256deep that; if no bytes survive record the gap and pivot file-recovery-carving, neither: re-run sha256deep on the single newest layer dir from step 1; if it still fails note the unreadable layer as a finding}
  emits: [key_iocs]
  serves: [poisoned-or-backdoored-base-image, malicious-overlay2-layer, dependency-or-package-tampering, tampered-image-manifest-or-config]
  provenance: {receipt_id: 03, artifact: overlay2 layer diff trees + image configs, offset_or_row: layer_file_hashes.txt rows, literal_cited: a layer-file SHA-256 + path}

- n: 4
  precondition: "exists #{case_out}/layer_file_hashes.txt"
  tool: |
    if test -s "#{case_out}/baseline_hashes.txt" ; then sort -k1,1 "#{case_out}/baseline_hashes.txt" > "#{case_out}/.bl.sorted" ; awk "{print \$1}" "#{case_out}/layer_file_hashes.txt" | sort -u > "#{case_out}/.layer.h" ; awk "{print \$1}" "#{case_out}/.bl.sorted" | sort -u > "#{case_out}/.bl.h" ; comm -23 "#{case_out}/.layer.h" "#{case_out}/.bl.h" > "#{case_out}/unmatched_hashes.txt" 2>>"#{case_out}/receipts/04.txt" ; fi ; for f in "#{mount_root}"/var/lib/docker/image/overlay2/imagedb/content/sha256/* ; do bn=$(basename "$f") ; ch=$(sha256deep "$f" 2>/dev/null | awk "{print \$1}") ; if test "$bn" != "$ch" ; then echo "CONFIG-DIGEST-MISMATCH $bn != $ch" >> "#{case_out}/unmatched_hashes.txt" ; fi ; done ; echo "--- unmatched ---" >> "#{case_out}/receipts/04.txt" ; cat "#{case_out}/unmatched_hashes.txt" >> "#{case_out}/receipts/04.txt" 2>&1 ; wc -l "#{case_out}/unmatched_hashes.txt" >> "#{case_out}/receipts/04.txt" 2>&1
  expect: with a known-good baseline present, the set difference lists layer-file hashes NOT in the official upstream (the poisoned adds); independently, any image-config file whose content hash does NOT equal its own sha256 filename is a CONFIG-DIGEST-MISMATCH = an edited manifest/config — both are direct tamper findings
  check: |
    test -s "#{case_out}/unmatched_hashes.txt"
  falsify: with a baseline present, the set difference is EMPTY and no config-digest mismatch — every layer byte and every config matches the upstream digest, image is pristine
  on_result: {expect_met: record the mismatched hashes/files as IOCs and which layer holds them; goto 5, falsify_met: image hashes pristine; redirect to the CI-runner and host-escape angles at goto 7, neither: no baseline available, so hash-compare is inconclusive; proceed to content-level inspection of the newest layer at goto 5 and label findings inferred}
  emits: [key_iocs]
  serves: [poisoned-or-backdoored-base-image, dependency-or-package-tampering, tampered-image-manifest-or-config, registry-push-of-trojaned-image]
  provenance: {receipt_id: 04, artifact: hash set-difference + config-digest self-check, offset_or_row: unmatched_hashes.txt rows, literal_cited: an unmatched layer hash or a CONFIG-DIGEST-MISMATCH line}

- n: 5
  precondition: "exists #{mount_root}/var/lib/docker/overlay2"
  tool: |
    NEWEST=$(ls -1dt "#{mount_root}"/var/lib/docker/overlay2/*/diff 2>/dev/null | head -n 1) ; echo "newest layer diff: $NEWEST" > "#{case_out}/receipts/05.txt" ; find "$NEWEST" -type f >> "#{case_out}/receipts/05.txt" 2>&1 ; srch_strings -a "$NEWEST"/* 2>/dev/null | grep -iE "http://|https://|nc |/bin/sh|/bin/bash|bash -i|curl |wget |base64|BEGIN .*PRIVATE KEY|AKIA[0-9A-Z]{16}|xoxb-|eval\\(" | head -n 200 >> "#{case_out}/receipts/05.txt" 2>&1
  expect: inside the newest overlay2 layer (the attacker add), planted files plus indicator strings — reverse-shell one-liners (bash -i, nc), download cradles (curl|wget), webshell eval(), or leaked credentials (PRIVATE KEY, AKIA..., xoxb- tokens) — the concrete payload and its IOCs
  check: |
    grep -qiE "http|/bin/sh|/bin/bash|nc |curl |wget |base64|PRIVATE KEY|AKIA|xoxb-|eval" "#{case_out}/receipts/05.txt"
  falsify: the newest layer contains only expected application files with no shell/network/credential indicators — no obvious implant or leaked secret in this layer
  on_result: {expect_met: record the dropped file paths + indicator strings as IOCs; goto 6, falsify_met: widen to ALL overlay2 layers not just the newest; if still clean record no-implant-found and move to CI/host angles at goto 7, neither: bstrings the layer files with its regex library for URLs/keys; bulk_extractor the image for features the mounted strings sweep missed}
  emits: [key_iocs, key_artifacts]
  serves: [malicious-overlay2-layer, secrets-leaked-in-image-layers, dependency-or-package-tampering]
  provenance: {receipt_id: 05, artifact: newest overlay2 layer diff tree, offset_or_row: receipt 05 strings hits, literal_cited: the reverse-shell/cradle/credential string + file path}

- n: 6
  precondition: "exists #{case_out}/receipts/05.txt"
  tool: |
    NEWEST=$(ls -1dt "#{mount_root}"/var/lib/docker/overlay2/*/diff 2>/dev/null | head -n 1) ; for b in $(find "$NEWEST" -type f 2>/dev/null | head -n 50) ; do echo "=== $b ===" >> "#{case_out}/receipts/06.txt" ; /opt/pe-scanner/bin/pe-scanner -f "$b" >> "#{case_out}/receipts/06.txt" 2>&1 ; densityscout "$b" >> "#{case_out}/receipts/06.txt" 2>&1 ; done ; clamscan -r "$NEWEST" >> "#{case_out}/receipts/06.txt" 2>&1
  expect: a dropped binary in the layer flagged by pe-scanner (PE/ELF anomaly or a python3-yara YARA-rule hit for a known webshell/backdoor family), a high-entropy/packed score from densityscout, or a clamscan signature match — confirming the add is malware not benign app code
  check: |
    grep -qiE "rule .*match|match|packed|entropy|FOUND|suspicious|high" "#{case_out}/receipts/06.txt"
  falsify: pe-scanner finds no anomaly, densityscout reports normal entropy, and clamscan is clean — the dropped files are not flagged as malicious by signature/heuristic
  on_result: {expect_met: record the implant hash + YARA-rule/signature name as a key IOC; goto 7, falsify_met: a clean scan does not clear a novel implant; keep the string-level finding from step 5 at inferred and corroborate via the timeline; goto 7, neither: re-run pe-scanner on the single most suspicious binary; page-brute the file with a webshell YARA-rule set if pe-scanner cannot load it}
  emits: [key_iocs]
  serves: [malicious-overlay2-layer, poisoned-or-backdoored-base-image, build-cache-or-pipeline-script-poisoning]
  provenance: {receipt_id: 06, artifact: dropped binary inside the layer, offset_or_row: receipt 06 scanner output, literal_cited: the YARA-rule/clamscan signature name or entropy score}

- n: 7
  precondition: "exists #{mount_root}/var/lib/docker"
  tool: |
    find "#{mount_root}/var/lib/docker/containers" -name "config.v2.json" -exec python3 -m json.tool {} \; > "#{case_out}/receipts/07.txt" 2>&1 ; grep -iE "Privileged|Binds|\"Source\"|HostConfig|Image\"|\"Cmd\"|CapAdd|PidMode|SecurityOpt" "#{case_out}/receipts/07.txt" | head -n 300 >> "#{case_out}/receipts/07.txt" 2>&1 ; for L in "#{mount_root}"/var/lib/docker/containers/*/*-json.log ; do srch_strings -a "$L" 2>/dev/null | grep -iE "exec|/bin/sh|escape|nsenter|runc|capsh|/host|chroot" | head -n 50 >> "#{case_out}/receipts/07.txt" 2>&1 ; done
  expect: a container config that is Privileged, mounts the host root (Binds Source=/), adds dangerous caps (CapAdd SYS_ADMIN), or shares host PID — the escape pre-condition; and/or daemon json-log lines showing nsenter/runc/chroot/host-mount abuse — evidence a container reached the host
  check: |
    grep -qiE "Privileged.*true|\"Source\": ?\"/\"|SYS_ADMIN|PidMode.*host|nsenter|runc|/host" "#{case_out}/receipts/07.txt"
  falsify: every container config is unprivileged with no host-root bind, no dangerous caps, and the logs show no host-reaching commands — no escape pre-condition or escape activity on disk
  on_result: {expect_met: record the privileged/host-mount config or the escape command as the escape vector; goto 8, falsify_met: record no-escape-evidence; if the case is purely image-poisoning this is expected, continue to host corroboration at goto 8, neither: cross-check host file writes by container UID via fls/mactime; widen #{time_window} around container start}
  emits: [key_artifacts, key_iocs]
  serves: [container-escape-to-host, runtime-container-persistence]
  provenance: {receipt_id: 07, artifact: container config.v2.json + json log, offset_or_row: receipt 07 HostConfig/log rows, literal_cited: the Privileged/Binds Source=/ value or the nsenter/runc log line}

- n: 8
  precondition: "exists #{mount_root}/var/lib/docker"
  tool: |
    log2timeline.py --status_view none --parsers "docker,filestat" "#{case_out}/supply.plaso" "#{mount_root}/var/lib/docker" > "#{case_out}/receipts/08.txt" 2>&1 ; psort.py -o l2tcsv "#{case_out}/supply.plaso" > "#{case_out}/supply_super.csv" 2>>"#{case_out}/receipts/08.txt" ; pinfo.py "#{case_out}/supply.plaso" >> "#{case_out}/receipts/08.txt" 2>&1 ; grep -iE "docker|overlay2|layer|container|image" "#{case_out}/supply_super.csv" | head -n 300 >> "#{case_out}/receipts/08.txt" 2>&1
  expect: a fused super-timeline placing image pull/build -> layer write (the poisoned layer from steps 3-6) -> CI job / entrypoint run -> registry push or host write/escape (step 7) in a coherent order inside #{time_window}, with no unexplained gap; the Docker parser tags layer/config events so the poisoning slots into the host timeline
  check: |
    test -s "#{case_out}/supply_super.csv" && grep -qiE "docker|overlay2|container|layer" "#{case_out}/supply_super.csv"
  falsify: ordering is impossible (e.g. the layer write predates the base image pull) OR an unexplained gap that no event accounts for — clock manipulation or a missing artifact
  on_result: {expect_met: COMMIT the conclusion with a confidence label; close per the gate, falsify_met: re-open the Theories table; a gap/inversion may mean timestomp on the layer files (recheck istat $SI vs ctime) or deleted daemon logs; anchor to mtime order not just $SI, neither: run pinfo.py to confirm the docker parser ran; if it did not, fall back to the fls mactime timeline from step 1 and the json-log timestamps}
  emits: [timeline_events]
  serves: [poisoned-or-backdoored-base-image, malicious-overlay2-layer, registry-push-of-trojaned-image, container-escape-to-host, compromised-ci-runner-artifacts]
  provenance: {receipt_id: 08, artifact: fused super-timeline, offset_or_row: supply_super.csv ordered docker rows, literal_cited: ordered pull->layer-write->build->push/escape chain}

- n: 9
  precondition: "exists #{mount_root}"
  tool: |
    for d in "#{mount_root}/var/lib/jenkins" "#{mount_root}/home/gitlab-runner" "#{mount_root}/actions-runner" "#{mount_root}/builds" ; do test -d "$d" && echo "=== runner: $d ===" >> "#{case_out}/receipts/09.txt" && sha256deep -r "$d" >> "#{case_out}/ci_artifact_hashes.txt" 2>>"#{case_out}/receipts/09.txt" ; done ; find "#{mount_root}" -maxdepth 6 \( -iname "Dockerfile" -o -iname "*.gitlab-ci.yml" -o -iname "Jenkinsfile" -o -iname "package-lock.json" -o -iname "requirements*.txt" -o -iname "go.sum" \) 2>/dev/null | head -n 100 >> "#{case_out}/receipts/09.txt" 2>&1 ; srch_strings -a "#{case_out}/ci_artifact_hashes.txt" 2>/dev/null | head -n 100 >> "#{case_out}/receipts/09.txt" 2>&1
  expect: CI runner workspaces and build manifests (Dockerfile, pipeline YAML, lockfiles) located and hashed; a lockfile/artifact whose hash differs from the pinned/expected value, or a pipeline script carrying an injected step (curl|sh, an extra build stage), is the build-time tamper — the upstream cause of a poisoned image
  check: |
    test -s "#{case_out}/receipts/09.txt" && grep -qiE "Dockerfile|gitlab-ci|Jenkinsfile|lock|requirements|go.sum|runner" "#{case_out}/receipts/09.txt"
  falsify: no CI runner workspace or build manifest on this host (it is a deploy host, not a build host) — record absence; the poisoning happened elsewhere in the pipeline
  on_result: {expect_met: record the tampered manifest/lockfile/artifact hash as an IOC and tie it to the poisoned layer; close per the gate, falsify_met: record this host as deploy-only with no build artifacts; the build-time tamper is out of scope for this image, pivot attack-lifecycle-hunting to trace the pipeline, neither: grep the found Dockerfiles/pipeline YAML for an injected step (curl pipe sh, an added RUN); diff a lockfile against its committed version if present}
  emits: [key_artifacts, key_iocs]
  serves: [compromised-ci-runner-artifacts, dependency-or-package-tampering, build-cache-or-pipeline-script-poisoning]
  provenance: {receipt_id: 09, artifact: CI runner workspace + build manifests, offset_or_row: receipt 09 manifest list / ci_artifact_hashes.txt rows, literal_cited: the tampered lockfile hash or the injected pipeline step}

## Linux branch (L1..Ln) — REQUIRED, numbered, same step shape
- n: L1
  precondition: "os == linux"
  tool: |
    fsstat -o #{ntfs_offset_sectors} "#{image_path}" > "#{case_out}/receipts/L01.txt" 2>&1 ; test -d "#{mount_root}/var/lib/docker" && echo "DOCKER-ROOT-PRESENT" >> "#{case_out}/receipts/L01.txt" ; test -d "#{mount_root}/var/lib/containerd" && echo "CONTAINERD-PRESENT" >> "#{case_out}/receipts/L01.txt" ; test -d "#{mount_root}/var/lib/containers" && echo "PODMAN-PRESENT" >> "#{case_out}/receipts/L01.txt" ; ls "#{mount_root}/etc/systemd/system" "#{mount_root}/etc/cron.d" >> "#{case_out}/receipts/L01.txt" 2>&1
  expect: this image is Linux (ext/xfs fsstat) and runs a Linux container runtime — Docker overlay2 / containerd / Podman are Linux constructs; the docker root, host systemd units and cron are where container-escape persistence and the poisoned overlay2 layers live. This category is Linux-primary because the Docker overlay2 storage driver and the runc/containerd escape surface are Linux-only
  check: |
    test -d "#{mount_root}/var/lib/docker" -o -d "#{mount_root}/var/lib/containerd" -o -d "#{mount_root}/var/lib/containers" -o -n "$(grep -iE 'ext[234]|xfs' "#{case_out}/receipts/L01.txt" 2>/dev/null)"
  falsify: fsstat reports NTFS and there is no /var/lib/docker tree — this is a Windows container host (Docker Desktop / Hyper-V isolation); the overlay2-on-disk model does not apply, use the Windows path in Cross-OS notes
  on_result: {expect_met: goto L2, falsify_met: Windows container host; overlay2 layer-diffing does not apply on disk, see Cross-OS notes and pivot disk-filesystem, neither: confirm OS family from the Step 0 fsstat/disktype receipt; if still ambiguous and a docker root exists treat as Linux and continue}
  emits: [key_artifacts]
  serves: [container-escape-to-host, malicious-overlay2-layer, runtime-container-persistence]
  provenance: {receipt_id: L01, artifact: fsstat + container-runtime dir check, offset_or_row: receipt L01 PRESENT markers, literal_cited: ext/xfs FS type or DOCKER-ROOT-PRESENT marker}

- n: L2
  precondition: "os == linux"
  tool: |
    fls -r -o #{ntfs_offset_sectors} "#{image_path}" 2>/dev/null | grep -iE "etc/cron|systemd/system|rc.local|/diff/|var/lib/docker" > "#{case_out}/receipts/L02.txt" 2>&1 ; for u in "#{mount_root}"/etc/systemd/system/*.service "#{mount_root}"/etc/cron.d/* "#{mount_root}"/etc/rc.local ; do test -f "$u" && echo "=== $u ===" >> "#{case_out}/receipts/L02.txt" && srch_strings -a "$u" 2>/dev/null | grep -iE "docker|nsenter|runc|/var/lib/docker|chroot|curl|wget|/bin/sh" >> "#{case_out}/receipts/L02.txt" 2>&1 ; done ; usnjls "#{image_path}" 2>/dev/null | head -n 5 >> "#{case_out}/receipts/L02.txt" 2>&1
  expect: a host persistence unit (systemd .service / cron / rc.local) dropped by an escaped container or a CI job — referencing docker/nsenter/runc, a host-mounted path, or a download cradle — placing the container compromise OUTSIDE the container boundary on the host itself; ties the overlay2 finding to host impact
  check: |
    grep -qiE "docker|nsenter|runc|chroot|curl|wget|/bin/sh|/diff/" "#{case_out}/receipts/L02.txt"
  falsify: no host systemd/cron/rc.local unit references a container runtime or escape primitive, and no host write traces to the docker layers — the compromise stayed inside the container, no host escape/persistence
  on_result: {expect_met: record the host persistence unit as the escape impact and IOC; commit with a confidence label, falsify_met: record no-host-escape; the case is contained to the image/layer; re-confirm via the super-timeline in step 8, neither: widen the fls search to /opt and /usr/local/bin for dropped tooling; check /root/.bash_history and authorized_keys for an escape footprint}
  emits: [key_artifacts, timeline_events]
  serves: [container-escape-to-host, runtime-container-persistence, build-cache-or-pipeline-script-poisoning]
  provenance: {receipt_id: L02, artifact: host systemd/cron/rc.local units, offset_or_row: receipt L02 unit grep hits, literal_cited: the docker/nsenter/runc reference inside a host persistence unit}

## Corroboration (two-source rule)
`required_sources: 2` · `pairs:`
- `[ poisoned layer hash (step 3/4) ↔ the extra build history step in the image config (step 2) ]`
- `[ config-digest mismatch (step 4) ↔ repositories.json tag re-point to a new digest (step 2) ]`
- `[ implant strings in the newest layer (step 5) ↔ pe-scanner/clamscan/python3-yara signature on the same file (step 6) ]`
- `[ privileged/host-mount container config (step 7) ↔ host persistence unit referencing runc/nsenter (Linux L2) ]`
- `[ layer write time (step 1 fls/mactime) ↔ fused docker super-timeline order (step 8) ]`
- `[ tampered CI lockfile/artifact hash (step 9) ↔ the poisoned layer that baked it in (step 3/4) ]`

One hit is a *lead*; promote to *fact* only when its paired source agrees.

## Don't get fooled (red flags & anti-forensics)
- **A new layer hash is NORMAL for any rebuild.** Every `docker build`/CI run produces new overlay2 layers with new hashes — a hash that differs is only suspicious when it differs from the OFFICIAL UPSTREAM digest or has no sanctioned build record. Always compare to a baseline, not to "it changed."
- **Timestomp on a planted layer file.** A dropped implant may show a backdated $SI/atime; compare `istat` $SI vs ctime and trust the overlay2 dir mtime and the docker super-timeline order over a single file's $SI.
- **Squashed/multi-stage builds hide the add.** A malicious step can be flattened so the history looks short; hash the layer BYTES (step 3) rather than trusting the `history` array, and look for an entrypoint that pulls at runtime (no on-disk payload).
- **Deleted layers / pruned images.** `docker image prune` or an attacker can remove the layer tar after the container ran — the bytes may survive in unallocated; carve with `bulk_extractor`/`tsk_recover`/`photorec`. **Missing evidence is itself a finding.**
- **Daemon log rotation/truncation.** `<id>-json.log` rotates and can be truncated to hide the pull/push and exec — a zero-length or gap-filled json log near the incident is itself a finding; corroborate with the fls/mactime layer timeline.
- **Secrets in build-args look leaked but may be squashed.** A secret in an intermediate layer that was correctly removed in a later layer is a hygiene issue, not necessarily exfil — confirm the secret survives in the FINAL image's layers before calling it a leak.
- **`latest` tag re-pointing.** repositories.json can map a familiar `repo:latest` to a brand-new malicious digest with no obvious file change — read the digest, not the tag.
- **Container UID vs host UID.** A file on the host owned by an unexpected UID can be an escape footprint (the container's root mapped to the host); check ownership against container mounts, do not assume host provenance.

## Failure modes
```
- mode: evidence-access failure — the disk won't mount or /var/lib/docker is unreadable
  guard: Step 0 fallback chain — ewfmount/loop RO, else TSK fls/icat the docker image/overlay2 inodes into #{case_out}/extracted; if all fail, record acquisition failure and pivot acquisition-custody
- mode: primary-artifact-absent — no /var/lib/docker (containerd/Podman instead), or layers pruned/deleted
  guard: record the absence as a finding; check /var/lib/containerd and /var/lib/containers; carve deleted layer tars from unallocated with bulk_extractor/tsk_recover/photorec; pivot file-recovery-carving
- mode: tool-output drift — the image config JSON schema or log2timeline docker-parser field names change so a grep/json literal misses, check exits 2
  guard: on check exit 2, adjudicate from the prose expect/falsify against the receipt and cap confidence at inferred; fall back to srch_strings over the raw config/log and grep diff_id/created_by directly, never silently pass
- mode: no known-good baseline — hash-compare in step 4 cannot run without official upstream digests
  guard: step 4 neither-branch proceeds to content-level layer inspection (steps 5-6) and labels findings inferred; pull the upstream digest from the image config's own sha256 filename for the config-digest self-check (works with no external baseline)
- mode: log2timeline docker parser absent/older build — the --parsers docker selection errors
  guard: pinfo.py confirms which parsers ran; fall back to the fls/mactime docker-root timeline (step 1) and the container json-log timestamps; record the parser gap
- mode: yara CLI absent on this box — a raw `yara` invocation would fail
  guard: ALL YARA-rule scanning runs through the python3-yara library inside pe-scanner/page-brute; never call a bare yara binary
```
Minimum set every playbook covers: evidence-access failure (Step 0 fallback chain) · primary-artifact-absent (absence recorded, secondary source named) · tool-output drift (`check` exits 2 → prose adjudication, never silent pass).

## Confidence labeling (observation → inference → conclusion)
- **confirmed:** direct receipt verbatim (e.g. a layer hash that mismatches the official upstream digest) + ≥2 independent sources agree (hash mismatch + the extra config history step, or implant strings + a python3-yara signature) + no unrefuted counter-theory.
- **inferred:** grounded but single-source/interpretive — a layer hash that merely changed with no baseline to compare, a string-level implant lead with a clean scanner, an escape config with no host-side write yet, or any `check`-exit-2 adjudication → hedge and tag `⚠️verify`.
- **insufficient_evidence:** precondition unmet (no docker root, layers pruned, no baseline AND no surviving payload) or sources conflict → abstain; state what's missing, do not guess.

<!-- BEGIN CLOSE-GATE INVARIANT — copy this block into every playbook VERBATIM, including these markers. Do not edit, summarize, or reflow; the linter byte-compares it against _TEMPLATE.md. -->
## Close-gate invariant (Done = may not be declared until ALL are true)
- [ ] **Per-modality sweep** — every modality PRESENT in the evidence was processed, and every ABSENT one was recorded as absent (absence is a finding): disk file system · memory · event logs · registry · email stores · browser profiles · cloud-sync clients.
- [ ] **Every IOC pivoted** — each hash, path, filename, IP/domain, account, extension, and mutex found was pivoted back through the other modalities and the timeline.
- [ ] **Timeline built** — a case timeline exists and the committed story is consistent with it (entry → action → impact ordering holds, no unexplained gaps).
- [ ] **Anti-forensics checked** — cleared logs, timestomp, gaps, emptied artifact dirs: each ruled out or recorded as a finding.
- [ ] **Every theory closed** — each row of "Theories to test" is refuted with a receipt or carried forward with a confidence label.

**Quick-path success does NOT waive the Done gate.** The quick path exists to find the thread fast; this gate exists to guarantee nothing present went unread. The quick path itself must include a timeline-first move before any story is committed.
<!-- END CLOSE-GATE INVARIANT -->

## Cross-OS notes
- **Linux/ESXi:** fully covered above and in the numbered L1–L2 branch — Docker overlay2, containerd, and Podman are Linux constructs; the docker root, host systemd/cron units, and runc/containerd are where layer poisoning and escape evidence live.
- **Windows:** Windows containers do NOT use overlay2; they use the WCIFS/`Windows Filter` storage layers under `C:\ProgramData\Docker\windowsfilter\` (and Hyper-V-isolated containers store a VHDX). The image config JSON model is the same, so step 2 (config/history) and step 3 (hashing the layer trees) still apply against the windowsfilter dirs; layer diffing is a directory walk, not `overlay2/<id>/diff`. Build runners on Windows (Azure DevOps/Jenkins agents) get the same step-9 artifact-hash treatment. ⚠️verify the exact windowsfilter layout per Docker version on the evidence.
- **macOS:** Docker Desktop on macOS runs Linux containers inside a `LinuxKit` VM — the overlay2 layers live in a VM disk image (`Docker.raw`/`docker.qcow2`) under the user's `~/Library/Containers/com.docker.docker/`. There is no host-native container store. Acquire and mount that VM disk, then the Linux branch applies inside it. Pivot virtualization-mobile to handle the nested VM disk.
- **Cloud:** managed registries (ECR/ACR/GCR) and managed CI (CodeBuild/Cloud Build) leave their trace in control-plane audit logs, not on a host disk — an image push or a build-config change shows in exported CloudTrail/Azure/GCP logs. Investigate from the *exported* JSON; pivot cloud-iaas-control-plane.

## Real-case notes (non-obvious things to look for)
- **A poisoned base image inherits everywhere downstream.** When a widely-used base image is backdoored, every derived image and every running container carries the malicious layer — the same bad `diff_id` appears across many images on the host. Pivot the bad layer hash across ALL imagedb configs, not just the suspect image. `[supply-chain compromise pattern / MITRE T1195.002 · high]`
- **Typosquatted / dependency-confusion packages bake in at build time.** A lockfile pointing at a malicious package (a name one character off a real one, or an internal name resolved from a public registry) shows as a single altered line in `package-lock.json`/`requirements.txt`/`go.sum`; the malicious code then lives inside a layer with no obvious "binary dropped." Hash the dependency tree against the pinned lockfile. `[MITRE T1195.001 / dependency-confusion research · high]`
- **Privileged containers and host-path mounts are the escape highway.** Most real escapes are not 0-days — they are a container run `--privileged` or with `-v /:/host` or `hostPID`, letting an attacker write straight to the host. The escape evidence is in the container `config.v2.json` HostConfig, not an exploit binary. `[container-security practice / MITRE T1611 · high]`
- **runc / CVE-class escapes leave a host write.** When an escape DOES use a runc/kernel flaw, the tell is a host file written by the container's mapped root UID at a container-start time — correlate host file ownership and mtime with the container's start in the daemon log. `[runc escape class / MITRE T1611 · med]`
- **Secrets shipped in layers are a top real finding.** Cloud keys, registry creds, and `.env` files frequently survive in an intermediate layer even when the Dockerfile "removed" them in a later step — they remain in the earlier layer's tar. Sweep every layer, not just the final filesystem. `[image-secret-leak research / MITRE T1552.001 · high]`
- **Tag re-pointing hides a trojaned push.** Pushing a malicious image to an existing `repo:latest` changes only the digest in repositories.json; the tag and most files look unchanged. Read the digest and the push time, not the tag name. `[registry abuse pattern / MITRE T1525 · med]`
- **Cryptominers ride in public images.** Opportunistic actors publish images that bundle a coinminer in a layer with mining-pool domains in the binary strings; a layer with outbound pool URLs and a high-entropy packed binary is the tell. `[cryptojacking-in-images pattern / MITRE T1610 · med]`

## ATT&CK mapping
- T1195.002 · Initial Access · Supply Chain Compromise: Compromise Software Supply Chain · poisoned/backdoored base image — steps 2/3/4
- T1195.001 · Initial Access · Supply Chain Compromise: Compromise Software Dependencies and Development Tools · tampered lockfile/package — steps 4/9
- T1525 · Persistence · Implant Internal Image · trojaned image pushed / extra malicious layer — steps 2/4/5
- T1610 · Execution/Defense Evasion · Deploy Container · malicious/coinminer image deployed — steps 5/6
- T1611 · Privilege Escalation · Escape to Host · privileged/host-mount container or runc/kernel escape — steps 7, L2
- T1612 · Defense Evasion · Build Image on Host · adversary builds a trojaned image locally to evade registry scanning — steps 8/9
- T1552.001 · Credential Access · Unsecured Credentials: Credentials In Files · secrets leaked in image layers — step 5
- T1059.004 · Execution · Unix Shell · reverse-shell/cradle dropped in a layer or CI script — steps 5/9, L2
- T1053.003 · Persistence · Scheduled Task/Job: Cron · host cron dropped by an escaped container — L2
- T1543.002 · Persistence · Create or Modify System Process: Systemd Service · host systemd unit from an escape — L2
- T1070 · Defense Evasion · Indicator Removal · pruned layers / truncated daemon log — Don't-get-fooled + Failure modes

## Pivots (lead-to-lead graph)
- `on_escape_to_host (step 7 / L2 privileged config or host persistence unit): linux-host-forensics — chase the host-side persistence, accounts, and lateral movement after the escape`
- `on_dropped_implant (step 5/6 layer binary): malware-analysis-triage — fully triage the dropped PE/ELF/webshell`
- `on_host_persistence_unit (L2 systemd/cron): linux-host-forensics — enumerate the full Linux persistence set`
- `on_layers_pruned_or_deleted (step 3 / failure mode): file-recovery-carving — carve the deleted layer tars from unallocated`
- `on_registry_push_or_cloud_build (step 2/9 cloud registry/CI): cloud-iaas-control-plane — read the control-plane push/build audit log`
- `on_full_intrusion_chain (step 8 multi-stage): attack-lifecycle-hunting — reconstruct the end-to-end pipeline-to-host intrusion and map ATT&CK`
- `on_nested_vm_docker_desktop (macOS/Win Docker Desktop): virtualization-mobile — mount and analyze the LinuxKit/Hyper-V VM disk that holds the layers`
- `on_disk_or_mount_failure (step 0): acquisition-custody — re-acquire or prove the collection gap`
- `on_new_layer_hash_to_rescope (step 4 unmatched hash): SELF — re-enter with the bad layer hash bound into #{time_window} to bracket every image and container that carries it`

## Jargon decoder
- **Container:** an isolated, lightweight process bundle that ships an app plus its dependencies; it shares the host kernel (unlike a full VM).
- **Image:** the read-only template a container is started from — a stack of file-system layers plus a config (entrypoint, env, history).
- **Layer:** one read-only file-system increment in an image; each Dockerfile step adds a layer. Stacking them (overlay) yields the container's view.
- **overlay2:** Docker's default Linux storage driver; each layer is a directory under `/var/lib/docker/overlay2/<id>/`, and the files a layer ADDED live in its `diff/` subdir.
- **diff_id / digest:** the SHA-256 of a layer's content (`diff_id`) or of an image config/layer tar (`digest`); the digest is how upstream images are identified — a mismatch means the bytes changed.
- **imagedb / image config JSON:** Docker's metadata store; each image's config (under `image/overlay2/imagedb/content/sha256/`) lists the layer `diff_id` chain, entrypoint, env, and the build `history` (the `created_by` step for each layer).
- **repositories.json:** maps each `repo:tag` to its image digest — where a re-pointed `latest` tag shows up.
- **Manifest:** the registry-side document listing an image's layers and config by digest; editing it (or the config) re-points the image at malicious bytes.
- **Container escape:** breaking out of the container's isolation to run on / write to the HOST file system — usually via a privileged/host-mounted container or a runc/kernel flaw.
- **runc / containerd:** the low-level runtime (runc) and the daemon (containerd) that actually start containers; flaws here enable escapes.
- **Privileged container / host bind mount:** a container run with full host capabilities (`--privileged`) or with a host path mounted in (`-v /:/host`) — the most common escape highway.
- **CI/CD runner:** the build machine (Jenkins agent, GitLab Runner, GitHub Actions self-hosted runner) that checks out code and produces artifacts — a prime supply-chain target.
- **Lockfile:** a pinned dependency manifest (`package-lock.json`, `go.sum`, `requirements.txt` with hashes); a changed line is how a dependency swap shows on disk.
- **Dependency confusion / typosquatting:** tricking a build into pulling a malicious package by name (an internal name resolved from a public registry, or a near-identical typo name).
- **Squashed / multi-stage build:** build techniques that flatten or drop intermediate layers — can hide a malicious step from the visible `history`, so hash the bytes.
- **Baseline (known-good):** the set of official upstream layer/image digests you compare against; "the hash changed" only matters relative to this.
- **bodyfile / mactime:** a TSK intermediate listing of file MAC times (`fls -m`) rendered into a chronological timeline (`mactime`).

## Tuning log (append-only — the eval loop writes here; humans never edit rows)
| date | case_id | bucket missed | delta applied |
|---|---|---|---|
