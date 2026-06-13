---
attack_type: linux-host-forensics
category_id: linux-host-forensics
name: Linux / Unix Host Forensics
description: Linux logons, persistence, logs, cron/systemd and file-system artifacts
version: 1
os_coverage: [windows, linux, macos, cloud]
sub_types_covered: 9
sub_types:
  - cron-systemd-rc-local-persistence
  - ssh-authorized-keys-backdoor
  - ssh-auth-log-logons
  - bash-history-command-recovery
  - package-tampering-dpkg-rpm
  - setuid-and-world-writable-files
  - webshell-on-server
  - wtmp-utmp-btmp-session-records
  - log-tampering-and-deleted-log-carving
validated_on: []
maturity: draft
variables:
  image_path:
    default: /cases/active/evidence/disk.E01
    derive: "Step 0 — first disk-evidence image (E01/dd/raw/vmdk) enumerated under the evidence directory named in the case brief"
  mount_root:
    default: /cases/active/mount
    derive: "Step 0 — directory where the Linux file system is mounted READ-ONLY (or where icat-extracted artifacts land when mounting fails)"
  case_out:
    default: /cases/active/out
    derive: "Step 0 — writable case output directory from the case brief; Step 0 creates #{case_out}/receipts/ and #{case_out}/extracted/"
  ntfs_offset_sectors:
    default: 2048
    derive: "Step 0 — start sector of the relevant partition from `mmls #{image_path}` (the largest Linux ext/xfs partition; the variable name is generic — it holds the ext/xfs offset on a Linux image)"
  time_window:
    default: 1970-01-01..2099-12-31
    derive: "case brief if it names one; else first confirmed malicious timestamp ±48h once a step pins one — then re-scope wide sweeps to it"
---

## In one line
A Linux/Unix box keeps plain-text and binary diaries of who logged in, what shell commands they ran, and which start-up jobs were planted. This playbook reads those diaries — SSH auth logs, wtmp/utmp/btmp session records, bash history, cron/systemd/rc.local autostarts, the package database, and the file-system timeline — to prove who got in, what they ran, and how they made it survive a reboot.

## Use this when (triggers)
- You need to know **who logged on** over SSH (or at the console) and from where — and whether a brute-force `Failed password` burst preceded the success.
- A Linux server is suspected compromised: a **webshell** under a web root, a process that "shouldn't be there", or beaconing traced back to this host.
- Signs of **persistence**: a new cron job, a systemd unit/timer, an `rc.local` line, or an attacker SSH key added to `~/.ssh/authorized_keys`.
- The **package database** looks tampered (a binary's hash no longer matches `dpkg`/`rpm`, or a system binary was replaced — trojanized `ls`/`sshd`).
- You want recovered **shell history** (`.bash_history`) tying an account to specific commands, or **setuid / world-writable** files dropped for privilege escalation.
- The **logs themselves look wiped** — a truncated `auth.log`, a `wtmp` with a gap, or `journal` missing a window (anti-forensics that is itself a finding).

## Quick path (the 90% case)
1. **Timeline-first.** Build a file-system timeline of the mounted Linux FS with TSK (`fls -r -m` bodyfile → `mactime`), and/or fold `/var/log` into a super-timeline with `log2timeline.py` + `psort.py` (syslog, utmp, systemd_journal, bash, dpkg parsers). Skim it inside `#{time_window}` BEFORE committing to a story — the order of logon → persistence planted → execution → log-wipe is the case.
2. **Find the entry.** Grep `auth.log`/`secure` for `Accepted password`/`Accepted publickey` (the logon = a Windows 4624 analog) and the `Failed password` bursts (= 4625) that precede a brute-forced success; confirm the session against `wtmp` with `last` / `utmpdump`.
3. **Find the foothold.** List cron (`/etc/cron*`, `/var/spool/cron`), systemd units/timers, `/etc/rc.local`, and every `~/.ssh/authorized_keys` — an attacker key or an odd cron line launching a script/shell is the persistence.
4. **Find what ran.** Recover `.bash_history` per account and grep for download/exec cradles (`curl|wget … | bash`, `nc`, `chmod +x`); scan web roots for webshell signatures and reconcile suspect binaries against `dpkg --verify` / `rpm -Va` output already on disk.
5. **Find the cover-up.** A truncated/zeroed `auth.log`, a `wtmp` gap, or a `journal` window missing is itself the finding — carve deleted log fragments out of unallocated with `srch_strings`/`bulk_extractor`.

If a logon, a persistence mechanism, an execution trace, and (if present) a tampering sign all line up on one timeline with a corroborating second source → you're mostly done. Otherwise drop into the full Steps.

## How it unfolds (the story)
An actor reaches the host — usually an SSH logon (`Accepted password`/`publickey`) after a spray of `Failed password` attempts from one IP, or by walking in through an exploited web app and dropping a **webshell** under the document root. They escalate (sudo, or a planted **setuid** binary / a writable cron'd script), then nail down persistence: an SSH key appended to `authorized_keys`, a **cron** entry, a **systemd** unit or timer, or a line in `rc.local`. They run their tooling from a shell (leaving `.bash_history` unless they unset it) and may trojanize a packaged binary (so `dpkg --verify`/`rpm -Va` flags a hash mismatch). To slow responders they truncate `auth.log`, clear `wtmp`/`btmp`, or delete journal segments — leaving a gap that is itself evidence. The whole sequence is reconstructable from the logs, the session records, the autostart locations, and the file-system timeline, each corroborated against a second source.

## Theories to test (and how to rule each out)
| Theory (who / why) | If true, you'd find… | Rule it out if… |
|---|---|---|
| **External-targeted (hands-on SSH intruder)** | `Failed password` burst then `Accepted password/publickey` from an unexpected/external IP in `auth.log`; a matching `wtmp` session via `last`; a new `authorized_keys` entry or cron/systemd unit minutes later; `.bash_history` with recon/download commands | No remote logon, no failure burst, no new key/cron/unit, no post-logon command history |
| **Other-insider (stolen credentials / key)** | Valid account `Accepted publickey` from an unusual source IP or odd hour; the key fingerprint not previously seen for that user; same account writes a webshell or cron job | Logon source, key, and hours match the account's own baseline; no anomalous origin or new key |
| **Insider (authorized admin acting maliciously)** | Console/`tty` logon or sudo by a real admin; tools run from their home; persistence added under their UID with no remote origin | Account was logged in remotely from outside, or its key was proven stolen → reclassify other-insider |
| **Web-app compromise (no logon at all)** | A **webshell** under the web root owned by `www-data`/`apache`, web-server access log hitting it, child processes spawned by the web server — but **no** SSH `Accepted` line | The suspicious file is a legitimate app component (matches the package/repo), or there is a real SSH logon that explains the activity instead |
| **Supply-chain / package tampering** | `dpkg --verify`/`rpm -Va` flags a core binary's checksum changed; the binary's `$MFT`-analog (inode) ctime is recent and out of band; the same trojanized binary appears fleet-wide | The flagged file is an expected local config edit (`/etc/...` 5-mismatch is normal), or a legitimate vendor update explains the changed hash and time |
| **Innocent / benign (NOT an attack)** | Cron jobs and systemd timers created by the distro/package manager; `authorized_keys` entries that match known admin keys; an `auth.log` rotation (not a wipe); all activity by expected accounts in business hours | A sanctioned change-control record explains the cron/unit/key AND the logon account + source are expected → benign cause confirmed; reclassify |

*(≥1 benign + ≥1 malicious, each ACTIVELY refuted. Attacker types mapped: insider · other-insider · external-commodity · external-targeted · supply-chain · innocent.)*

## Evidence → Tool → What it reveals (per OS)
| Evidence | SIFT tool | What it tells you *for this attack* | OS |
|---|---|---|---|
| `/var/log/auth.log` · `/var/log/secure` (SSH `Accepted`/`Failed password`, `sudo`, `session opened`) | `log2timeline.py` (syslog parser) + `psort.py`; `srch_strings`/grep | Who logged on over SSH, from which IP, by password or key; brute-force bursts; sudo escalation | Linux |
| `/var/log/wtmp` · `/var/run/utmp` · `/var/log/btmp` (login/active/bad-login session records) | `last` / `lastb` / `utmpdump`; `log2timeline.py` (utmp parser) | Confirmed login sessions, durations, source hosts (corroborates `auth.log`); `btmp` = failed logins; a gap = wipe | Linux |
| `~/.bash_history` (and `.zsh_history`, `.python_history`) | `fls`/`icat` to recover, then `srch_strings`/grep | The exact shell commands an account ran — download cradles, `chmod +x`, recon — tying an actor to actions | Linux |
| Cron: `/etc/crontab` · `/etc/cron.d/*` · `/etc/cron.{daily,hourly}` · `/var/spool/cron/*` | `fls`/`icat`/`mactime`; `srch_strings`/grep | Scheduled persistence — a cron line launching a script/shell/curl-cradle, with its file create/modify time on the timeline | Linux |
| systemd: `/etc/systemd/system/*.{service,timer}` · `/lib/systemd/system/*` · `[Service] ExecStart=` | `fls`/`icat`/`mactime`; `srch_strings`/grep | Service/timer persistence — a unit whose `ExecStart` runs an attacker binary; recently-created units stand out on the FS timeline | Linux |
| `/etc/rc.local`, `~/.bashrc`/`~/.profile`, `/etc/profile.d/*` | `icat`/`srch_strings` | Legacy/shell-init persistence — a command appended to run at boot or login | Linux |
| `~/.ssh/authorized_keys` (per user, incl. `/root`) | `fls`/`icat`/`mactime` | Attacker-added public keys = passwordless persistence; key comment/fingerprint and the file mtime are the IOC | Linux |
| `/var/lib/dpkg/info/*.md5sums` · the RPM database (`/var/lib/rpm`) | `dpkg --verify` / `rpm -Va` (run against the mounted root); `md5deep`/`sha256deep` for ad-hoc hashing | Package tampering — a system binary whose on-disk checksum no longer matches what the package manager recorded (trojanized binary) | Linux |
| File system metadata (ext/xfs inodes, ctime/mtime/atime) | `fls -r -m` → `mactime`; `istat`; `tsk_gettimes` | The MACB timeline; **setuid** bits and **world-writable** files; an inode `ctime` that betrays a recently planted/replaced file even when mtime was backdated | Linux |
| ext3/ext4 journal | `jls` / `jcat` | Recent FS transactions just before capture — file ops an attacker performed moments ago | Linux |
| Web roots (`/var/www`, app dirs): `.php`/`.jsp`/`.aspx` with eval/exec | `srch_strings`/grep for webshell signatures; `page-brute`/`pe-scanner` (both back onto python3-yara) for rule scans; `clamscan` | A **webshell** — `eval($_POST[...])`, `system(`, `passthru(`, base64 blob — dropped under the document root | Linux |
| Unallocated space / deleted logs | `srch_strings` · `bulk_extractor` · `blkls` · `tsk_recover` · `photorec` | Carved fragments of a truncated/deleted `auth.log`/`wtmp`/`.bash_history`; IPs, URLs, command fragments spilled outside the live files | Linux |
| `/var/log/journal/*` (binary systemd journal) | `log2timeline.py` (systemd_journal parser) + `psort.py` | Systemd-era equivalent of syslog — logons, unit starts, sudo — when text logs are sparse or absent | Linux |
| All artifacts fused | `log2timeline.py` + `psort.py` (+ `pinfo.py`) | One chronology placing logon → persistence → execution → tampering in order | all |
| Linux RAM image (if captured) | `vol` (Volatility 3 `linux.*`) | Live rogue process, hidden module, network residue — **ONLY if a matching ISF symbol pack exists** (none bundled; see precondition + `⚠️verify`) | Linux |
| auditd `audit.log` (if syscall auditing was on) | text grep only (`srch_strings`/grep `type=EXECVE`) — **no `ausearch`/`aureport` on this box (absent)** | `execve` of attacker tooling and file writes, read as raw text — `⚠️verify` (no parser to normalize it) | Linux |

*Linux memory analysis in `vol` needs a per-kernel ISF symbol table — **0 are bundled on this box** (`dwarf2json` + the target's debug kernel must build one off-box). Treat any `vol linux.*` step as `⚠️verify` and gate it behind a precondition that the pack exists.*

## Step 0 — evidence inventory & access bootstrap
- n: 0
  tool: |
    mkdir -p "#{case_out}/receipts" "#{case_out}/extracted" && ls -laR "#{mount_root}" > "#{case_out}/receipts/00.txt" 2>&1 ; img_stat "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; mmls "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; fsstat -o #{ntfs_offset_sectors} "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; for d in etc/passwd var/log/auth.log var/log/secure var/log/wtmp var/log/journal etc/crontab etc/systemd/system var/www; do ls -la "#{mount_root}/$d" >> "#{case_out}/receipts/00.txt" 2>&1 ; done
  expect: every evidence file classified; #{image_path}, #{mount_root}, #{ntfs_offset_sectors}, #{case_out} bound; read-only access proven; fsstat reports an ext/xfs Linux file system and the key Linux trees (/etc/passwd, /var/log, cron/systemd, /var/www) are enumerated, or their absence is recorded
  check: |
    test -r "#{mount_root}" -o -n "$(ls "#{case_out}/extracted" 2>/dev/null)"
  falsify: evidence dir empty/unreadable, or no supported image format found, or fsstat reports NTFS/HFS+ (this is not a Linux image — see the OS-confirm branch)
  on_result: {expect_met: goto 1, falsify_met: STOP — report acquisition/access failure; pivot acquisition-custody, neither: try the icat-extract fallback (fls to find the /etc, /var/log, cron and authorized_keys inodes, icat each into #{case_out}/extracted); if that also fails, treat as falsify_met}
  emits: [key_artifacts]
  serves: [cron-systemd-rc-local-persistence, ssh-authorized-keys-backdoor, ssh-auth-log-logons, bash-history-command-recovery, package-tampering-dpkg-rpm, setuid-and-world-writable-files, webshell-on-server, wtmp-utmp-btmp-session-records, log-tampering-and-deleted-log-carving]
  provenance: {receipt_id: 00, artifact: evidence directory listing + Linux tree enumeration, offset_or_row: full listing, literal_cited: image filename + fsstat File System Type line}

## Steps (executable — decision-driven)
- n: 1
  precondition: "test -r #{mount_root}"
  tool: |
    log2timeline.py --status_view none --parsers "syslog,utmp,systemd_journal,bash_history,dpkg" "#{case_out}/linux.plaso" "#{mount_root}/var/log" > "#{case_out}/receipts/01.txt" 2>&1 ; psort.py -o l2tcsv "#{case_out}/linux.plaso" > "#{case_out}/super.csv" 2>> "#{case_out}/receipts/01.txt" ; pinfo.py "#{case_out}/linux.plaso" >> "#{case_out}/receipts/01.txt" 2>&1 ; fls -r -m / -o #{ntfs_offset_sectors} "#{image_path}" > "#{case_out}/fs.body" 2>> "#{case_out}/receipts/01.txt" ; mactime -b "#{case_out}/fs.body" -d >> "#{case_out}/receipts/01.txt" 2>&1
  expect: a single sorted super-timeline (#{case_out}/super.csv) over /var/log plus a file-system MACB bodyfile (#{case_out}/fs.body) — the timeline-first artifacts every later step filters; pinfo confirms the syslog/utmp/systemd_journal/bash/dpkg parsers ran
  check: |
    test -s "#{case_out}/super.csv" -o -s "#{case_out}/fs.body"
  falsify: /var/log is empty or unparseable AND fls returns no entries (wrong offset, encrypted, or wiped FS) — no timeline can be built from this image
  on_result: {expect_met: goto 2, falsify_met: re-derive #{ntfs_offset_sectors} from the mmls receipt; if the FS is encrypted/LUKS record that and pivot acquisition-custody, neither: fall back to per-artifact srch_strings/grep over the extracted logs; if logs are truly absent record absence as a finding and continue to step 5 (deleted-log carving)}
  emits: [timeline_events]
  serves: [ssh-auth-log-logons, cron-systemd-rc-local-persistence, package-tampering-dpkg-rpm]
  provenance: {receipt_id: 01, artifact: /var/log/* + ext/xfs file system, offset_or_row: super.csv header + row count / fs.body line count, literal_cited: pinfo parser list + mactime first/last timestamp}

- n: 2
  precondition: "exists #{case_out}/super.csv"
  tool: |
    grep -iE "Accepted (password|publickey)|Failed password|session opened|sudo:|new session" "#{case_out}/super.csv" > "#{case_out}/receipts/02.txt" 2>&1 ; for f in auth.log secure btmp; do srch_strings "#{mount_root}/var/log/$f" 2>/dev/null | grep -iE "Accepted|Failed password|sudo|invalid user" >> "#{case_out}/receipts/02.txt" 2>&1 ; done ; utmpdump "#{mount_root}/var/log/wtmp" >> "#{case_out}/receipts/02.txt" 2>&1 ; last -aiwF -f "#{mount_root}/var/log/wtmp" >> "#{case_out}/receipts/02.txt" 2>&1 ; lastb -aiwF -f "#{mount_root}/var/log/btmp" >> "#{case_out}/receipts/02.txt" 2>&1
  expect: SSH `Accepted password`/`Accepted publickey` lines naming the account + source IP (the logon = 4624 analog), ideally preceded by a `Failed password` burst from that same IP (brute-force = 4625), and a matching login session in `wtmp` via `last`/`utmpdump`, inside #{time_window}
  check: |
    grep -qiE "Accepted (password|publickey)|Failed password" "#{case_out}/receipts/02.txt"
  falsify: no `Accepted`/`Failed password` anywhere AND `wtmp`/`btmp` empty (SSH logging off, logs wiped, or entry was not via SSH) — logon not evidenced in the auth logs
  on_result: {expect_met: record account + source IP + auth method (password/key); goto 3, falsify_met: if auth.log is truncated/zeroed treat the gap as a finding and lean on wtmp/journal/web logs — if entry looks web-based (no logon) skip to step 6 (webshell), neither: widen #{time_window}; parse /var/log/journal with the systemd_journal parser (step 1 covers it) and re-grep; check for non-default SSH log paths}
  emits: [actor_accounts, timeline_events]
  serves: [ssh-auth-log-logons, wtmp-utmp-btmp-session-records]
  provenance: {receipt_id: 02, artifact: /var/log/auth.log + wtmp/btmp, offset_or_row: super.csv/grep auth rows + utmpdump session lines, literal_cited: "Accepted password for <user> from <ip>" + matching wtmp session}

- n: 3
  precondition: "test -r #{mount_root}"
  tool: |
    for u in "#{mount_root}/root/.ssh/authorized_keys" "#{mount_root}"/home/*/.ssh/authorized_keys; do echo "== $u ==" >> "#{case_out}/receipts/03.txt" ; srch_strings "$u" >> "#{case_out}/receipts/03.txt" 2>/dev/null ; istat -o #{ntfs_offset_sectors} "#{image_path}" "$(ifind -o #{ntfs_offset_sectors} -n "${u#"#{mount_root}"}" "#{image_path}" 2>/dev/null)" >> "#{case_out}/receipts/03.txt" 2>&1 ; done ; for k in "#{mount_root}"/root/.ssh/authorized_keys "#{mount_root}"/home/*/.ssh/authorized_keys ; do ls -la "$k" >> "#{case_out}/receipts/03.txt" 2>&1 ; done
  expect: an `authorized_keys` entry whose key comment/fingerprint is not a known admin key, on an account that should not have one, with a file mtime/ctime inside #{time_window} (passwordless persistence); ideally the same source/user as the step-2 logon
  check: |
    grep -qiE "ssh-(rsa|ed25519|dss)|ecdsa-sha2" "#{case_out}/receipts/03.txt"
  falsify: every authorized_keys entry matches a known/expected admin key with an old, pre-incident mtime — no attacker key was added (key-based persistence not evidenced)
  on_result: {expect_met: record the key comment/fingerprint + owning account as an IOC; goto 4, falsify_met: record "no rogue SSH key"; continue to other persistence at goto 4, neither: compare each key fingerprint against the org's known-good set; if a user has no prior key history at all, flag the file's recent ctime and hold at inferred}
  emits: [key_iocs, actor_accounts]
  serves: [ssh-authorized-keys-backdoor]
  provenance: {receipt_id: 03, artifact: ~/.ssh/authorized_keys (per user + root), offset_or_row: authorized_keys line + istat ctime/mtime, literal_cited: "the ssh-<type> key body + comment and its mtime"}

- n: 4
  precondition: "test -r #{mount_root}"
  tool: |
    for p in etc/crontab etc/cron.d etc/cron.daily etc/cron.hourly etc/cron.weekly var/spool/cron etc/rc.local etc/profile.d ; do echo "== $p ==" >> "#{case_out}/receipts/04.txt" ; ls -laR "#{mount_root}/$p" >> "#{case_out}/receipts/04.txt" 2>&1 ; grep -rIiE "curl|wget|/tmp/|/dev/shm|bash -i|nc |ncat|base64 -d|\.sh|python" "#{mount_root}/$p" >> "#{case_out}/receipts/04.txt" 2>&1 ; done ; for s in etc/systemd/system lib/systemd/system usr/lib/systemd/system ; do find "#{mount_root}/$s" -maxdepth 2 -name "*.service" -o -name "*.timer" 2>/dev/null | while read -r unit; do echo "== $unit ==" >> "#{case_out}/receipts/04.txt" ; grep -iE "ExecStart|ExecStartPre|WorkingDirectory" "$unit" >> "#{case_out}/receipts/04.txt" 2>&1 ; done ; done
  expect: a cron entry, a systemd `.service`/`.timer` `ExecStart`, or an `rc.local`/`profile.d` line that launches a script/shell/curl-cradle from a suspicious path (`/tmp`, `/dev/shm`, a user home, a hidden dir), with a create/modify time near the step-2 logon — the persistence mechanism
  check: |
    grep -qiE "ExecStart|curl|wget|/tmp/|/dev/shm|bash -i|base64 -d|@reboot" "#{case_out}/receipts/04.txt"
  falsify: every cron job, systemd unit and rc.local line is a known distro/package entry with an expected path and an old mtime — no scheduled/boot persistence on this host
  on_result: {expect_met: record the cron line / unit ExecStart / rc.local command as an IOC; goto 5, falsify_met: record "no cron/systemd/rc.local persistence"; check authorized_keys (step 3) and any LD_PRELOAD/ld.so.preload as alternatives; goto 5, neither: cross-check each unit/cron file's mtime against the FS timeline (step 1) and flag any created inside #{time_window}; widen the search to ~/.config/systemd/user}
  emits: [key_iocs, timeline_events]
  serves: [cron-systemd-rc-local-persistence]
  provenance: {receipt_id: 04, artifact: cron dirs / systemd units / rc.local, offset_or_row: matching cron line or unit ExecStart line, literal_cited: "the @reboot/cron command or ExecStart= target path"}

- n: 5
  precondition: "test -r #{mount_root}"
  tool: |
    for h in "#{mount_root}"/root/.bash_history "#{mount_root}"/home/*/.bash_history "#{mount_root}"/root/.zsh_history "#{mount_root}"/home/*/.zsh_history ; do echo "== $h ==" >> "#{case_out}/receipts/05.txt" ; srch_strings "$h" 2>/dev/null >> "#{case_out}/receipts/05.txt" ; done ; grep -iE "curl|wget|chmod \+x|nc |ncat|/tmp/|base64|wget .*\| ?(bash|sh)|useradd|passwd |unset HISTFILE|history -c" "#{case_out}/receipts/05.txt" > "#{case_out}/receipts/05_flagged.txt" 2>&1
  expect: recovered shell history lines tying an account to attacker actions — a download cradle (`curl|wget … | bash`), `chmod +x` on a dropped file, account creation (`useradd`), or `unset HISTFILE`/`history -c` (an attempt to NOT leave history, itself a tell), inside #{time_window}
  check: |
    test -s "#{case_out}/receipts/05_flagged.txt"
  falsify: bash_history files are empty/absent for the actor account (cleared, or shell was non-interactive) AND no suspicious command recovered — execution not evidenced in shell history
  on_result: {expect_met: record the commands + any dropped paths/URLs as IOCs; goto 6, falsify_met: history likely cleared (note `unset HISTFILE`/empty file as a finding); corroborate execution via the FS timeline (step 1) and journal exec records; carve deleted history from unallocated (step 8), neither: recover deleted .bash_history copies via fls/icat of the inode and re-grep; check .python_history and web-server error logs for spawned commands}
  emits: [key_iocs, timeline_events]
  serves: [bash-history-command-recovery]
  provenance: {receipt_id: 05, artifact: ~/.bash_history (per user + root), offset_or_row: flagged history lines, literal_cited: "the exact download/exec command line"}

- n: 6
  precondition: "test -r #{mount_root}"
  tool: |
    for w in var/www srv/www usr/share/nginx opt/lampp/htdocs var/www/html ; do find "#{mount_root}/$w" -type f \( -iname "*.php" -o -iname "*.jsp" -o -iname "*.jspx" -o -iname "*.aspx" -o -iname "*.phtml" \) 2>/dev/null | while read -r f; do if grep -liE "eval\(|assert\(|system\(|passthru\(|shell_exec|base64_decode\(|\\\$_(POST|GET|REQUEST)\[|FromBase64String|Runtime\.getRuntime" "$f" >/dev/null 2>&1; then echo "== WEBSHELL? $f ==" >> "#{case_out}/receipts/06.txt" ; grep -inE "eval\(|assert\(|system\(|passthru\(|shell_exec|base64_decode\(|\\\$_(POST|GET|REQUEST)\[" "$f" >> "#{case_out}/receipts/06.txt" 2>&1 ; ls -la "$f" >> "#{case_out}/receipts/06.txt" 2>&1 ; fi ; done ; done ; clamscan -r --infected "#{mount_root}/$w" >> "#{case_out}/receipts/06.txt" 2>&1
  expect: a web-root script containing a webshell signature (`eval($_POST[...])`, `system(`, `passthru(`, a `base64_decode(` blob) owned by `www-data`/`apache`, with a recent mtime and ideally a hit in the web access log — a server-side foothold needing no SSH logon
  check: |
    grep -qiE "WEBSHELL\?|eval\(|passthru\(|shell_exec|base64_decode\(|FOUND" "#{case_out}/receipts/06.txt"
  falsify: every web-root script matches the application's own/repo code (no injected eval/exec, expected mtime) AND clamscan finds nothing — no webshell on this server
  on_result: {expect_met: record the webshell path + signature + owner as an IOC; goto 7, falsify_met: record "no webshell"; if this host is web-facing pivot web-server-compromise for the exploited service; goto 7, neither: scan the same roots with page-brute/pe-scanner (python3-yara-backed) using webshell rules; correlate any hit with the web access log timestamp}
  emits: [key_iocs, key_artifacts]
  serves: [webshell-on-server]
  provenance: {receipt_id: 06, artifact: web document root (php/jsp/aspx), offset_or_row: matched line in the script + ls -la mtime/owner, literal_cited: "the eval/system/base64_decode webshell line"}

- n: 7
  precondition: "test -r #{mount_root}"
  tool: |
    dpkg --root "#{mount_root}" --verify > "#{case_out}/receipts/07.txt" 2>&1 ; rpm --root "#{mount_root}" -Va >> "#{case_out}/receipts/07.txt" 2>&1 ; find "#{mount_root}" -xdev -type f -perm -4000 -printf "SUID %M %u %p\n" >> "#{case_out}/receipts/07.txt" 2>&1 ; find "#{mount_root}" -xdev -type f -perm -2000 -printf "SGID %M %u %p\n" >> "#{case_out}/receipts/07.txt" 2>&1 ; find "#{mount_root}" -xdev -type f -perm -0002 ! -type l -printf "WW %M %u %p\n" >> "#{case_out}/receipts/07.txt" 2>&1 ; sha256deep -r "#{mount_root}/usr/bin" >> "#{case_out}/receipts/07.txt" 2>&1
  expect: a `dpkg --verify`/`rpm -Va` line flagging a packaged binary whose on-disk checksum changed (`5` = MD5 mismatch on a file that is not a config) — a trojanized system binary; and/or an unexpected **setuid** binary or a **world-writable** file in a sensitive path planted for privilege escalation, with a recent ctime
  check: |
    grep -qE "^..5|^SUID|^SGID|^WW |missing" "#{case_out}/receipts/07.txt"
  falsify: dpkg/rpm report only expected `c`-config (`/etc/...`) mismatches, and every setuid/world-writable file is a standard distro binary (`/usr/bin/sudo`, `passwd`) with a stock checksum — no package tampering or rogue privileged file
  on_result: {expect_met: record the tampered binary / rogue setuid file path + hash as an IOC; goto 8, falsify_met: record "package DB and setuid set intact"; goto 8, neither: hash the flagged binary with sha256deep and compare to a clean reference of the same package version; check the inode ctime via istat — a recent ctime with an old mtime = timestomp; pivot malware-analysis-triage to triage the binary}
  emits: [key_iocs, key_artifacts]
  serves: [package-tampering-dpkg-rpm, setuid-and-world-writable-files]
  provenance: {receipt_id: 07, artifact: dpkg/rpm verify output + setuid/world-writable find, offset_or_row: the verify line / find line, literal_cited: "the dpkg/rpm mismatch line or the SUID/WW file path"}

- n: 8
  precondition: "test -r #{mount_root}"
  tool: |
    for L in var/log/auth.log var/log/secure var/log/wtmp var/log/btmp ; do echo "== $L ==" >> "#{case_out}/receipts/08.txt" ; ls -la "#{mount_root}/$L" >> "#{case_out}/receipts/08.txt" 2>&1 ; done ; blkls -o #{ntfs_offset_sectors} "#{image_path}" > "#{case_out}/extracted/unalloc.blkls" 2>> "#{case_out}/receipts/08.txt" ; srch_strings "#{case_out}/extracted/unalloc.blkls" | grep -iE "Accepted password|Failed password|sshd|sudo:|\.bash_history|HISTFILE" > "#{case_out}/extracted/carved_logs.txt" 2>> "#{case_out}/receipts/08.txt" ; bulk_extractor -o "#{case_out}/extracted/bulk" "#{image_path}" >> "#{case_out}/receipts/08.txt" 2>&1 ; wc -l "#{case_out}/extracted/carved_logs.txt" >> "#{case_out}/receipts/08.txt" 2>&1
  expect: a truncated/zeroed `auth.log` (size 0 or far smaller than rotation would explain) or a `wtmp` gap, PLUS carved fragments of the deleted log lines from unallocated (`srch_strings`/`bulk_extractor`) that the live file no longer holds — proving deliberate log tampering and recovering what was hidden, inside #{time_window}
  check: |
    test -s "#{case_out}/extracted/carved_logs.txt" || grep -qiE "log|wtmp|auth" "#{case_out}/receipts/08.txt"
  falsify: live `auth.log`/`wtmp` are continuous and consistent with rotation, and no contradicting log lines surface from unallocated — no evidence of log wiping
  on_result: {expect_met: record log-tampering as a high-signal finding and fold the carved lines back into the timeline (step 1); close per the gate, falsify_met: record "logs continuous, no wipe"; close per the gate, neither: compare each log's size/mtime against /var/log rotation siblings (.1/.gz); a live file newer than its .1 but smaller is suspicious — flag and hold at inferred}
  emits: [key_artifacts, timeline_events]
  serves: [log-tampering-and-deleted-log-carving, wtmp-utmp-btmp-session-records]
  provenance: {receipt_id: 08, artifact: /var/log live files + unallocated carve, offset_or_row: ls -la sizes + carved_logs.txt lines, literal_cited: "the zero/short auth.log size or a carved Accepted/Failed line absent from the live file"}

## Linux branch (L1..Ln) — REQUIRED, numbered, same step shape
*This playbook is Linux-primary; the numbered Steps 1–8 above already carry the Linux investigation. This branch's L1 machine-confirms the evidence really is Linux (so the precondition gates above are honest), and L2 reaches for Linux RAM only when an ISF symbol pack genuinely matches the captured kernel.*
- n: L1
  precondition: "os == linux"
  tool: |
    fsstat -o #{ntfs_offset_sectors} "#{image_path}" > "#{case_out}/receipts/L01.txt" 2>&1 ; ls -la "#{mount_root}/etc/os-release" "#{mount_root}/etc/passwd" "#{mount_root}/var/log" >> "#{case_out}/receipts/L01.txt" 2>&1 ; srch_strings "#{mount_root}/etc/os-release" >> "#{case_out}/receipts/L01.txt" 2>&1
  expect: fsstat reports an ext2/3/4 or xfs file system AND /etc/passwd + /var/log + /etc/os-release are present — this is a Linux/Unix host, so the main Steps 1–8 apply (Windows EVTX/ETW and macOS unified logs do NOT exist here); record "Linux-confirmed" with the distro from os-release
  check: |
    test -e "#{mount_root}/etc/passwd" -o -n "$(grep -iE 'ext[234]|xfs|file system type' "#{case_out}/receipts/L01.txt" 2>/dev/null)"
  falsify: fsstat reports NTFS/exFAT (Windows) or HFS+/APFS (macOS) and no /etc/passwd exists — this evidence is NOT Linux; this playbook does not apply (X-only because the artifacts are an OS this category does not cover)
  on_result: {expect_met: goto L2, falsify_met: wrong-OS image — record "non-Linux evidence, linux-host-forensics does not apply" and pivot windows-event-logs (if NTFS) or macos-forensics (if HFS+/APFS), neither: re-confirm OS family from the Step 0 fsstat/disktype receipt; if still ambiguous treat as non-Linux and stop this playbook}
  emits: [key_artifacts]
  serves: [ssh-auth-log-logons]
  provenance: {receipt_id: L01, artifact: fsstat output + /etc/passwd + /etc/os-release, offset_or_row: fsstat File System Type line + os-release PRETTY_NAME, literal_cited: "ext/xfs FS type and the os-release distro string (Linux-confirmed)"}

- n: L2
  precondition: "os == linux; exists #{case_out}/symbols_isf_present"
  tool: |
    vol -f "#{image_path}" -s "#{case_out}/symbols" linux.pslist > "#{case_out}/receipts/L02.txt" 2>&1 ; vol -f "#{image_path}" -s "#{case_out}/symbols" linux.lsmod >> "#{case_out}/receipts/L02.txt" 2>&1 ; vol -f "#{image_path}" -s "#{case_out}/symbols" linux.bash >> "#{case_out}/receipts/L02.txt" 2>&1
  expect: with a matching per-kernel ISF symbol pack present (the precondition), Volatility3 `linux.pslist`/`linux.lsmod`/`linux.bash` show a rogue process, a hidden/unexpected kernel module, or in-RAM bash history corroborating the disk findings — ⚠️verify the pack truly matches the captured kernel version
  check: |
    grep -qiE "PID|Offset|Module|Command" "#{case_out}/receipts/L02.txt"
  falsify: vol errors with "no suitable symbols" / "unsatisfied requirement" — NO ISF pack matches this kernel (0 are bundled on this box), so Linux memory cannot be parsed here; the disk-based Steps 1–8 stand alone
  on_result: {expect_met: record the rogue process/module as an IOC and corroborate against the disk persistence (steps 4/7); commit with confidence label, falsify_met: record "Linux memory unavailable — no matching ISF symbol pack (⚠️verify, build via dwarf2json off-box)"; rely on disk Steps 1–8, neither: confirm the kernel/banner via vol banners or strings on the image; if a pack can be built off-box, do so and retry; else treat as falsify_met}
  emits: [key_iocs, timeline_events]
  serves: [cron-systemd-rc-local-persistence, bash-history-command-recovery]
  provenance: {receipt_id: L02, artifact: Linux RAM image (if captured) + ISF symbols, offset_or_row: linux.pslist/lsmod/bash rows, literal_cited: "the rogue PID/process name or hidden module — or the 'no suitable symbols' error"}

## Corroboration (two-source rule)
`required_sources: 2` · `pairs:`
- `[ auth.log "Accepted password/publickey" (step 2) ↔ matching wtmp login session via last/utmpdump (step 2) ]`
- `[ Failed password burst (step 2) ↔ the following Accepted from the same source IP (step 2) ]`
- `[ rogue authorized_keys entry (step 3) ↔ the file's recent ctime/mtime on the FS timeline (steps 1/3) ]`
- `[ cron/systemd persistence (step 4) ↔ the unit/cron file create time on the FS timeline (step 1) ]`
- `[ .bash_history download/exec line (step 5) ↔ the dropped file's create time + presence in $MFT-analog / cron (steps 1/4/7) ]`
- `[ webshell signature (step 6) ↔ the web access-log hit and the file's www-data ownership/mtime (step 6) ]`
- `[ dpkg/rpm checksum mismatch (step 7) ↔ the binary's inode ctime anomaly via istat (steps 1/7) ]`
- `[ truncated/zeroed log (step 8) ↔ the carved log line from unallocated absent from the live file (step 8) ]`

One hit is a *lead*; promote to *fact* only when its paired source agrees.

## Don't get fooled (red flags & anti-forensics)
- **Cleared history is itself a finding.** An empty `.bash_history`, an `unset HISTFILE`, or `history -c` in any recovered fragment means the operator tried to leave no trace — don't read the silence as "they ran nothing". Carve deleted history from unallocated and lean on the FS timeline and journal.
- **A truncated or zeroed `auth.log`/`wtmp` is tampering, not absence.** Compare each live log to its rotated siblings (`.1`, `.gz`): a live file that is *newer but smaller* than its `.1` has been re-written. A `wtmp`/`utmp` gap (a logout with no matching login, or vice-versa) is a wipe — `utmpdump` exposes the broken record sequence.
- **`mtime`/`atime` are trivially forged; trust `ctime` and the inode.** `touch -t` backdates mtime/atime but NOT the inode `ctime` (changed only by metadata ops you can't easily fake from userland). An old mtime with a recent ctime on a persistence file = timestomp. Use `istat`, not just `ls`.
- **Package-verify `5`/config noise.** `dpkg --verify`/`rpm -Va` flag `/etc/...` config files routinely (a `c`/`5` on a config you edited is normal). The finding is a **non-config** binary in `/bin`,`/usr/bin`,`/sbin` with a checksum mismatch — a trojanized binary — not a tweaked config.
- **A webshell can masquerade as a benign app file.** Attackers name it `index.php`, `wp-config-sample.php`, `style.php`, or append a one-line eval to a real file. Owner = `www-data`/`apache`, a recent mtime out of step with the rest of the app, and an `eval`/`base64_decode($_POST)` body are the tells — diff against the app's own repo/package.
- **No SSH logon does NOT mean no intrusion.** Web-app compromise leaves no `Accepted` line — the entry is in the web access log and the foothold is the webshell. Absence of an auth-log logon should push you to the web roots, not to "benign".
- **LD_PRELOAD / `/etc/ld.so.preload` and SUID rootkits hide execution.** A library injected via `ld.so.preload` or a setuid backdoor won't show in cron/systemd; check that file and the setuid set explicitly.
- **Distrust host time around destructive activity.** If the timeline is internally impossible, anchor to the ext journal (`jls`) transaction order and to log-line sequence rather than file mtimes. **Missing evidence is itself a finding.**

## Failure modes
```
- mode: evidence-access failure — the disk won't mount or /var/log and /home are unreadable
  guard: Step 0 fallback chain — ewfmount/loop RO, else TSK fls/icat the /etc, /var/log, cron and authorized_keys inodes into #{case_out}/extracted; if all fail, record acquisition failure and pivot acquisition-custody
- mode: primary-artifact-absent — auth.log/secure or wtmp missing, empty, or zero-length (cleared or never collected)
  guard: record the absence as a finding (it IS evidence of clearing); name the secondary sources (wtmp/btmp via last/lastb, the systemd journal, web access logs, carved fragments from unallocated) and continue — never read absence as "nothing happened"
- mode: tool-output drift — log2timeline parser names or psort CSV columns change, or a field breaks a grep literal so check exits 2
  guard: on check exit 2, adjudicate from the prose expect/falsify against the receipt, cap confidence at inferred; fall back to raw srch_strings/grep over the extracted log files directly, never silently pass
- mode: auditd audit.log present but no parser — ausearch/aureport are ABSENT on this box
  guard: read audit.log as TEXT only (srch_strings/grep for `type=EXECVE`/`type=SYSCALL`); tag every audit.log-derived claim ⚠️verify since nothing normalizes it
- mode: Linux memory image present but Volatility3 linux.* fails — 0 ISF symbol packs are bundled
  guard: gate L2 behind the symbols-present precondition; on "no suitable symbols" record the gap (⚠️verify, build via dwarf2json off-box) and rely on the disk Steps 1–8; do not fabricate a memory finding
- mode: encrypted/LUKS root or unknown FS — fls/fsstat return nothing
  guard: record the encrypted volume as a finding; attempt decryption only with a provided key off the evidence; otherwise pivot acquisition-custody
```
Minimum set every playbook covers: evidence-access failure (Step 0 fallback chain) · primary-artifact-absent (absence recorded, secondary source named) · tool-output drift (`check` exits 2 → prose adjudication, never silent pass).

## Confidence labeling (observation → inference → conclusion)
- **confirmed:** direct receipt verbatim (e.g. the `Accepted password for <user> from <ip>` line) + ≥2 independent sources agree (auth.log + wtmp session, or persistence file + its FS-timeline ctime) + no unrefuted counter-theory.
- **inferred:** grounded but single-source/interpretive — e.g. an authorized_keys entry with no confirmed logon yet, a webshell with no access-log corroboration, a recent ctime read as timestomp, or any `vol linux.*` result whose ISF pack match is unverified → hedge and tag `⚠️verify`. Every `check`-exit-2 adjudication lands here at best.
- **insufficient_evidence:** precondition unmet (logs absent; no ISF symbol pack; auditd unparsed) or sources conflict → abstain; state what's missing, do not guess.

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
- **Linux/Unix:** fully covered above — this is the primary OS. SSH `auth.log`/`secure`, `wtmp`/`utmp`/`btmp`, `.bash_history`, cron/systemd/rc.local, `authorized_keys`, the dpkg/rpm database, and the ext/xfs FS timeline are the richest sources. ESXi/appliance Linux follows the same shape (shell history + `/var/log` + crontab), though some appliances strip the package DB.
- **Windows (cross-OS note):** the same attack class maps to a different artifact set — there is no `auth.log`/`wtmp`/cron/dpkg. The analogs are: SSH/RDP logons → Security `4624`/`4625`; persistence → services `7045`, scheduled tasks `4698`/TaskScheduler Operational, Run keys, WMI subscriptions (registry, not cron); "package tampering" → an unsigned/replaced system binary checked via `MFTECmd` $SI/$FN + Authenticode, not `dpkg`. If the image is NTFS, this playbook does not apply — pivot **windows-event-logs** / **windows-registry-persistence** (the L1 check machine-confirms the OS first).
- **macOS:** logons live in the Unified Log (`.tracev3`) and ASL; persistence is LaunchAgents/LaunchDaemons plists and login items, not cron/systemd. This box has **no working Unified-Log parser** (`⚠️verify` — degraded). Pivot **macos-forensics**.
- **Cloud:** a Linux VM's control-plane actions (key-pair add, security-group change) live in the provider audit log (CloudTrail/Azure/GCP), not on the host. This box has **no dedicated cloud-log parser** (`⚠️verify`) — investigate from exported JSON by grepping with `bstrings`/`srch_strings`. Pivot **cloud-identity-saas** / **cloud-iaas-control-plane**.

## Real-case notes (non-obvious things to look for)
- **`ctime` beats `mtime` for catching planted files.** `touch -t` backdates a dropped backdoor's mtime/atime to blend in, but the inode `ctime` (metadata-change time) is far harder to forge from userland and still reflects the real drop time — `istat`/`fls` expose the disagreement. Always read `ctime`, not just `ls -l`. `[general Linux DFIR / TSK istat semantics · high]`
- **A `wtmp`/`utmp` gap with no matching wipe event is the loud finding.** Operators run `> /var/log/wtmp` or selectively edit it; `utmpdump` reveals a broken record sequence (a logout with no login, or a frozen "still logged in") that `last` alone may hide. `[utmpdump / wtmp record-structure docs · high]`
- **Webshells hide as one-liners appended to legitimate app files.** Beyond standalone `c99`/`r57` shells, attackers append `<?php @eval($_POST['x']); ?>` to a real `index.php`/`functions.php`; the file's mtime jumps out of step with its neighbours and the eval body is the tell. Diff the web root against the app's package/repo, don't just look for new files. `[MITRE T1505.003 / web-server IR practice · high]`
- **SSH key persistence survives password rotation and is easy to miss.** A single line appended to `/root/.ssh/authorized_keys` (or a new `~/.ssh/authorized_keys` for a service account that never had one) gives passwordless re-entry; the key comment often carries the attacker's username/host. Check EVERY user's file including system accounts, and the file's mtime. `[MITRE T1098.004 · high]`
- **Package-verify catches trojanized binaries — but you must build a clean reference.** `dpkg --verify`/`rpm -Va` flag a changed `/usr/sbin/sshd` or `/bin/ls`, yet the local DB itself can be edited; corroborate by hashing the suspect binary (`sha256deep`) against a pristine copy of the exact package version pulled off-box. `[MITRE T1554 / T1574 supply-chain practice · med]`
- **Cron and systemd both hide persistence; check `@reboot` and `.timer` units, not just `crontab -l`.** A `@reboot` line in `/etc/cron.d/`, a user crontab under `/var/spool/cron/`, or a systemd `.timer` paired with a `.service` whose `ExecStart` is a `/tmp` or `/dev/shm` script are classic footholds that a casual `crontab -l` on the live box would miss. `[MITRE T1053.003 / T1543.002 · high]`
- **Linux memory forensics is gated on a per-kernel symbol pack — empty ≠ clean.** Volatility3 `linux.*` cannot parse a RAM image without an ISF built from the *exact* kernel's debug symbols (`dwarf2json`); none ship on this box, so a failed `vol` run means "unparsed", not "no rogue process". Build the ISF off-box on a matching kernel before relying on memory. `⚠️verify any linux.* result.` `[Volatility3 Linux symbol-table docs · high]`

## ATT&CK mapping
- T1078 · Valid Accounts · SSH `Accepted password/publickey` with stolen/valid creds — step 2
- T1110 · Credential Access · Brute Force · `Failed password` burst → `Accepted` — step 2
- T1021.004 · Lateral Movement · SSH · inbound SSH logon from another internal host — step 2
- T1098.004 · Persistence · SSH Authorized Keys · attacker key appended to `authorized_keys` — step 3
- T1053.003 · Persistence/Execution · Scheduled Task/Job: Cron · cron entry / `@reboot` — step 4
- T1543.002 · Persistence · Create or Modify System Process: systemd Service · `.service`/`.timer` `ExecStart` — step 4
- T1037.004 · Persistence · Boot or Logon Init Scripts: rc.local / profile.d — step 4
- T1059.004 · Execution · Unix Shell · download/exec cradles in `.bash_history` — step 5
- T1070.003 · Defense Evasion · Clear Command History · `unset HISTFILE` / `history -c` / emptied `.bash_history` — step 5
- T1505.003 · Persistence · Server Software Component: Web Shell · eval/exec script under the web root — step 6
- T1554 · Persistence · Compromise Host Software Binary · trojanized packaged binary (dpkg/rpm mismatch) — step 7
- T1548.001 · Privilege Escalation · Setuid and Setgid · unexpected setuid/setgid binary — step 7
- T1222.002 · Defense Evasion · Linux File and Directory Permissions Modification · world-writable sensitive file — step 7
- T1070.002 · Defense Evasion · Clear Linux or Mac System Logs · truncated/zeroed `auth.log` / `wtmp` gap — step 8
- T1070.006 · Defense Evasion · Timestomp · backdated mtime vs recent ctime on a persistence file — steps 3/7
- T1014 · Defense Evasion · Rootkit · `ld.so.preload` / hidden kernel module (Linux memory) — step L2

## Pivots (lead-to-lead graph)
- `on_web_entry_no_logon (step 2/6 webshell, no Accepted line): web-server-compromise — investigate the exploited internet-facing service`
- `on_ssh_lateral_from_peer (step 2 inbound SSH from an internal host): attack-lifecycle-hunting — reconstruct the multi-host hop chain`
- `on_credential_or_key_persistence (step 3 rogue authorized_keys): active-directory-domain — if this is a domain-joined Linux host or the key maps to a directory account`
- `on_dropped_or_trojanized_binary (step 5/7 payload path / package mismatch): malware-analysis-triage — triage the dropped/replaced binary`
- `on_package_tamper_fleetwide (step 7 same binary across hosts): containers-supply-chain — chase the poisoned package/image up the supply chain`
- `on_log_wipe_or_gap (step 8 truncated auth.log / wtmp gap): SELF — re-enter with the wipe timestamp bound into #{time_window} to bracket what was hidden`
- `on_memory_image_present (step L2 Linux RAM): memory-forensics — full volatile-memory triage once an ISF pack is built`
- `on_logs_absent_or_unmountable (step 0/1): acquisition-custody — re-acquire or prove the collection gap`

## Jargon decoder
- **`auth.log` / `secure`:** the SSH/PAM authentication log (`auth.log` on Debian/Ubuntu, `secure` on RHEL); `Accepted password`/`publickey` = a successful logon, `Failed password` = a failure.
- **wtmp / utmp / btmp:** binary session-record files — `wtmp` = login/logout history (read with `last`), `utmp` = who is logged in *now*, `btmp` = bad/failed logins (read with `lastb`). `utmpdump` prints them as text.
- **`.bash_history`:** the per-user shell-command history file; the Linux execution-evidence analog of Windows UserAssist.
- **cron:** the time-based job scheduler — system crontabs (`/etc/crontab`, `/etc/cron.d`) and per-user (`/var/spool/cron`); `@reboot` runs a job at every boot (a persistence trick).
- **systemd unit / timer:** the modern init system's job definitions — a `.service` (a daemon, `ExecStart=` runs it) and a `.timer` (schedules a service) are the systemd-era persistence locations.
- **rc.local:** a legacy boot script (`/etc/rc.local`) whose lines run at startup — a classic place to plant a persistent command.
- **authorized_keys:** `~/.ssh/authorized_keys` lists the public keys allowed to log in as that user without a password; an appended attacker key = passwordless backdoor.
- **dpkg / rpm verify:** `dpkg --verify` (Debian) / `rpm -Va` (RHEL) compare installed files against the package manager's recorded checksums; a `5` flag = the file's MD5 changed (possible trojanized binary).
- **setuid / setgid:** a permission bit (`-perm -4000`/`-2000`) that runs a binary as its owner (often root) regardless of who launches it — an unexpected one is a privilege-escalation backdoor.
- **world-writable:** a file any user can modify (`-perm -0002`); a world-writable script in a privileged path is an escalation foothold.
- **webshell:** a script (PHP/JSP/ASPX) dropped under a web root that executes attacker commands via the web server (`eval($_POST[...])`, `system(`), needing no shell logon.
- **ctime vs mtime:** `mtime` = content last modified (forgeable with `touch`); `ctime` = inode metadata last changed (much harder to forge) — disagreement hints at **timestomp**.
- **inode / istat:** the ext/xfs metadata record for a file; `istat` prints its MACB times and data location — the Linux analog of an `$MFT` entry.
- **ext journal / `jls`:** the ext3/ext4 file-system journal of recent transactions; `jls`/`jcat` read it to see file ops just before capture.
- **ISF symbol pack:** the per-kernel Intermediate Symbol Format table Volatility3 needs to parse a Linux RAM image — built off-box with `dwarf2json`; without it `vol linux.*` cannot run.
- **auditd / `audit.log`:** the Linux kernel audit log (`type=EXECVE`/`type=SYSCALL` records); on this box it has **no parser** (`ausearch`/`aureport` absent) — read it as plain text only.
- **LD_PRELOAD / `ld.so.preload`:** a mechanism to force a shared library to load into every process — abused to hook syscalls and hide files/processes (a userland rootkit).
- **Super-timeline:** one merged chronology across many artifacts, built with `log2timeline.py` + `psort.py`.

## Tuning log (append-only — the eval loop writes here; humans never edit rows)
| date | case_id | bucket missed | delta applied |
|---|---|---|---|
