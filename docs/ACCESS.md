# Access & Infrastructure

## Hosts

| Host | Role | Address |
|------|------|---------|
| josh | Dev, orchestration, git — all editing and version control | local |
| sift-vm | Eval execution — Claude Code with Protocol SIFT skills + Braintrust | `10.104.28.103` |

## SSH Access

```bash
ssh ubuntu@10.104.28.103
```

Key-based authentication. If no key is present:

```bash
ssh-copy-id ubuntu@10.104.28.103
```

## sift-vm Environment

- **Claude Code**: installed (see connectivity check below for PATH details)
- **Protocol SIFT**: global CLAUDE.md and skills loaded into `~/.claude/`
- **Braintrust SDK**: installed; `BRAINTRUST_API_KEY` must be set in environment
- **Prompt tracing**: enabled
- **Evidence**: `/home/ubuntu/Downloads/` containing:
  - `SRL-2015/`
  - `SRL-2018/`
  - `Standard-Forensic-Case-2/`
  - `Standard-Forensic_Case/`
- **Evidence mutability**: writable home dir, no ro bind-mount; integrity enforced by A6 (deny-regex over Bash commands + per-run `hashdeep -a -k hashes.txt -r /home/ubuntu/Downloads`). Optional hardening TODO: ro bind-mount at `/mnt/evidence`.

## Connectivity Check (Task 6)

Command run:

```
ssh -o BatchMode=yes -o ConnectTimeout=5 ubuntu@10.104.28.103 'echo ok && which claude && ls ~/.claude/skills 2>/dev/null'
```

Verbatim output:

```
ok
```

Exit code: `1`

Interpretation: SSH key auth succeeded and `echo ok` ran. `which claude` returned non-zero — `claude` is not in the default `$PATH` for non-interactive SSH sessions on sift-vm (it may be installed under a user-local path such as `~/.local/bin` or via `nvm`/`fnm`). The `ls ~/.claude/skills` command was not reached due to `&&` short-circuit.

Remediation if needed: add Claude Code's install directory to `PATH` in `~/.bashrc` or `~/.profile`, then re-run the connectivity check.

## Hygiene Rules

1. **Answer-key denylist** (`dataset/answer_key_denylist.txt`) must be finalized (paths confirmed or files deleted from sift-vm) **before** manifest generation.
2. **manifest.txt** (`find /home/ubuntu/Downloads -type f`, absolute paths) and **hashes.txt** (`hashdeep -r /home/ubuntu/Downloads`, absolute paths) are regenerated only when evidence changes — never during an eval run.
3. **Evals never run on josh** — all `claude -p` execution happens on sift-vm only.
4. Answer-key files should be deleted from sift-vm before any eval run; the denylist is the authoritative record of their former presence.
