# SMTP Relay Sender

An **educational proof-of-concept** SMTP client, written while solving a
hands-on Active Directory training lab (**"FoughtServ"**). In that lab, the
path to root required abusing a misconfigured **open SMTP relay**: an
internal automated user would open links sent from a specific address found
in on-host correspondence. This tool sends a message through such a relay,
substituting a link into the body — a classic **phishing-simulation delivery
vector**.

## Purpose & scope

This project demonstrates — and helps defenders detect — the risk of an
unauthenticated (open relay) SMTP server combined with a link-clicking user.

It is intended **solely for authorized environments**: CTF platforms,
training labs, and systems you own or have explicit written permission to
test. Do **not** send email to anyone without their consent, and never use
this against real users or third-party infrastructure. The author accepts no
responsibility for misuse.

## What this tool does — and does not do

- **Does:** send an email through an SMTP server (including open-relay, i.e.
  no authentication), read the body from a file, substitute a `{hta_url}`
  placeholder, render HTML, and preview the full MIME message with
  `--dry-run`. It includes basic safety checks (config-file permission
  checks, TLS policy enforcement, warnings against passing passwords on the
  command line).
- **Does not:** generate, host, or contain any payload. The `{hta_url}`
  field is just a link placed in the message body. No HTA dropper, no C2
  agent, and no EDR-evasion code are part of this repository — by design.

The delivery payload and post-exploitation tradecraft from the original lab
are **not** published here; only the mail-delivery vector and its mitigations
are.

## Usage

```bash
# Preview the full message without sending anything
python3 send/email_send.py -c send/config.ini --dry-run

# Send (authorized lab only)
python3 send/email_send.py -c send/config.ini
```

Key options: `-t/--to`, `-s/--subject`, `--url` (value for `{hta_url}`),
`--server`, `--from`, `--tls` / `--ssl`, `--ask-password`, `--dry-run`.
All target/domain values live in `send/config.ini` — the committed values are
placeholders (`example.local`, RFC1918 addresses).

## Detection & mitigation (defender view)

- **Close the open relay:** require SMTP AUTH; restrict relaying to known
  hosts/networks; disable anonymous relay.
- Enforce **SPF / DKIM / DMARC** so spoofed internal senders are rejected.
- Block or sandbox **`.hta` / `mshta`** execution via application control
  (WDAC / AppLocker); strip active-content links at the mail gateway.
- User-awareness training against "urgent security update" lures.
- Monitor for outbound SMTP from unexpected hosts and for `mshta.exe`
  spawning shells.

## Context

Part of my offensive-security learning. This PoC corresponds to the
**FoughtServ** lab write-up in my private Obsidian knowledge base, along with
research notes on HTA-based delivery and detection. For educational use only;
all committed configuration values are placeholders.
