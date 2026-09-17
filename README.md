# Overgrant

Integrations declare what they may touch while traffic shows where data actually goes.
Overgrant reports where the two disagree.

## What a finding looks like

Here are two Slack scopes an app asked for. Overgrant scores them one at a time:

- `channels:history` — MEDIUM. "Read messages and events from public channels."
  Narrow in practice: the app reads only the channels a human invited it into.
- `channels:join` — MEDIUM. "Join public channels." A plain write, no data attached.

An install screen lists them as two bullets. Neither is HIGH. Neither is wrong.

Held together, the second scope removes the limit on the first. The app adds
itself to any public channel and then reads that channel's full history so the
effective reach is every public message in the workspace, arrived at one join at
a time rather than in a single obvious grant.

The danger doesn't exist in either line. It exists in the pair. And there's no
line on the install screen for the pair.

That's the gap Overgrant fills. Lint the manifest:

```console
$ overgrant scopes lint examples/notes-bot-manifest.json

[1] HIGH  combination:self-expanding-channel-read

    Scopes:
      channels:join
      channels:history

    Evidence: INFERRED (source: combination rule self-expanding-channel-read)

    Caveat: Capability, not behaviour. This says the app CAN expand its own
    reach, not that it has. Confirm against observed conversations.join calls
    before treating it as an incident.
```

That caveat matters as much as the finding. It says HIGH because the capability
is high, not because this app did anything. The tool never claims to have
watched it happen.

## Install

Python 3.11+. No dependencies.

```
git clone https://github.com/Lhod789/overgrant.git
```

```
cd overgrant
```

```
pip install .
```

## The four commands

**`scopes lint`** — assess a grant set. Takes an app manifest, a consent URL or
a plain list of scopes.

```
overgrant scopes lint examples/notes-bot-manifest.json
```

**`scopes snapshot` / `scopes diff`** — record what an integration holds in a lockfile you commit then detect drift against it. Runs as a GitHub Action on every pull request.

```
$ overgrant scopes snapshot examples/notes-bot-manifest.json -o scopes.lock.json
$ overgrant scopes diff examples/notes-bot-manifest.json --against scopes.lock.json
No changes against scopes.lock.json

# someone adds chat:write to the manifest and says nothing in the PR
$ overgrant scopes diff examples/notes-bot-manifest.json --against scopes.lock.json
bot:
  FAIL  added_escalation    chat:write
```

Exit `1` and the check goes red. `chat:write` is flagged not because it scores
highly but because it is not in the catalogue at all. An uncurated scope is
never assumed harmless.

Exit `0` for a clean run or a non-blocking change
`1` for a widening or an escalation
`2` for input it could not read and that is deliberately distinct because
"could not check" must never look like "checked, clean".

**`egress map`** — group a captured HAR by vendor.

```
overgrant egress map examples/notes-bot.synthetic.har
```

```
Capture window: 2026-01-01T00:00:00+00:00 to 2026-01-01T00:00:02+00:00 (2s)

Slack  (2 requests)
  hosts       slack.com
  path        /api/conversations.history
  path        /api/conversations.join
  detected    credential x2

UNKNOWN  (1 request)
  hosts       telemetry.notesbot.example
  path        /v1/events
  detected    credential x1, email_address x1
```

**`correlate`** — the join.

Needs a lockfile and an egress map. The map comes from the previous command:

macOS / Linux:

```
overgrant egress map examples/notes-bot.synthetic.har --format json > egress.json
```

Windows PowerShell — `>` writes UTF-16 there and the file will not parse:

```
overgrant egress map capture.har --format json | Set-Content -Encoding ascii egress.json
```

Then, on either:

```
overgrant correlate --scopes scopes.lock.json --egress egress.json
```

```
Correlating slack scopes against 2s of capture

[1] MEDIUM  over-grant
    Read files - granted to bot, never observed
    Evidence: INFERRED
    Caveat: Absence of evidence over 2s of capture (2026-01-01T00:00:00+00:00 to
    2026-01-01T00:00:02+00:00). A scope used weekly looks identical to one never
    used, at this window length.
```

## What the join produces

|                 | **Observed**                                       | **Not observed**                                                      |
| --------------- | -------------------------------------------------- | --------------------------------------------------------------------- |
| **Granted**     | Working as intended                                | **over-grant** — dead permission, tiered by what removing it buys you |
| **Not granted** | **undeclared capability** — a call no scope covers | Nothing to report                                                     |

Scope linters only see the left column and traffic tools only see the top row.

## What it deliberately does not do

See [docs/limitations.md](docs/limitations.md).

## Status

Built and tested — 104 tests, standard library `unittest`.

- Scope catalogue with risk scoring, dangerous-combination rules and redundancy
  detection (Slack, Google). To add scopes or a provider is doumented in [docs/scope-database.md](docs/scope-database.md)
- Manifest, consent URL and scope-list parsing, with shape-based provider detection
- Lockfiles, drift classification and a composite GitHub Action
- HAR ingestion, credential scrubbing, path normalisation, vendor resolution,
  and sensitive-data detection by count
- Correlation of declared scopes against observed traffic
