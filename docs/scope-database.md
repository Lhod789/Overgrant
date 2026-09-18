# The scope database

How to add scopes or a whole provider to `overgrant/data/`

Every judgement this tool makes lives in the catalogue. The surrounding code
only compares numbers and formats the result so correctness rests entirely on
hand-written data. A wrong entry does not crash anything instead it produces a
confident, well-formatted finding that is false which is worse.

## Where things live

```
overgrant/data/<provider>.toml    one file per provider; the filename is the
                                  provider name used by --provider and
                                  detected automatically
overgrant/reference/vendors.toml  host -> vendor, for the egress map only
```

Anything ending in `.toml` in `data/` is discovered as a provider and parsed as
a scope catalogue. Do not put other kinds of data there.

## A scope entry

```toml
[[scopes]]
id = "channels:history"
short = "Read channel history"
grants = "Read messages and events from public channels"
breadth = "resource"
mutability = "read"
sensitivity = "content"
data_classes = ["messages"]
endpoints = ["conversations.history", "conversations.replies"]
supersedes = []
admin_consent = false
source = "https://api.slack.com/scopes/channels%3Ahistory"
notes = ""
```

### The three axes

Ascending in each case. Pick the highest value the scope can reach, not the
typical case.

| `breadth`   |                                                 |
| ----------- | ----------------------------------------------- |
| `self`      | The installing identity only                    |
| `resource`  | Specific resources it was granted or invited to |
| `workspace` | Everything in the tenant                        |
| `org_admin` | Across tenants or administrative control        |

| `mutability` |                                       |
| ------------ | ------------------------------------- |
| `read`       |                                       |
| `write`      | Create or modify                      |
| `delete`     | Destroy                               |
| `admin`      | Change permissions, roles or settings |

| `sensitivity` |                                          |
| ------------- | ---------------------------------------- |
| `none`        | No data                                  |
| `metadata`    | Names, ids, timestamps                   |
| `content`     | The substance of messages, files or mail |
| `credentials` | Tokens, keys, secrets                    |

### `data_classes`

A fixed vocabulary. Anything outside it fails on load:

```
messages, direct_messages, mailbox, email_address, files, calendar_events,
contacts, profiles, directory, credentials, audit_logs
```

Extending the vocabulary is a code change in `overgrant/risk.py` and it needs a
reason as two scoring rules key off these sets (`IDENTIFIES_PEOPLE`,
`PRIVATE_CORRESPONDENCE`) so a new class that nothing reads changes no findings.

### `endpoints`

Bare API method names, not paths. `conversations.join`, never
`/api/conversations.join`.

Matching an observed path is a suffix check. A stored path bakes in today's URL
layout and when the provider changes it the match stops firing **silently**. The report says "never observed" and someone concludes the scope is unused.

This field is what makes `correlate` possible. A scope with no endpoints is
invisible to correlation.

## Curation rules

These are the four rules for writing a catalogue entry

### `grants` descrbes the worst it allows

Write what the scope permits at its widest reasonable reading in the provider's
own terms. Do not narrow it to how the integration in front of you happens to
use it.

The report is read by someone deciding whether to approve access. Understating
reach removes their reason to say no.

### Ambiguity goes in `notes`

Provider documentation is frequently vague. When it is, say so in `notes` rather
than picking an interpretation and scoring it.

A narrow guess recorded as fact is indistinguishable from a researched answer
once it is in the file. `notes` survives into `scopes explain`, so the next
person sees the uncertainty instead of inheriting your assumption.

### `source` is the provider's own documentation

An `https://` link to the provider. Enforced on load so a missing or non-HTTPS
source fails the test suite.

Not a blog post, not a Stack Overflow answer, not an LLM summary.

### `supersedes` is curated conservatively

List a narrower scope only when holding this one genuinely satisfies every use
of it.

Direction matters: the **broader** scope lists the narrower ones. `drive`
supersedes `drive.readonly`, never the reverse.

Get this backwards and two things break at once. Redundancy findings tell someone to delete a scope they still need. And drift classification reads this field, so you either get fake "BROADENED" alarms for changes that widened nothing, or worse, real widening goes unreported on exactly the integrations holding the most access.

When unsure, leave it out. A missing relationship costs a finding. A wrong one
produces a false one.

## Combinations

A combination says these scopes are individually okay but dangerous
together.

```toml
[[combinations]]
id = "self-expanding-channel-read"
requires = ["channels:join", "channels:history"]
tier = "high"
rationale = """
Why each scope is unremarkable alone and what holding both actually enables.
"""
caveat = """
Capability, not behaviour. What would have to be observed to confirm it.
"""
```

`caveat` is mandatory and enforced on load. A combination is an inference the
tool made, not something the integration declared, so it renders as `INFERRED`
and cannot exist without stating what it does not know.

Write the `rationale` for someone who will read it in isolation, pasted into a
ticket with no surrounding context.

## What is validated on load

A malformed entry fails `python -m unittest discover -s tests -t .` — every
catalogue in `data/` is loaded and validated by the suite, so you will hit these
before review does.

Scopes:

- duplicate `id` within a file
- `source` missing or not starting with `https://`
- a `data_classes` value outside the fixed vocabulary
- `sensitivity = "content"` with an empty `data_classes`
- `supersedes` naming a scope not in the file
- `supersedes` naming itself
- `breadth`, `mutability`, `sensitivity` outside their enums

Combinations:

- missing or empty `caveat`
- fewer than two scopes in `requires` a combination of one is just a scope
  so score it with a rule instead
- `requires` naming a scope not in the file

## Adding a new provider

1. Create `overgrant/data/<provider>.toml`. The filename becomes the provider
   name.
2. Add scopes. Start with the ones that actually get requested not the full
   published list. A small honest catalogue beats a large guessed one, and
   anything absent is reported as unassessed rather than assumed safe.
3. Check `overgrant/inputs.py` recognises the shape of the provider's scope
   strings. Detection is on shape, scored proportionally; a provider whose
   scopes look like nothing known will be refused rather than guessed at.
4. Add the provider's hosts to `overgrant/reference/vendors.toml` so the egress
   map can name them.
5. Add a test in `tests/` asserting one scope scores the tier you expect and
   one combination fires. `tests/test_google_catalogue.py` is the model.
6. Run the suite.

## Before opening a pull request

- The suite passes.
- Every new scope has an `https://` source you have actually opened.
- Every `supersedes` entry is one you would defend in review.
- Anything you were unsure about is in `notes` rather than silently resolved.
