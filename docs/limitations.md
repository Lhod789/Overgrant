# Limitations

Read this before acting on a finding.

The short version: overgrant reports **capability** and **observation**. It does
not report intent, trustworthiness or proof.

## The capture window

`correlate` reports a scope as an over-grant when nothing in the capture
exercised it. That is not the same as unused.

A scope called once a week produces exactly the same evidence as a scope never
called across a capture shorter than a week and no window length makes this
stop being true, only less likely.

Every over-grant finding is labelled `INFERRED` and carries the window duration
in its caveat for this reason. A finding read without its caveat is being read
wrong.

**Do not** treat an over-grant as authorisation to revoke. Treat it as a reason
to ask the owner why the scope is held.

## Catalogue coverage

The catalogue describes a subset of each provider's published scopes. Slack has
roughly 200; this catalogue has three.

A granted scope the catalogue does not describe is reported as **unassessed**,
never omitted. An absent line and a line assessed as harmless are
indistinguishable to a reader so nothing is dropped silently.

Unassessed means nobody has looked. It does not mean safe.

The same applies to `egress map`: a host not in the vendor list resolves to
`UNKNOWN` rather than being guessed at. `UNKNOWN` is a prompt to investigate, not
a verdict.

## Curation dependence

Three kinds of finding rest entirely on hand-written data:

- **Combinations** — the pairs of scopes that are dangerous together exist
  because someone wrote the rule. An undiscovered dangerous pair produces no
  finding at all, and the report will look clean.
- **Redundancy** — depends on `supersedes` being recorded correctly.
- **Drift classification** — `BROADENED` versus `NARROWED` is decided by
  `supersedes`. Recorded backwards, the two swap, and the worst case is the
  quiet one: combinations stop firing for exactly the integrations holding the
  most access.

If the curation is wrong, the finding is wrong. There is no mechanism here that
would catch that.

## What the tiers do not measure

Tiers measure the **reach of data access**: how much, how sensitive, how
mutable. They do not measure:

- **Impersonation.** `gmail.send` scores LOW. It reads nothing. It is also a
  complete phishing capability, sending mail as the user from the user's own
  account.
- **Availability.** A scope that can delete or lock resources is scored on what
  it can read, not on what it can destroy.
- **Billing.** A scope that can provision paid resources scores on data reach
  alone.

A LOW finding is not a safe finding. It is a finding that is low on this one
axis.

## Detectors are heuristics

The egress detectors match shapes in text. Detections are counts, never values. The classes that hold them have no field capable of carrying the matched text.

They produce false positives: a string shaped like a phone number is reported as
one. They produce false negatives: an encoded, compressed or unusually formatted
secret is not matched and silence from a detector is not evidence of absence.

A detection is a reason to look at the request. It is not proof that data left.

## Provider detection is a guess

When no `--provider` is given, the provider is inferred from the shape of the
scope strings, scored proportionally across the set. Fewer than half matching any
known shape is a refusal rather than a guess because a wrong catalogue produces
a report that is fluent, detailed and entirely fictional.

The inferred provider is stated in the report header. Check it.

## Path normalisation loses detail

Identifier-shaped path segments collapse to `:id` so that a thousand calls become
one row. The matching is deliberately narrow, covering only UUIDs, long hex
strings and pure numbers because over-collapsing merges distinct endpoints into
one line and hides the outlier the map exists to surface.

The cost is that provider-specific identifier formats are not recognised and
appear uncollapsed. That makes reports longer which is the failure mode chosen
on purpose.

## What it deliberately does not do

- **No API calls.** It reads manifests, consent URLs and exported captures.
  Nothing authenticates, nothing is queried live.
- **No traffic interception.** HAR and mitmproxy exports only: no root, no CA
  installation, no liability for intercepting anyone's traffic. The captures it
  reads were produced by someone else and it inherits whatever is missing from
  them.
- **No trustworthiness judgements.** It has no opinion on whether a vendor
  deserves the access it holds.

## Consistency with the report footer

Every report carries a shortened version of this document in its `Limitations`
section. The two must not drift apart.

If you change a limit here, change `LIMITATIONS` in `overgrant/report.py` in the
same commit.
