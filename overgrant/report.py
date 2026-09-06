import textwrap

from .evidence import Evidence
from .findings import Tier

WIDTH = 88
RULE = "=" * WIDTH
SECTION = "-" * WIDTH

LIMITATIONS = """
This report describes what the integration is permitted to do, not what it has
done. Every finding is a statement about capability. Confirming behaviour
requires observed API traffic, which this tool does not collect.

Findings labelled INFERRED were derived by this tool rather than declared by the
integration. Combination and redundancy findings rest on the hand-curated
relationships in the scope catalogue; if that curation is wrong, so is the finding.

The catalogue covers a subset of each provider's published scopes. Any granted
scope it does not describe is listed as unassessed rather than scored.

Tiers measure the reach of data access. They do not measure impersonation,
availability or billing impact - a scope that can send mail as the user but read
nothing scores low here despite being a real phishing capability.
"""


def _wrap(text, indent=""):
    return textwrap.fill(
        " ".join(text.split()),
        width=WIDTH,
        initial_indent=indent,
        subsequent_indent=indent,
        # Scope ids are single long tokens and Google's full URLs. We don't want to break them across lines, we need it greppable.
        break_long_words=False,
        break_on_hyphens=False,
    )


def _paragraphs(text, indent=""):
    blocks = [b for b in text.strip().split("\n\n") if b.strip()]
    return "\n\n".join(_wrap(block, indent) for block in blocks)


def _section(assessment) -> list:
    lines = [SECTION, f"Grant set: {assessment.label}", SECTION, ""]

    counts = {tier: 0 for tier in Tier}
    for finding in assessment.findings:
        counts[finding.tier] += 1
    summary = ", ".join(
        f"{counts[tier]} {tier.name.lower()}" for tier in sorted(Tier, reverse=True)
    )
    lines.append(
        _wrap(
            f"{len(assessment.findings)} findings across "
            f"{len(assessment.granted)} granted scopes: {summary}"
        )
    )
    lines.append("")

    for index, finding in enumerate(assessment.findings, start=1):
        lines.append(f"[{index}] {finding.tier.name}  {finding.rule}")
        lines.append(_wrap(finding.title, indent="    "))
        lines.append("")
        lines.append("    Scopes:")
        for scope_id in finding.scopes:
            lines.append(f"      {scope_id}")
        lines.append("")
        lines.append(
            _wrap(
                f"Evidence: {finding.claim.evidence.value.upper()} "
                f"(source: {finding.claim.source})",
                indent="    ",
            )
        )
        lines.append("")
        lines.append(_paragraphs(finding.detail, indent="    "))
        if finding.claim.evidence is Evidence.INFERRED:
            lines.append("")
            lines.append(_paragraphs(f"Caveat: {finding.claim.caveat}", indent="    "))
        lines.append("")

    if assessment.unrecognised:
        lines.append("    Unassessed scopes")
        lines.append("")
        lines.append(
            _wrap(
                "These scopes were granted but are not described in the catalogue, "
                "so nothing above assesses them. Their absence from the findings is "
                "not evidence that they are safe.",
                indent="    ",
            )
        )
        lines.append("")
        for scope_id in assessment.unrecognised:
            lines.append(f"      {scope_id}")
        lines.append("")

    return lines


def render_text(assessments) -> str:
    if not assessments:
        raise ValueError("render_text needs at least one assessment")

    providers = {a.provider for a in assessments}
    if len(providers) > 1:
        raise ValueError(f"assessments span multiple providers: {sorted(providers)}")

    provider = assessments[0].provider or "unknown provider"
    lines = [RULE, f"OAuth scope assessment: {provider}", RULE, ""]

    for assessment in assessments:
        lines.extend(_section(assessment))

    lines.append(RULE)
    lines.append("Limitations")
    lines.append(RULE)
    lines.append("")
    lines.append(_paragraphs(LIMITATIONS))

    return "\n".join(lines) + "\n"
