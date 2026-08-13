"""Render a report as a single self-contained HTML file.

An incident report gets forwarded, pasted into a ticket, and read by someone who
was not at the keyboard, so it must survive being a lone file: no stylesheet to
fetch, no script to run, no font to download. What it shows is ordered the way a
responder acts — what to rotate first, then the timeline it rests on, then every
caveat that limits the conclusion.
"""
from __future__ import annotations

from html import escape

from .grading import Grade
from .org import OrgReport

GRADE_COLOR = {
    Grade.CONFIRMED: "#b3261e",
    Grade.LIKELY: "#a15c00",
    Grade.POSSIBLE: "#5b5b5b",
    Grade.NO_EVIDENCE: "#1b6b3a",
}

STYLE = """\
:root { color-scheme: light dark; }
body { font: 15px/1.6 ui-sans-serif, system-ui, sans-serif; margin: 0 auto;
       max-width: 60rem; padding: 2rem 1.25rem 4rem; }
h1 { font-size: 1.5rem; margin: 0 0 .25rem; }
h2 { font-size: 1.1rem; margin: 2rem 0 .5rem; }
.sub { color: #666; margin: 0 0 1.5rem; }
table { border-collapse: collapse; width: 100%; font-size: .93rem; }
th, td { text-align: left; padding: .45rem .6rem; border-bottom: 1px solid #8883;
         vertical-align: top; }
th { font-weight: 600; }
code { font: .88em ui-monospace, monospace; }
.grade { font-weight: 700; font-size: .78rem; letter-spacing: .02em; }
.evidence { color: #666; font-size: .85rem; }
.banner { padding: .7rem .9rem; border-left: 4px solid; margin: 0 0 1.25rem;
          background: #8881; }
ul { margin: .3rem 0; padding-left: 1.2rem; }
li { margin: .15rem 0; }
"""


def _grade(grade: Grade) -> str:
    return (f'<span class="grade" style="color:{GRADE_COLOR[grade]}">'
            f'{escape(grade.value)}</span>')


def render_html(report: OrgReport, advisory=None) -> str:
    """One file a responder can forward as-is."""
    items = report.rotation_items
    banner_color = GRADE_COLOR[report.worst_grade]
    # Green is reserved for a proven all-clear. A scan that found nothing but could
    # not look everywhere is grey: the colour is read before the sentence.
    if not report.proves_absence and report.worst_grade is Grade.NO_EVIDENCE:
        banner_color = GRADE_COLOR[Grade.POSSIBLE]
    unnamed = report.unnamed_rotations
    # Both halves of the list, because a count of the credentials that could be
    # named reads as the whole job when another repository's could not be.
    claims = []
    if items:
        claims.append(f"{len(items)} credential(s) to rotate")
    if report.unnamed_repos:
        broad = report.unnamed_repos
        claims.append(f"{len(broad)} repositor{'y' if len(broad) == 1 else 'ies'} "
                      "to rotate broadly — credentials at risk could not be named")
    headline = ", ".join(claims) if claims else "no credential to rotate"
    if not report.proves_absence:
        headline += " — this scan cannot prove absence of exposure"

    out = [
        "<!doctype html><html lang='en'><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<title>deptrail — {escape(report.advisory_id)}</title>",
        f"<style>{STYLE}</style>",
        f"<h1>{escape(report.advisory_name)}</h1>",
        f"<p class='sub'>advisory <code>{escape(report.advisory_id)}</code> · "
        f"{report.repos_scanned} repositor{'y' if report.repos_scanned == 1 else 'ies'} "
        f"scanned · worst grade {_grade(report.worst_grade)}</p>",
        f"<p class='banner' style='border-color:{banner_color}'>{escape(headline)}</p>",
    ]

    if advisory is not None:
        window = (f"{advisory.window[0]:%Y-%m-%d %H:%M %Z} → "
                  f"{advisory.window[1]:%Y-%m-%d %H:%M %Z}")
        sources = " · ".join(escape(s) for s in advisory.sources)
        out.append(
            "<h2>Advisory</h2><p class='sub'>installable window "
            f"<strong>{escape(window)}</strong> · coverage "
            f"{escape(advisory.coverage)} · packages "
            + ", ".join(f"<code>{escape(p.name)}</code>" for p in advisory.packages)
            + f"<br>{sources}</p>"
        )

    out.append("<h2>Rotate</h2>")
    if items:
        out.append("<table><tr><th>Repository</th><th>Secret</th><th>Grade</th>"
                   "<th>Scope</th><th>Why</th></tr>")
        for item in items:
            runs = (f" <span class='evidence'>(run "
                    f"{escape(', '.join(item.run_ids))})</span>" if item.run_ids else "")
            out.append(
                f"<tr><td>{escape(item.repo)}</td>"
                f"<td><code>{escape(item.secret)}</code></td>"
                f"<td>{_grade(item.grade)}</td>"
                f"<td>{escape(item.scope.value)}</td>"
                f"<td>{escape(item.reason)}{runs}</td></tr>"
            )
        out.append("</table>")
    if unnamed:
        # After the table, never instead of it: the `elif` that used to stand here
        # hid this list whenever some other repository named a credential.
        out.append("<p>Credentials are at risk but could not be named:</p><ul>")
        out += [f"<li>{escape(n)}</li>" for n in unnamed]
        out.append("</ul>")
    if not items and not unnamed:
        out.append("<p>Nothing.</p>")

    installed = [e for e in report.timeline if e.probably_installed]
    out.append("<h2>Timeline</h2>")
    if installed:
        out.append("<table><tr><th>When</th><th>Repository</th><th>Package</th>"
                   "<th>Grade</th><th>Evidence</th></tr>")
        for entry in installed:
            until = (entry.exposure.until.strftime("%Y-%m-%d %H:%M")
                     if entry.exposure.until else "still pinned")
            facts = "".join(f"<li>{escape(fact)}</li>" for fact in entry.evidence)
            out.append(
                f"<tr><td>{entry.exposure.since:%Y-%m-%d %H:%M}<br>"
                f"<span class='evidence'>→ {escape(until)}</span></td>"
                f"<td>{escape(entry.repo)}</td>"
                f"<td><code>{escape(entry.package)}@{escape(entry.exposure.version)}</code>"
                f"<br><span class='evidence'>{escape(entry.exposure.lockfile_path)}<br>"
                f"{escape(' → '.join(entry.exposure.chain))}</span></td>"
                f"<td>{_grade(entry.grade)}</td>"
                f"<td><ul>{facts}</ul></td></tr>"
            )
        out.append("</table>")
    elif report.unread or report.incomplete:
        out.append("<p>No exposure found in what could be read — see the sections "
                   "below for what could not be.</p>")
    else:
        out.append("<p>No exposure found in a tree a workflow would install.</p>")

    if report.set_aside:
        out.append("<h2>Set aside</h2>"
                   "<p class='sub'>Fixture or example trees — findings kept visible, "
                   "but no workflow installs them.</p><ul>")
        for entry in report.set_aside:
            out.append(f"<li>{escape(entry.repo)}: <code>"
                       f"{escape(entry.package)}@{escape(entry.exposure.version)}</code> "
                       f"in <code>{escape(entry.exposure.lockfile_path)}</code></li>")
        out.append("</ul>")

    if report.errors:
        out.append("<h2>Could not scan</h2><ul>")
        out += [f"<li>{escape(e)}</li>" for e in report.errors]
        out.append("</ul>")

    if report.transient:
        out.append("<h2>Could not run</h2><p class='sub'>These failed for reasons that "
                   "are not evidence — a missing tool, a failed call. Retrying may "
                   "help.</p><ul>")
        out += [f"<li>{escape(t)}</li>" for t in report.transient]
        out.append("</ul>")

    if report.incomplete:
        out.append("<h2>Incomplete view</h2><p class='sub'>This clone holds less than "
                   "the repository does, so absence could not be established. A deeper "
                   "clone would say more.</p><ul>")
        out += [f"<li>{escape(i)}</li>" for i in report.incomplete]
        out.append("</ul>")

    if report.unread:
        out.append("<h2>Not judged</h2><p class='sub'>No lockfile this tool can read, "
                   "so these trees were neither cleared nor implicated.</p><ul>")
        out += [f"<li>{escape(u)}</li>" for u in report.unread]
        out.append("</ul>")

    caveats = report.caveats
    if caveats:
        out.append("<h2>Caveats</h2><ul>")
        out += [f"<li>{escape(c)}</li>" for c in caveats]
        out.append("</ul>")

    out.append("<p class='sub'>Generated by deptrail — grades cite the evidence they "
               "rest on; POSSIBLE means an install was neither shown nor ruled out.</p>")
    out.append("</html>")
    return "\n".join(out)
