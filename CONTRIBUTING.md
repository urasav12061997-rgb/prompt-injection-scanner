# Contributing

Thanks for wanting to improve this scanner. New patterns are the most
valuable contribution, and the bar is deliberately low.

## Add a new pattern

Most PRs should add exactly one detection pattern. The steps:

1. **Add a minimal reproducible sample** to `examples/` showing the
   attack in its most compact form. Existing filenames use the
   `NN_category_name.md` convention — follow it.

2. **Add a `Pattern` dataclass** to `PATTERNS` in `scanner.py`. Put it
   in the right category section (the file is grouped with comment
   headers like `# --- Suppression / silencing ---`). Keep the regex
   tight — broader regexes generate false positives on real repos.

3. **Run the scanner** against your new sample and make sure it fires:

   ```bash
   python scanner.py examples/NN_your_sample.md
   ```

   And against the whole examples folder to make sure you didn't break
   anything else:

   ```bash
   python scanner.py examples/
   ```

4. **Run the quality gates** before opening the PR:

   ```bash
   ruff check scanner.py
   ruff format --check scanner.py
   ```

   CI runs the same commands, so if they pass locally they pass in CI.

5. **Open a PR** with:

   - A one-line title: `feat: detect <pattern-name>`
   - A body that quotes the attack and links any public writeup
   - One pattern per PR — easier to review, easier to revert

## What makes a pattern worth adding

- **It's seen in the wild.** A real skill, a real README, a real CVE,
  a real research paper. "Could theoretically exist" is a weaker
  signal than "we saw this on GitHub last week".
- **Regex can catch it without many false positives.** If a rule fires
  on every third README, it's not useful.
- **It has a short, quotable example.** If the payload is 10 lines,
  it's probably too specific to one attacker.

## What makes a pattern not worth adding

- **It's vague.** "Any mention of AI" is not a prompt injection.
- **It's a subset of an existing pattern.** Extend the existing regex
  instead of adding a near-duplicate.
- **It requires semantic understanding.** Regex cannot understand
  meaning. Anything that needs an LLM to detect belongs in a different
  tool.

## Severity guide

When picking a severity for your new pattern:

| Severity | Meaning |
|---|---|
| `CRITICAL` | The pattern is essentially always malicious in an AI context. `rm -rf /`, `<!-- SYSTEM: ... -->`, `ssh/id_rsa`. Near-zero false positive rate. |
| `HIGH` | Almost always a red flag, but legitimate discussions exist. `note from Anthropic`, `from now on you must`, `.env`. |
| `MEDIUM` | Worth flagging but often benign in context. Role change phrases, loose sensitive paths. |
| `LOW` | Noise filter. Long base64 blocks, non-specific encoding indicators. |

When in doubt, pick a lower severity. Users can crank up
`--min-severity` if they want only the loud findings; they cannot
easily suppress a single noisy pattern.

## Other contributions

Not everything has to be a pattern. Also useful:

- **Doc fixes.** Typos in README, outdated examples, broken links.
- **New categories** in `docs/DEFENSIVE_PROMPT.md` if you've seen a new
  social-engineering angle on AI agents.
- **CI improvements.** Adding more shells (Windows, macOS) or more
  Python versions to the matrix.
- **Benchmarks.** If you can run the scanner against a large real-world
  corpus (top-1000 skills, top-100 PyPI packages, etc.) and report how
  many injections it catches, file an issue with the results.

## What not to send

- **An LLM-based detector.** See the README for why.
- **A full rewrite** in another language. Keep the Python version as
  the canonical one; ports can live in separate repos.
- **Dependencies.** The whole point is "zero-install, one file, easy to
  audit". If a new pattern needs a library, there's probably a simpler
  regex that covers 90% of the cases.

## Questions

Open an issue. Small repo, one maintainer, fast responses.
