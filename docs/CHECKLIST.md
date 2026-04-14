# Reviewing a skill from GitHub — checklist

Print this and walk through it every time you `git clone` a new skill,
plugin, or "awesome list" of prompts into your AI assistant.

## Before cloning

- [ ] The repo has a maintainer you've heard of, or more than 50 stars,
      or a link from an official vendor page.
- [ ] The most recent commit is not from an anonymous account with zero
      prior history.
- [ ] The repo is not a fresh fork of a popular skill with no explanation
      of what changed.
- [ ] You have a clean working tree you can roll back to if anything
      goes wrong.

## Before activating

- [ ] You opened `SKILL.md` (or equivalent) on GitHub in the **raw** view
      and read it end to end. HTML comments do not render in the normal
      view — the raw view shows everything.
- [ ] You opened every file referenced in `SKILL.md`: examples, configs,
      init scripts, templates.
- [ ] You ran `prompt-injection-scanner` against the cloned folder and
      reviewed every finding:
      ```bash
      python scanner.py path/to/skill --min-severity MEDIUM
      ```
- [ ] You reviewed the skill's shell commands, if any. Nothing that
      touches `~/.ssh`, `~/.aws`, `.env`, `credentials.*`, `token.*`.
- [ ] You reviewed any network calls. Every domain is named in the
      public description.
- [ ] No HTML comments with instructions.
- [ ] No "note from Anthropic / OpenAI / the team" language.
- [ ] No references to admin, developer, debug, or god mode.

## First run

- [ ] You are running in a git worktree, branch, or sandbox — not on
      your main working copy.
- [ ] You don't have uncommitted work in the target directory.
- [ ] You know exactly what the skill is supposed to do. If it starts
      doing something else, you will notice.
- [ ] Your defensive prompt (see `DEFENSIVE_PROMPT.md`) is active.

## Ongoing

- [ ] You re-run the scanner when the skill updates. A skill that was
      clean at v1 might be hijacked at v2 — especially if ownership of
      the repo changes.
- [ ] You watch for the agent doing anything the skill's public
      description didn't advertise. That is a red flag, not a coincidence.
- [ ] You report any finding that slipped past the scanner so the
      patterns can be improved.

## If something looks wrong

1. Stop the agent immediately. Don't let it "clean up".
2. Save the exact file and line that triggered your suspicion.
3. Revert any changes the agent made during this session.
4. Open an issue against the skill repo and against this scanner so the
   pattern can be added.
5. Rotate any credential that was in scope when the agent was running.
