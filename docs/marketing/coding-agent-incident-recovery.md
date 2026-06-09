# What to do when your AI coding agent runs a destructive command

**Updated:** 2026-06-09
**For:** the developer reading this at 2am because something just got deleted, force-pushed, deployed, or committed.
**TL;DR:** Take three minutes to *stop the agent*, capture the damage, and look for recoverable state before anything else. Specific instructions per failure mode below. Then install [Quill](https://github.com/manumarri-sudo/quill) (`uvx quillx start`) so this stops happening to you.

---

## First three things, regardless of which failure mode

1. **Stop the agent now.** Cmd+C in the terminal, kill the IDE, whatever you have. The longer the agent runs, the more damage it can do. The Replit / Lemkin incident (July 2025) went from one deleted database to 4,000 fabricated fake users in the minutes it took the agent to "cover" its mistake. Stop first, diagnose second.
2. **Don't touch the disk yet.** Many recoveries depend on unmodified inode state. If you `rm` something else, write a fresh commit, or run `git gc`, you may lose your recovery window. Pause.
3. **Take a screenshot of the agent's terminal / chat scrollback.** Even if the agent already fabricated explanations (like the Lemkin incident), the scrollback contains the actual commands it ran. That's your forensic record for the next 24 hours.

Now scroll to your specific failure mode below.

---

## `rm -rf` against the wrong directory

**The damage**: files are gone from the filesystem, but the inodes often aren't reclaimed until the disk is reused.

**Recovery options, in order of best-to-worst**:

1. **Time Machine (macOS)**: open Time Machine, navigate to the deleted directory's parent, scroll back to before the agent's incident, restore. Works if Time Machine was on (it usually is by default on a Mac).
2. **macOS Trash**: `rm -rf` does *not* go through Trash, but if you used Finder to delete it, check `~/.Trash`.
3. **git**: if the files were under git version control and any commit included them, `git checkout HEAD -- <path>` brings them back. Use `git fsck --lost-found` to recover orphaned commits the agent may have made.
4. **Disk snapshots / APFS local snapshots**: macOS takes hourly APFS snapshots; `tmutil listlocalsnapshots /` shows them. You can mount one read-only and copy files out.
5. **File-recovery tools**: `testdisk`, `PhotoRec`, or commercial tools (Disk Drill, R-Studio) can sometimes recover unallocated inodes if the disk hasn't been heavily written since the delete. Best results if you stopped writing to the disk immediately.
6. **Backups**: if you have iCloud, Dropbox, or a separate backup service, check whether the file was synced before the delete.

**What you can't recover**: anything that wasn't backed up, snapshotted, or committed to git. The Replit incident is a reminder that production databases without backups are not recoverable; the lesson is to have backups *before* you need them.

**Prevention**: Quill's [`policy.py`](../../src/quill/policy.py) classifies `rm -rf` (and `rm -f`, `rm -r`, `rmdir -r`) as `Risk.CRITICAL` by default. The agent has to type the action name back, or (on macOS) confirm with Touch ID, before the command executes. The default-critical regex set is inspectable and extensible.

---

## `git push --force` overwrote shared history

**The damage**: commits that other people had (or that CI had) are now orphaned on the remote. The remote's branch head is your local head, and the old commits look gone.

**Recovery options**:

1. **`git reflog` is your friend**. On your local clone (or any team member's clone), `git reflog` lists every position HEAD has been at. Find the SHA from before the force-push, run `git reset --hard <sha>`, then `git push` (without --force) to a fresh branch and open a PR.
2. **GitHub's web UI keeps deleted refs for ~30 days**. The Activity log at `https://github.com/<owner>/<repo>/activity` shows force-pushes. Click the SHA in the "before" column to view the orphaned commit; cherry-pick or revert from there.
3. **CI logs often have the lost SHA**. Your CI ran on the now-orphaned commits; the SHA is in the CI run metadata, and you can `git fetch <sha>` to pull it back.
4. **Someone else's local clone**. Any teammate who pulled before the force-push has the lost history in their reflog. Ask in Slack.

**What you can't recover**: nothing, usually. Force-push almost always recoverable from one of the four sources above.

**Prevention**: Quill's regex set blocks `git push --force` by default. The safer alternative it suggests is `git push --force-with-lease`, which fails if the remote has commits the local doesn't (which is the actual safety property you wanted from --force).

---

## `DROP TABLE` or destructive SQL ran against production

**The damage**: a table is gone. Or rows are gone. Or constraints are gone. Whichever happened, the production database is in a state it wasn't a minute ago.

**Recovery options**:

1. **Point-in-time recovery (PITR)**: every managed database (RDS, Cloud SQL, Aurora, Supabase, Neon, PlanetScale, Crunchy Bridge, Render Postgres) supports point-in-time recovery if it's enabled. Check your provider's console; restore to a timestamp a few minutes before the incident.
2. **Latest backup**: if PITR isn't on, restore from the most recent full backup. You'll lose data after the backup, but you'll have a table.
3. **Replica failover**: if you have a read replica that hadn't yet replicated the destructive transaction, promote the replica. (This is racy; check replication lag first.)
4. **Binlog / WAL replay**: if you have access to the binary log or write-ahead log up to but excluding the destructive transaction, you can replay it onto a clean database to reconstruct state.

**What you can't recover**: anything not in PITR, a backup, a replica, or a binlog. The Replit / Lemkin incident is an example: the production database had no recoverable backup at the time of the agent's destructive command.

**Prevention**: Quill's regex set classifies `DROP TABLE`, `DELETE FROM` without WHERE, `TRUNCATE`, and similar verbs as `Risk.CRITICAL`. For production database connections specifically, also enforce role-based privileges at the DB layer (the agent's connection should not have DROP authority in production at all).

---

## A secret (API key, PAT, password) got committed to git

**The damage**: the secret is now in your commit history. If you've pushed, it's in the remote's history. If the remote is public, search engines may have indexed it.

**Recovery, in this order, fast**:

1. **Rotate the secret immediately.** Even before cleaning the history. The window between push and rotation is the window where the secret is exposed.
   - GitHub PATs: https://github.com/settings/tokens
   - AWS access keys: IAM console → deactivate → delete
   - Stripe live keys: Stripe Dashboard → Developers → API keys → Roll
   - OpenAI / Anthropic: their respective dashboards → roll the key
2. **Force-removal from history**: `git filter-repo --replace-text` (or the older `git filter-branch`) to scrub the secret from every commit. `bfg-repo-cleaner` is the easiest tool.
3. **Force-push the cleaned history**. Yes, force-push. Yes, this rewrites shared history. Yes, you have to coordinate with your team. The alternative is a permanent leak.
4. **Notify your security team / Github Secret Scanning** if applicable. GitHub may have already alerted you via Secret Scanning; the alert often includes which third-party noticed.
5. **Audit usage after the leak**: AWS CloudTrail, GCP Audit Logs, Stripe Events. Look for usage from IPs / agents you don't recognize during the exposure window.

**What you can't recover**: time. If the key was used by an attacker in the exposure window, the damage from that usage is permanent.

**Prevention**: Quill's [secret detection](../../src/quill/secrets.py) scans every Edit / MultiEdit / Write / NotebookEdit before it lands. The 26 vendor-format patterns cover AWS, OpenAI legacy + project, Anthropic, GitHub (classic + fine-grained + OAuth + App), Stripe (live + test + restricted + webhook), Slack (bot + user + webhook), Google, JWT, PEM private keys, HuggingFace, Twilio, SendGrid, Mailgun, Discord, and Notion. Hits escalate to `Risk.CRITICAL` with the line number in the verdict reason. Also exposed as `quill scan-secrets <path>` for CI use.

---

## The agent deployed something to production by accident

**The damage**: code that wasn't supposed to ship is now live. Customers may be hitting it.

**Recovery**:

1. **Roll back the deployment immediately**. Every modern deploy platform has a one-click rollback: Vercel ("Promote to Production" on the previous deployment), Render, Fly.io, Heroku (`heroku releases:rollback`), Kubernetes (`kubectl rollout undo`), AWS Elastic Beanstalk (Application versions → Restore).
2. **Communicate**: if the bad deploy was up for more than a few seconds and your product has paying customers, post a brief status-page update. Honesty wins.
3. **Re-deploy from a known-good SHA** rather than the agent's recent commits.
4. **Diff the bad deploy vs the previous to scope the customer-facing impact**: which routes were affected? Were any new database writes? Did any payment flows change?

**Prevention**: Quill's default-critical patterns include `vercel --prod`, `npm publish`, `flyctl deploy`, `terraform apply`, `kubectl apply` against production contexts, `heroku releases:promote`, and similar verbs. The agent has to type the action name back (or Touch ID confirm on macOS) before deploys execute.

---

## The agent invented a fix that doesn't exist (and the test passed somehow)

**The damage**: the code looks correct, the tests passed, but something subtle is wrong. The Replit incident's "4,000 fake users" started as an agent fabricating database rows to make a buggy report look fixed.

**Recovery**:

1. **Don't trust the agent's narrative**. Read the actual diff. The agent's explanation of what it did and what it actually did can diverge.
2. **Run the affected tests by hand outside the agent's environment**. The agent may have mocked, stubbed, or modified the test setup to pass.
3. **Diff the test fixtures against the previous commit**. New test data files appearing without good reason are a tell.
4. **Bisect with `git bisect`** if the bug surfaces in a subtle way (works fine for unit tests, fails in production).
5. **Audit any data the agent created**. If the agent wrote rows to a development database, verify they're sensible. Fabrication-to-pass-tests is a real pattern.

**Prevention**: this is a model-behavior problem, not a Quill problem. Quill records every action the agent took, but if the action *looked* legitimate (write to a fixture file, insert into a test database), it would be `verdict.allowed` rather than blocked. Pair Quill with code review and human-eyes-on-test-data.

---

## The general lesson: the pause button you wish your agent had

The Replit / Lemkin incident, the Cursor `rm -rf ~/` incident, the GitHub PAT leaks reported in 2025 — every one of them happened because an AI coding agent had authority to do something irreversible and no friction between the agent's decision and the action.

Quill is the smallest pause button I could build. It sits between your AI coding agent (Claude Code, Cursor, Cline, Aider, Continue, Windsurf, Zed) and the things you can't undo. Three deterministic layers (no LLM in the gate), an HMAC-chained tamper-evident audit log on your own disk, Touch ID hardware-attested approval for critical actions on macOS, and a one-shot paste-able approve-token flow so you can confirm from your phone when needed.

One command to install:

```bash
uvx quillx start
```

Or for the guided wizard:

```bash
pipx install quillx
quill onboard
```

Open source, MIT, single Python package, 700+ tests passing. Repo: [github.com/manumarri-sudo/quill](https://github.com/manumarri-sudo/quill).

---

## Reading list if you have an hour

- [Replit deleted Jason Lemkin's database — Fortune coverage, July 2025](https://fortune.com/2025/07/23/ai-coding-tool-replit-wiped-database-called-it-a-catastrophic-failure/)
- [Simon Willison on the Lethal Trifecta (prompt injection)](https://simonwillison.net/tags/prompt-injection/)
- [Meta's Agents Rule of Two](https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/)
- [Invariant Labs MCP Tool Poisoning advisory, March 2025](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- [Anthropic Claude Code permissions documentation](https://code.claude.com/docs/en/permissions)
- [Quill source repository](https://github.com/manumarri-sudo/quill)
- [Quill's CVE-2025-59536 mitigation page](cve-2025-59536-mitigation.md)
- [Quill's EU AI Act readiness guide](eu-ai-act-august-2026-readiness.md)
