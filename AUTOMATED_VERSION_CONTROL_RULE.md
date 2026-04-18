# AUTOMATED VERSION CONTROL RULE
You are operating in a production algorithmic trading environment. Version control is critical.

Every time you successfully complete a coding task, implement a feature, or refactor a file, you MUST automatically do the following before asking me for the next prompt:
1. Run `git status` to check what was modified.
2. Run `git add .` to stage all changes.
3. Run `git commit -m "<type>: <brief description>"` using conventional commit formatting (e.g., feat:, fix:, refactor:, chore:).
4. Inform me that the changes have been locally committed and provide the commit hash.

CRITICAL: Do NOT run `git push`. Only commit locally so I have a safe rollback point.
