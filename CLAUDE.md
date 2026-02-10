# Claude Code Instructions

## Project Layout

Before starting any task, confirm the project root directory. Key repos:
- `~/superduper` - Main project repository

## Git Operations

When performing git operations, always confirm the current working directory is the correct repository before running any git commands. Use `pwd` and `git remote -v` to verify.

When git push fails due to diverged branches, explain the situation to the user and ask whether they want to merge, rebase, or force push before proceeding. Never force push without explicit confirmation.
