# security-notes

A personal log of practice security challenges (CTFs — "Capture The Flag" exercises) and bug bounty work (getting paid by companies to find and report security flaws in their software). Keeps track of what I tried, what worked, and what I learned. Built while studying cybersecurity, as a working record and something to point to when applying for internships or freelance work.

## Structure

```
security-notes/
├── ctf/
│   └── thm/                    # TryHackMe (a website that hosts practice challenges) rooms
│       └── <room-slug>/
│           └── notes.md
├── bugbounty/
│   └── <program-name>/
│       ├── scope.md            # what's in/out of bounds for that program
│       └── findings/
│           └── <finding-slug>.md
└── templates/
    ├── ctf-template.md         # copy for each new challenge
    └── finding-template.md     # copy for each new bug bounty report
```

Each challenge write-up covers: the platform, how hard it was, the steps taken to investigate/solve it, and what I learned. The goal is something I can search later ("every time I used technique X"), not a polished tutorial.

## ⚠️ Bug bounty entries — keep them private until cleared

Companies running bug bounty programs almost always require that a found flaw stay secret until *they* say it's okay to talk about publicly (this is called responsible disclosure, and is usually a condition of taking part in the program at all — breaking it can get you banned or in legal trouble). Before adding anything under `bugbounty/`:

- Check that specific program's rules allow sharing what you're about to add
- Remove/blank out any target details not yet cleared for release
- If unsure, don't put it in this public repo — keep it somewhere private until it's cleared

## Completed rooms / programs

| Date | Platform | Name | Status |
|---|---|---|---|
| 2026-09-10 | TryHackMe | [Trusted By Default](ctf/thm/trustedbydefault/notes.md) | In progress |
