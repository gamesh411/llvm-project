# 01: CodeChecker dev loop on colorful-day

**What to build:** A developer can analyze the two-path example with the Colorful Day Clang build, store the report on a local CodeChecker server, and open it in a browser using the web UI built from the CodeChecker `colorful-day` branch.
The same loop proves that the Thrift API can be regenerated with the pinned Docker image.
This is prefactoring for every later ticket, and it records the exact commands so later tickets don't rediscover them.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] A Python environment for the `colorful-day` CodeChecker branch can run the analyzer, store and server commands.
- [ ] The web UI builds from the branch and the running server serves that build.
- [ ] The two-path example, analyzed with the Colorful Day Clang through `PATH`, appears as one report with one Bug Path in the browser.
- [ ] Regenerating the Thrift API with the pinned Docker image succeeds, and the regenerated packages install and run.
- [ ] The commands for this loop are written down in a Comments section on this ticket.
