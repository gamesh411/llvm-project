# 02: Show ranges for event steps, end to end

**What to build:** With the new analyzer config option enabled through CodeChecker's existing passthrough, a report reader turns on the debug view, clicks an event Path Step, and sees that step's symbol ranges in a side panel.
This is the tracer bullet through both repositories, from Clang's plist output to the web UI.

**Blocked by:** 01

**Status:** ready-for-agent

- [ ] Clang's analyzer config option is off by default, and plist output is unchanged when it is off.
- [ ] With the option on, every event Path Step in the plist carries a Constraint Snapshot with symbol ranges.
- [ ] CodeChecker's parser, report model and storage carry the data through the existing report path data blob with no database migration.
- [ ] The report details API exposes the data through an optional field, and the new blob item type is not returned as extended report data.
- [ ] A toggle beside "Show arrows" is off by default and leaves the report page visually unchanged while off.
- [ ] With the toggle on, clicking an event Path Step opens a side panel showing that step's ranges.
- [ ] On a report with no constraint data, the toggle is disabled and explains why.
- [ ] A Clang lit test covers the plist output, and a CodeChecker functional test stores a Clang-generated fixture plist and reads it back through the API, including the no-data case.
- [ ] The behavior is checked in a real browser on the two-path example.
