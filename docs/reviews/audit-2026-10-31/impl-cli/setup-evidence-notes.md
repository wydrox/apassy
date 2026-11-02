# Setup implementation evidence

PR: https://github.com/wydrox/apassy/pull/35

All setup fixtures and native tours use a scratch HOME and synthetic data. No owner vault, keychain, host configuration, LaunchAgent, provider, local browser, Docker, or release operation was used.

The standard screenshot tour completed 21 captures. Its existing Decisions steps leave a fresh owner-check dialog open and obscure later standard-tour pages. Use the focused `setup-agents.png`, `setup-connect-host.png`, `setup-owner-check.png`, and `setup-runnable-command.png` for the setup evidence. The last image was visually checked after a synthetic Codex connection saved its configuration. It shows the absolute quoted launcher, 660-second timeout, and both PATH copy blocks. The helper executable paths belong to the synthetic debug example, not an installed-app acceptance run. The live tour was quit and its temporary vault was removed by the script.

The initial full test attempt found one source assertion requiring the obsolete 330-second timeout. That related test was corrected to 660 seconds and the already-failed run was stopped. Final full-suite and CI results are recorded separately after completion.

Final head: `8d7c2590deaf2330fbac156c7f20fdbac229ec03`. CI workflow 168 / run 41240445459 completed successfully: all 12 jobs green. PR reviews were empty at handoff. Final-head CI logs explicitly show the padded-name retry and raw-proof rejection tests passing, and the Keychain isolation test passing in the macOS runner.

Local unit phase: 1210 passed, 5 existing manual tests ignored. Binary/example targets passed. Vault docs: 6 passed. Node: 33 passed. Python boundary fixtures: 9 passed. Focused launcher recovery: 5 passed. Twenty fresh CLI fixtures passed on the final CLI build, including a real controlling-TTY fixture with one stdout JSON document, stderr-only progress, no TTY writes, and no token output.

The last duplicated local library compile was canceled after final-head CI proved its two connection tests. The local integration rerun excluded the Keychain query per the machine rule and was stopped after CI became green, as requested; it is not a completed local full-suite pass. The completed full-suite result is from CI. All owned test and screenshot processes were stopped before target cleanup.

Concurrent handoff update: the remote PR head advanced to `5d0312f3a7a4145407dec45035e3f627fef5d176` (Align setup JSON state and verify runnable host commands). That commit was made outside this worktree after `8d7c2590` passed all CI. Its CI was pending at handoff; no green result is claimed for it here. The working tree remains clean at the verified `8d7c2590`. The follow-up changes the JSON shape to top-level `stage` and `partial_state`; the saved manual fixtures reflect the earlier verified shape. No concurrent changes were overwritten.

Cleanup: `/Users/rafalw/Dev/.target-cli1` was checked for active executables/compiler use and deleted.
