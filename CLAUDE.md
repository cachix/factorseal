@AGENTS.md

For Windows builds and checks of Desktop from WSL2, use the
`windows-desktop-check` skill. devenv generates `.claude/` and `.mcp.json`
when its shell starts (`claude.code` in `devenv.nix`); the skill's source is
`scripts/windows-desktop-check/skill.md`. Edit the sources, not the generated
files.
