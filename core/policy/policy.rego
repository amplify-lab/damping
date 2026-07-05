# package damping.policy is the Rego translation of rules_shell.go,
# rules_mcp.go, and rules_selfprotection.go — see core/policy/opa.go for how
# it's embedded and evaluated, and docs/architecture.md §4 for why the
# always_allow/always_deny override tier stays in Go (patterns.go) rather
# than moving here: that tier is simple user-authored glob matching, not
# policy-as-code detection logic, so duplicating it in Rego would just be a
# second implementation of the same trivial string match to keep in sync.
#
# `matches` is the set of every rule id whose condition holds for the given
# input.facts/input.config — which one "wins" when more than one matches is
# a config-order tie-break OPAEngine.Evaluate applies in Go, exactly
# mirroring core/policy.Engine.Evaluate's `for _, rc := range cfg.Rules`
# first-match loop. Every rule here must stay behaviorally identical to its
# Go counterpart — core/policy/opa_equivalence_test.go runs the exact same
# table both engines are tested against and fails if they ever diverge.
package damping.policy

import rego.v1

# --- destructive.rm_rf_protected — rules_shell.go matchRmRfProtected ---

regenerable_dir_names := {
	"node_modules", "build", "dist", ".next", ".cache",
	"target", "vendor", "__pycache__", ".venv", "venv",
}

# rm accepts multiple path operands in a single invocation
# ("rm -rf /etc build"), and every one of them gets force-recursively
# deleted — so each operand is checked independently rather than just
# input.facts.target (the *last* word), mirroring rules_shell.go's
# rmPathOperands/matchRmRfProtected exactly.

matches contains "destructive.rm_rf_protected" if {
	input.facts.command == "rm"
	has_recursive_force
	some target in rm_path_operands
	is_filesystem_or_home_root(target)
}

matches contains "destructive.rm_rf_protected" if {
	input.facts.command == "rm"
	has_recursive_force
	some target in rm_path_operands
	in_protected_paths(target)
}

matches contains "destructive.rm_rf_protected" if {
	input.facts.command == "rm"
	has_recursive_force
	some target in rm_path_operands
	not is_regenerable_target(target)
}

rm_path_operands contains a if {
	some a in input.facts.args
	not is_rm_flag(a)
}

is_rm_flag(a) if {
	startswith(a, "-")
	a != "-"
}

is_filesystem_or_home_root(target) if {
	target in {"/", "~", "~/", "$HOME"}
}

is_regenerable_target(target) if {
	segments := [s | some s in split(target, "/"); s != ""]
	count(segments) > 0
	segments[count(segments) - 1] in regenerable_dir_names
}

in_protected_paths(target) if {
	some p in input.config.protected_paths
	trimmed := trim_suffix(p, "/")
	target == trimmed
}

in_protected_paths(target) if {
	some p in input.config.protected_paths
	trimmed := trim_suffix(p, "/")
	startswith(target, concat("", [trimmed, "/"]))
}

# rm's recursive+force flags: the long flags, the plain short flags, or any
# combined short-flag cluster in either order/case for the recursive letter
# ("-rf", "-fr", "-Rf", "-fR") — see hasRecursiveForce's doc comment in
# rules_shell.go for the real bypass this guards against.
has_recursive_force if {
	rm_has_r
	rm_has_f
}

rm_has_r if {
	"--recursive" in input.facts.args
}

rm_has_r if {
	some a in input.facts.args
	is_short_flag_cluster(a)
	contains(a, "r")
}

rm_has_r if {
	some a in input.facts.args
	is_short_flag_cluster(a)
	contains(a, "R")
}

rm_has_f if {
	"--force" in input.facts.args
}

rm_has_f if {
	some a in input.facts.args
	is_short_flag_cluster(a)
	contains(a, "f")
}

is_short_flag_cluster(a) if {
	startswith(a, "-")
	not startswith(a, "--")
	count(a) > 1
}

# --- destructive.write_protected_path — rules_shell.go matchWriteProtectedPath ---

matches contains "destructive.write_protected_path" if {
	input.facts.command == "<redirect-write>"
	in_protected_paths(input.facts.target)
}

# --- destructive.dynamic_command_construction ---

matches contains "destructive.dynamic_command_construction" if {
	input.facts.command == "<dynamic>"
}

# --- destructive.git_push_force — rules_shell.go matchGitPushForce ---

matches contains "destructive.git_push_force" if {
	input.facts.command == "git"
	"push" in input.facts.args
	git_has_force
}

git_has_force if { "--force" in input.facts.args }
git_has_force if { "-f" in input.facts.args }

# --- destructive.sql_drop_truncate — rules_shell.go matchSQLDropTruncate ---

sql_shell_clients := {"psql", "mysql", "sqlite3", "mongosh"}

matches contains "destructive.sql_drop_truncate" if {
	input.facts.command in sql_shell_clients
	some a in input.facts.args
	regex.match(`(?i)\b(DROP\s+TABLE|TRUNCATE)\b`, a)
}

# mongosh uses JS method-call syntax, not SQL keywords, so the pattern above
# can never match real Mongo usage despite mongosh being a listed client —
# mirrors rules_shell.go's mongoDestructivePattern exactly.
matches contains "destructive.sql_drop_truncate" if {
	input.facts.command == "mongosh"
	some a in input.facts.args
	regex.match(`(?i)\bdb\.\w+\.drop\(\)|\bdb\.dropDatabase\(\)|\.(?:deleteMany|remove)\(\s*(?:\{\s*\})?\s*\)`, a)
}

# --- destructive.chmod_777_recursive — rules_shell.go matchChmod777Recursive ---

matches contains "destructive.chmod_777_recursive" if {
	input.facts.command == "chmod"
	chmod_has_777
	chmod_has_recursive
}

chmod_has_777 if {
	some a in input.facts.args
	is_world_writable_octal_mode(a)
}

# chmod's short recursive flag is uppercase-only (-R); unlike rm, lowercase
# -r is not a valid chmod flag at all.
chmod_has_recursive if { "--recursive" in input.facts.args }

chmod_has_recursive if {
	some a in input.facts.args
	is_short_flag_cluster(a)
	contains(a, "R")
}

# Any all-octal-digit mode string ending in 777 (777, 0777, 1777 with the
# sticky bit, 2777, ...) — a leading digit or leading zeros don't change
# that the low three bits grant world write.
is_world_writable_octal_mode(a) if {
	a != ""
	regex.match(`^[0-7]+$`, a)
	endswith(a, "777")
}

# --- destructive.curl_pipe_sh_unallowlisted — rules_shell.go matchCurlPipeShUnallowlisted ---

fetch_commands := {"curl", "wget"}
shell_sinks := {"sh", "bash", "zsh"}

matches contains "destructive.curl_pipe_sh_unallowlisted" if {
	input.facts.is_pipeline
	count(input.facts.pipeline_cmds) >= 2
	input.facts.pipeline_cmds[0] in fetch_commands
	input.facts.pipeline_cmds[count(input.facts.pipeline_cmds) - 1] in shell_sinks
	not domain_allowlisted
}

domain_allowlisted if {
	some d in input.config.allowlisted_install_domains
	lower(input.facts.domain) == lower(d)
}

# --- destructive.encoded_payload_pipe — rules_shell.go matchEncodedPayloadPipe ---

# decode_commands are decode primitives whose bare command name is
# unambiguous; decode_flag_patterns catches the ambiguous ones (xxd is also
# used for plain hex dumps, openssl has dozens of unrelated subcommands) by
# regex against the raw text, since pipeline_cmds carries no per-stage args —
# mirrors rules_shell.go's decodeCommands/decodeFlagPatterns exactly.
decode_commands := {"base64", "base32", "uudecode"}
shell_or_eval_sinks := {"sh", "bash", "zsh", "eval", "source"}

decode_flag_patterns := [
	`\bxxd\s+(?:-\S+\s+)*-r\b`,
	`\bopenssl\s+(?:enc|base64)\b.*\s-d\b`,
]

has_decode_flag_pattern if {
	some p in decode_flag_patterns
	regex.match(p, input.facts.raw)
}

matches contains "destructive.encoded_payload_pipe" if {
	input.facts.is_pipeline
	count(input.facts.pipeline_cmds) > 0
	some c in input.facts.pipeline_cmds
	c in decode_commands
	input.facts.pipeline_cmds[count(input.facts.pipeline_cmds) - 1] in shell_or_eval_sinks
}

matches contains "destructive.encoded_payload_pipe" if {
	input.facts.is_pipeline
	count(input.facts.pipeline_cmds) > 0
	has_decode_flag_pattern
	input.facts.pipeline_cmds[count(input.facts.pipeline_cmds) - 1] in shell_or_eval_sinks
}

# --- destructive.proc_sandbox_bypass — rules_shell.go matchProcSandboxBypass ---

proc_bypass_paths := ["/proc/self/root/", "/proc/self/exe"]

matches contains "destructive.proc_sandbox_bypass" if {
	some p in proc_bypass_paths
	contains(input.facts.raw, p)
}

# --- mcp.destructive_tool_call / mcp.write_tool_unscoped_identity — rules_mcp.go ---

matches contains "mcp.destructive_tool_call" if {
	input.facts.action_type == "tool_call"
	"destructive" in input.facts.tool_tags
}

# Registered but deliberately not in cli/policies/default.yaml's active rule
# list — see rules_mcp.go's doc comment: no identity system exists in the
# individual tier, so this would nag on nearly every write tool call.
matches contains "mcp.write_tool_unscoped_identity" if {
	input.facts.action_type == "tool_call"
	"write" in input.facts.tool_tags
	not input.facts.has_identity
}

# --- self_protection.damping_off_attempt — rules_selfprotection.go ---
#
# "off" must occupy the actual subcommand position, not just appear
# somewhere in the argument list — otherwise a flag *value* elsewhere
# ("damping log --actor off", or a wrapped MCP server's own flag passed
# through "damping mcp wrap -- server --telemetry off") would be mistaken
# for the real `damping off` subcommand. Mirrors
# rules_selfprotection.go's dampingSubcommand exactly.

matches contains "self_protection.damping_off_attempt" if {
	input.facts.command == "damping"
	damping_subcommand == "off"
}

damping_subcommand := sub if {
	non_flag_indices := [i |
		some i, a in input.facts.args
		not is_damping_flag_or_value(i, a)
	]
	count(non_flag_indices) > 0
	sub := input.facts.args[non_flag_indices[0]]
}

is_damping_flag_or_value(i, a) if {
	startswith(a, "-")
}

is_damping_flag_or_value(i, a) if {
	i > 0
	input.facts.args[i-1] == "--config"
}
