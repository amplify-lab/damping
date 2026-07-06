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

# 2026-07 coverage expansion: UPDATE/DELETE with no WHERE clause (or an
# always-true one) — mirrors rules_shell.go's hasUnscopedUpdateOrDelete.
matches contains "destructive.sql_drop_truncate" if {
	input.facts.command in sql_shell_clients
	some a in input.facts.args
	regex.match(`(?i)\b(UPDATE\s+\S+\s+SET\b|DELETE\s+FROM\b)`, a)
	not regex.match(`(?i)\bWHERE\b`, a)
}

matches contains "destructive.sql_drop_truncate" if {
	input.facts.command in sql_shell_clients
	some a in input.facts.args
	regex.match(`(?i)\b(UPDATE\s+\S+\s+SET\b|DELETE\s+FROM\b)`, a)
	regex.match(`(?i)\bWHERE\s+(1|TRUE)\s*;?\s*$`, a)
}

# 2026-07 coverage expansion: redis-cli FLUSHALL/FLUSHDB — same rule id as
# SQL TRUNCATE, mirrors rules_shell.go's redisShellClients/redisFlushPattern.
redis_shell_clients := {"redis-cli"}

matches contains "destructive.sql_drop_truncate" if {
	input.facts.command in redis_shell_clients
	some a in input.facts.args
	regex.match(`(?i)^(FLUSHALL|FLUSHDB)$`, a)
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

# --- 2026-07 dangerous-command-coverage expansion — rules_expansion.go ---
# See rules_expansion.go's package-level doc comments for the real-world
# incidents motivating each rule below (DataTalks.Club/incidentdatabase.ai
# #1424 for iac_destroy; the Claude Code CHANGELOG v2.1.183 precedent for
# both iac_apply_unreviewed and git_history_destructive; the TrapDoor
# campaign for secret_exfiltration).

# --- destructive.iac_destroy / destructive.iac_apply_unreviewed ---

iac_destroy_commands := {"terraform", "pulumi", "cdk"}

matches contains "destructive.iac_destroy" if {
	input.facts.command in iac_destroy_commands
	"destroy" in input.facts.args
}

matches contains "destructive.iac_apply_unreviewed" if {
	input.facts.command == "terraform"
	"apply" in input.facts.args
	terraform_has_auto_approve
}

terraform_has_auto_approve if { "-auto-approve" in input.facts.args }

terraform_has_auto_approve if { "--auto-approve" in input.facts.args }

matches contains "destructive.iac_apply_unreviewed" if {
	input.facts.command == "pulumi"
	"up" in input.facts.args
	pulumi_has_unattended
}

pulumi_has_unattended if { "--yes" in input.facts.args }

pulumi_has_unattended if { "-y" in input.facts.args }

pulumi_has_unattended if { "--skip-preview" in input.facts.args }

# --- destructive.git_history_destructive ---

git_rest(args) := array.slice(args, 1, count(args))

matches contains "destructive.git_history_destructive" if {
	input.facts.command == "git"
	count(input.facts.args) > 0
	input.facts.args[0] == "reset"
	"--hard" in git_rest(input.facts.args)
}

matches contains "destructive.git_history_destructive" if {
	input.facts.command == "git"
	count(input.facts.args) > 0
	input.facts.args[0] == "clean"
	"--force" in git_rest(input.facts.args)
}

matches contains "destructive.git_history_destructive" if {
	input.facts.command == "git"
	count(input.facts.args) > 0
	input.facts.args[0] == "clean"
	some a in git_rest(input.facts.args)
	is_short_flag_cluster(a)
	contains(a, "f")
}

matches contains "destructive.git_history_destructive" if {
	input.facts.command == "git"
	count(input.facts.args) > 0
	input.facts.args[0] == "stash"
	some a in git_rest(input.facts.args)
	a in {"clear", "drop"}
}

matches contains "destructive.git_history_destructive" if {
	input.facts.command == "git"
	count(input.facts.args) > 0
	input.facts.args[0] == "checkout"
	"." in git_rest(input.facts.args)
}

matches contains "destructive.git_history_destructive" if {
	input.facts.command == "git"
	count(input.facts.args) > 0
	input.facts.args[0] in {"filter-branch", "filter-repo"}
}

# --- destructive.secret_exfiltration ---

secret_exfil_network_sinks := {"curl", "wget", "nc", "ncat", "ssh", "scp"}
data_upload_flags := {"-d", "--data", "--data-binary", "--data-raw", "-F", "--form"}

raw_contains_sensitive_path if {
	some p in input.config.protected_paths
	contains(input.facts.raw, p)
}

egress_domain_allowlisted if {
	some d in input.config.allowlisted_egress_domains
	lower(input.facts.domain) == lower(d)
}

matches contains "destructive.secret_exfiltration" if {
	count(input.config.protected_paths) > 0
	input.facts.is_pipeline
	count(input.facts.pipeline_cmds) > 0
	last_cmd := input.facts.pipeline_cmds[count(input.facts.pipeline_cmds) - 1]
	last_cmd in {"curl", "wget"}
	raw_contains_sensitive_path
	not egress_domain_allowlisted
}

matches contains "destructive.secret_exfiltration" if {
	count(input.config.protected_paths) > 0
	input.facts.is_pipeline
	count(input.facts.pipeline_cmds) > 0
	last_cmd := input.facts.pipeline_cmds[count(input.facts.pipeline_cmds) - 1]
	last_cmd in secret_exfil_network_sinks
	not last_cmd in {"curl", "wget"}
	raw_contains_sensitive_path
}

matches contains "destructive.secret_exfiltration" if {
	count(input.config.protected_paths) > 0
	input.facts.command in {"curl", "wget"}
	some i, a in input.facts.args
	a in data_upload_flags
	i + 1 < count(input.facts.args)
	val := input.facts.args[i + 1]
	startswith(val, "@")
	path := substring(val, 1, -1)
	in_protected_paths(path)
	not egress_domain_allowlisted
}

# --- 2026-07 non-Bash attack-surface expansion — rules_configwrite.go ---
# cli/cmd/hook.go also intercepts Claude Code's Write/Edit/MultiEdit tool
# calls now (Cursor/Codex have no equivalent pre-write hook — see
# docs/cli-reference.md §11). See rules_configwrite.go's doc comment for
# the real CVEs (CVE-2025-53773, CVE-2026-50549) motivating these rules.

agent_settings_file_suffixes := [".vscode/settings.json", ".claude/settings.json", ".claude/settings.local.json"]

matches contains "destructive.agent_permission_escalation" if {
	input.facts.action_type == "config_write"
	some suffix in agent_settings_file_suffixes
	endswith(input.facts.target, suffix)
	regex.match(`(?i)"(chat\.tools\.autoApprove|skipDangerousModePermissionPrompt|dangerouslySkipPermissions)"\s*:\s*true`, input.facts.raw)
}

matches contains "destructive.git_hook_write" if {
	input.facts.action_type == "config_write"
	contains(input.facts.target, ".git/hooks/")
}

matches contains "destructive.git_hook_write" if {
	input.facts.action_type == "config_write"
	startswith(input.facts.target, ".git/hooks/")
}

matches contains "destructive.npm_lifecycle_script_write" if {
	input.facts.action_type == "config_write"
	target_basename(input.facts.target) == "package.json"
	regex.match(`(?i)"(postinstall|preinstall|prepare)"\s*:`, input.facts.raw)
}

target_basename(target) := seg if {
	segments := split(target, "/")
	seg := segments[count(segments) - 1]
}

# --- 2026-07 wave 2 coverage expansion — rules_wave2.go ---
# See rules_wave2.go's package-level and per-rule doc comments for the real
# incidents grounding each rule below (Gustavo Zanotto's postmortem for
# kubectl_bulk_delete; the compromised Amazon Q Developer extension for
# cloud_cli_mass_delete; WhisperGate for raw_device_write; the finch-rust/
# sha-rust crates.io incident for cargo_publish_unreviewed; the rest-client
# RubyGems incident for gem_push_unreviewed; Socket's Discord-webhook-as-C2
# research for webhook_exfiltration).

# --- destructive.kubectl_bulk_delete ---

kubectl_bulk_delete_resources := {
	"deployment", "deployments", "deploy",
	"pod", "pods", "po",
	"pvc", "pvcs", "persistentvolumeclaim", "persistentvolumeclaims",
	"pv", "pvs", "persistentvolume", "persistentvolumes",
	"all",
}

matches contains "destructive.kubectl_bulk_delete" if {
	input.facts.command == "kubectl"
	count(input.facts.args) > 0
	input.facts.args[0] == "delete"
	rest := git_rest(input.facts.args)
	count(rest) > 0
	rest[0] in {"namespace", "namespaces", "ns"}
}

matches contains "destructive.kubectl_bulk_delete" if {
	input.facts.command == "kubectl"
	count(input.facts.args) > 0
	input.facts.args[0] == "delete"
	rest := git_rest(input.facts.args)
	count(rest) > 0
	rest[0] in kubectl_bulk_delete_resources
	kubectl_has_all(rest)
}

kubectl_has_all(rest) if { "--all" in rest }

kubectl_has_all(rest) if { "--all-namespaces" in rest }

# --- destructive.cloud_cli_mass_delete ---

matches contains "destructive.cloud_cli_mass_delete" if {
	input.facts.command == "aws"
	count(input.facts.args) >= 2
	input.facts.args[0] == "ec2"
	input.facts.args[1] == "terminate-instances"
}

matches contains "destructive.cloud_cli_mass_delete" if {
	input.facts.command == "aws"
	count(input.facts.args) >= 2
	input.facts.args[0] == "s3"
	input.facts.args[1] == "rm"
	"--recursive" in array.slice(input.facts.args, 2, count(input.facts.args))
}

matches contains "destructive.cloud_cli_mass_delete" if {
	input.facts.command == "aws"
	count(input.facts.args) >= 2
	input.facts.args[0] == "s3"
	input.facts.args[1] == "rb"
	"--force" in array.slice(input.facts.args, 2, count(input.facts.args))
}

matches contains "destructive.cloud_cli_mass_delete" if {
	input.facts.command == "aws"
	count(input.facts.args) >= 2
	input.facts.args[0] == "rds"
	input.facts.args[1] == "delete-db-instance"
}

matches contains "destructive.cloud_cli_mass_delete" if {
	input.facts.command == "gcloud"
	count(input.facts.args) >= 3
	input.facts.args[0] == "compute"
	input.facts.args[1] == "instances"
	input.facts.args[2] == "delete"
}

matches contains "destructive.cloud_cli_mass_delete" if {
	input.facts.command == "az"
	count(input.facts.args) >= 2
	input.facts.args[0] == "vm"
	input.facts.args[1] == "delete"
}

# --- destructive.raw_device_write ---

raw_device_commands := {"dd", "shred", "blkdiscard"}

raw_whole_device_pattern := `^/dev/(sd[a-z]+[0-9]*|hd[a-z]+[0-9]*|vd[a-z]+[0-9]*|xvd[a-z]+[0-9]*|nvme[0-9]+n[0-9]+(p[0-9]+)?|mmcblk[0-9]+(p[0-9]+)?)$`

matches contains "destructive.raw_device_write" if {
	input.facts.command == "dd"
	some a in input.facts.args
	startswith(a, "of=")
	val := substring(a, count("of="), -1)
	regex.match(raw_whole_device_pattern, val)
}

matches contains "destructive.raw_device_write" if {
	input.facts.command in {"shred", "blkdiscard"}
	some a in input.facts.args
	regex.match(raw_whole_device_pattern, a)
}

# --- destructive.cargo_publish_unreviewed ---

matches contains "destructive.cargo_publish_unreviewed" if {
	input.facts.command == "cargo"
	count(input.facts.args) > 0
	input.facts.args[0] == "publish"
	not "--dry-run" in git_rest(input.facts.args)
}

matches contains "destructive.cargo_publish_unreviewed" if {
	input.facts.command == "cargo"
	count(input.facts.args) > 0
	input.facts.args[0] == "release"
	"--execute" in git_rest(input.facts.args)
}

# --- destructive.gem_push_unreviewed ---

matches contains "destructive.gem_push_unreviewed" if {
	input.facts.command == "gem"
	count(input.facts.args) > 0
	input.facts.args[0] == "push"
}

matches contains "destructive.gem_push_unreviewed" if {
	input.facts.command == "gem"
	count(input.facts.args) > 0
	input.facts.args[0] == "bump"
	"--push" in git_rest(input.facts.args)
}

matches contains "destructive.gem_push_unreviewed" if {
	input.facts.command == "rake"
	"release" in input.facts.args
}

matches contains "destructive.gem_push_unreviewed" if {
	input.facts.command == "bundle"
	some i, a in input.facts.args
	a == "rake"
	i + 1 < count(input.facts.args)
	input.facts.args[i + 1] == "release"
}

# --- destructive.webhook_exfiltration ---

webhook_url_pattern := `(?i)https?://(discord\.com/api/webhooks/|hooks\.slack\.com/services/|outlook\.office\.com/webhook/|[a-z0-9.-]+\.webhook\.office\.com/webhookb2/)`

webhook_data_flag_prefixes := [
	"-d", "--data", "--data-binary", "--data-raw", "-F", "--form",
	"--post-data", "--post-file", "-T", "--upload-file",
]

webhook_has_data_flag if {
	some a in input.facts.args
	some prefix in webhook_data_flag_prefixes
	a == prefix
}

webhook_has_data_flag if {
	some a in input.facts.args
	some prefix in webhook_data_flag_prefixes
	startswith(a, concat("", [prefix, "="]))
}

matches contains "destructive.webhook_exfiltration" if {
	input.facts.command in {"curl", "wget"}
	regex.match(webhook_url_pattern, input.facts.raw)
	webhook_has_data_flag
}
