package policy

import (
	"regexp"
	"strings"
)

// This file holds the rules added by the 2026-07 wave 2 dangerous-command-
// coverage expansion — six new categories (Kubernetes bulk deletion, cloud
// CLI mass-delete/terminate operations, raw block-device writes, unreviewed
// package-registry publishes for Cargo/RubyGems, and chat-webhook
// exfiltration) each grounded in a real, independently verified incident —
// grouped separately from rules_expansion.go's 2026-07 wave 1 set so this
// wave's diff and reasoning stay traceable to its own research rather than
// blending into wave 1's history.

// --- destructive.kubectl_bulk_delete ---
//
// Gustavo Zanotto's first-person postmortem (blog published Jan 19, 2024,
// describing a 2023 incident): using K9s in production he ran a kubectl
// delete against the wrong namespace ("ingress-system" instead of the
// intended "istio-system"), taking production ingress/load-balancing
// offline for ~40 minutes, and a subsequent ArgoCD auto-sync redeploy then
// deleted RabbitMQ's PersistentVolume, destroying its data (recovered from
// Velero backups). https://medium.com/@gustavo.zanotto/the-day-i-deleted-the-production-ingress-namespace-in-k8s-9ba4f56a7f05
//
// kubectlBulkDeleteResources are resource types whose bulk deletion
// (--all/--all-namespaces) can wipe an entire workload class in one
// command — deliberately narrow (deployments/pods/pvc/pv/"all") per this
// rule's scope, not every resource type kubectl knows about. The resource
// type is assumed to be the first positional argument after "delete", the
// overwhelmingly common invocation shape ("kubectl delete <type> ..."); a
// flag placed before the resource type (e.g. "kubectl delete -n prod
// deployment --all") would slip past this check, the same "simple,
// documented v1 heuristic" tradeoff as matchGitHistoryDestructive's
// f.Args[0] subcommand check.
var kubectlBulkDeleteResources = map[string]bool{
	"deployment": true, "deployments": true, "deploy": true,
	"pod": true, "pods": true, "po": true,
	"pvc": true, "pvcs": true, "persistentvolumeclaim": true, "persistentvolumeclaims": true,
	"pv": true, "pvs": true, "persistentvolume": true, "persistentvolumes": true,
	"all": true,
}

func matchKubectlBulkDelete(f Facts, _ Config) bool {
	if f.Command != "kubectl" || len(f.Args) == 0 || f.Args[0] != "delete" {
		return false
	}
	rest := f.Args[1:]
	if len(rest) == 0 {
		return false
	}
	// "kubectl delete namespace <name>" destroys the entire namespace (and
	// everything inside it) with nothing but the name — no --all flag is
	// needed at all, unlike the other resource types below.
	switch rest[0] {
	case "namespace", "namespaces", "ns":
		return true
	}
	if !kubectlBulkDeleteResources[rest[0]] {
		return false
	}
	return containsArg(rest, "--all") || containsArg(rest, "--all-namespaces")
}

// --- destructive.cloud_cli_mass_delete ---
//
// In July 2025 a compromised release (v1.84, live ~48 hours) of Amazon's
// own "Amazon Q Developer" VS Code extension shipped with an injected
// prompt that instructed the AI agent — invoked with --trust-all-tools
// --no-interactive — to discover local AWS profiles and run literal `aws
// ec2 terminate-instances`, `aws s3 rm`, and `aws iam delete-user`
// commands to wipe a user's cloud resources; AWS confirmed the tampering
// and pulled the release (The Register, 24 Jul 2025; corroborated with the
// exact command list by CybersecurityNews).
// https://www.theregister.com/2025/07/24/amazon_q_ai_prompt/
func matchCloudCLIMassDelete(f Facts, _ Config) bool {
	switch f.Command {
	case "aws":
		return matchAWSMassDelete(f.Args)
	case "gcloud":
		return matchGCloudMassDelete(f.Args)
	case "az":
		return matchAzMassDelete(f.Args)
	}
	return false
}

func matchAWSMassDelete(args []string) bool {
	if len(args) < 2 {
		return false
	}
	service, action, rest := args[0], args[1], args[2:]
	switch {
	case service == "ec2" && action == "terminate-instances":
		return true
	case service == "s3" && action == "rm":
		return containsArg(rest, "--recursive")
	case service == "s3" && action == "rb":
		return containsArg(rest, "--force")
	case service == "rds" && action == "delete-db-instance":
		return true
	}
	return false
}

// matchGCloudMassDelete assumes "compute instances delete" is contiguous —
// gcloud's own documented invocation shape ("gcloud compute instances
// delete INSTANCE_NAMES ... [--zone=ZONE]"), the same positional-assumption
// tradeoff as matchKubectlBulkDelete above.
func matchGCloudMassDelete(args []string) bool {
	return len(args) >= 3 && args[0] == "compute" && args[1] == "instances" && args[2] == "delete"
}

func matchAzMassDelete(args []string) bool {
	return len(args) >= 2 && args[0] == "vm" && args[1] == "delete"
}

// --- destructive.raw_device_write ---
//
// WhisperGate (threat actor DEV-0586, later renamed Cadet Blizzard) — first
// observed on Ukrainian government/organization systems on Jan 13, 2022; a
// two-stage wiper masquerading as ransomware that overwrites the Master
// Boot Record (Stage 1) with a fake ransom note and then destructively
// overwrites file contents (Stage 2), rendering devices inoperable with no
// real recovery mechanism, per Microsoft MSTIC's Jan 15, 2022 writeup — the
// exact raw-overwrite effect a `dd`/`shred`/`blkdiscard` write to a whole
// device would replicate.
// https://www.microsoft.com/en-us/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/
var rawDeviceCommands = map[string]bool{"dd": true, "shred": true, "blkdiscard": true}

// rawWholeDevicePattern matches a whole-disk (or disk-partition) block
// device path — /dev/sda, /dev/nvme0n1, /dev/vda1, /dev/xvdf, /dev/mmcblk0
// — deliberately excluding /dev/loop* devices, which are routinely operated
// on against a plain file-backed image in everyday dev/test workflows, not
// a physical device whose destruction is irreversible.
var rawWholeDevicePattern = regexp.MustCompile(`^/dev/(sd[a-z]+\d*|hd[a-z]+\d*|vd[a-z]+\d*|xvd[a-z]+\d*|nvme\d+n\d+(p\d+)?|mmcblk\d+(p\d+)?)$`)

func matchRawDeviceWrite(f Facts, _ Config) bool {
	if !rawDeviceCommands[f.Command] {
		return false
	}
	if f.Command == "dd" {
		for _, a := range f.Args {
			if val, ok := strings.CutPrefix(a, "of="); ok && rawWholeDevicePattern.MatchString(val) {
				return true
			}
		}
		return false
	}
	// shred and blkdiscard both take the device path as a bare operand.
	for _, a := range f.Args {
		if rawWholeDevicePattern.MatchString(a) {
			return true
		}
	}
	return false
}

// --- destructive.cargo_publish_unreviewed ---
//
// On 2025-12-05, a threat actor published the malicious crates finch-rust
// and sha-rust directly to crates.io — finch-rust impersonated the
// legitimate "finch" crate and loaded the sha-rust credential-exfiltration
// payload — before the crates.io team disabled the account and deleted
// both crates the same day.
// https://blog.rust-lang.org/2025/12/05/crates.io-malicious-crates-finch-rust-and-sha-rust/
func matchCargoPublishUnreviewed(f Facts, _ Config) bool {
	if f.Command != "cargo" || len(f.Args) == 0 {
		return false
	}
	rest := f.Args[1:]
	switch f.Args[0] {
	case "publish":
		// cargo publish --dry-run never actually publishes to crates.io —
		// it only validates and packages the crate locally.
		return !containsArg(rest, "--dry-run")
	case "release":
		// cargo-release defaults to a dry run; --execute is what actually
		// performs the version bump + publish.
		return containsArg(rest, "--execute")
	}
	return false
}

// --- destructive.gem_push_unreviewed ---
//
// In August 2019, an attacker who compromised a maintainer's RubyGems.org
// account used it to gem-push four malicious versions (1.6.10-1.6.13) of
// the popular rest-client gem, one of which (1.6.13) contained a
// credential-exfiltrating and cryptomining backdoor — tracked as
// CVE-2019-15224. https://github.com/rest-client/rest-client/issues/713
func matchGemPushUnreviewed(f Facts, _ Config) bool {
	switch f.Command {
	case "gem":
		if len(f.Args) == 0 {
			return false
		}
		rest := f.Args[1:]
		switch f.Args[0] {
		case "push":
			return true
		case "bump":
			return containsArg(rest, "--push")
		}
		return false
	case "rake":
		return containsArg(f.Args, "release")
	case "bundle":
		// "bundle exec rake release" — rake's own subcommand appears
		// somewhere after "exec", so this looks for the adjacent
		// "rake"/"release" pair rather than assuming a fixed position.
		for i, a := range f.Args {
			if a == "rake" && i+1 < len(f.Args) && f.Args[i+1] == "release" {
				return true
			}
		}
		return false
	}
	return false
}

// --- destructive.webhook_exfiltration ---
//
// Socket's Threat Research Team documented the npm package
// mysql-dumpdiscord (plus companion PyPI/RubyGems packages) reading
// .env/config.json/ayarlar.json and POSTing their contents as JSON to a
// hard-coded Discord incoming-webhook URL, part of a broader campaign
// weaponizing Discord webhooks as low-cost, unauthenticated C2/exfil
// infrastructure across npm, PyPI, and RubyGems.
// https://socket.dev/blog/weaponizing-discord-for-command-and-control
//
// webhookURLPattern is checked against Raw rather than Target/Domain since
// detecting this needs the URL *path* (/api/webhooks/, /services/), not
// just the bare domain — a domain-only check would also flag legitimate,
// authenticated API calls to the same hosts (e.g. Discord's bot REST API).
var webhookURLPattern = regexp.MustCompile(`(?i)https?://(discord\.com/api/webhooks/|hooks\.slack\.com/services/|outlook\.office\.com/webhook/|[a-z0-9.-]+\.webhook\.office\.com/webhookb2/)`)

// webhookDataFlagPrefixes are curl/wget flags that actually send a request
// body (POST data or an uploaded file) rather than just performing a GET —
// a bare GET against a webhook URL is harmless (most webhook providers
// respond to it with innocuous metadata), so this rule only fires when data
// is actually being sent.
var webhookDataFlagPrefixes = []string{
	"-d", "--data", "--data-binary", "--data-raw", "-F", "--form",
	"--post-data", "--post-file", "-T", "--upload-file",
}

func matchWebhookExfiltration(f Facts, _ Config) bool {
	if f.Command != "curl" && f.Command != "wget" {
		return false
	}
	if !webhookURLPattern.MatchString(f.Raw) {
		return false
	}
	for _, a := range f.Args {
		for _, prefix := range webhookDataFlagPrefixes {
			if a == prefix || strings.HasPrefix(a, prefix+"=") {
				return true
			}
		}
	}
	return false
}
