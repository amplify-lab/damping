package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/amplify-lab/damping/core/decision"
)

// AppendAlwaysPattern appends pattern to the always_allow or always_deny
// list (depending on verdict) in the policy YAML file at path — this is
// what a [A]/[D] response to the TTY prompt persists (see cli/ui and
// docs/cli-reference.md §12).
//
// This edits the file via yaml.Node surgery rather than a full
// unmarshal-into-Config-then-marshal-back-out round trip: the latter would
// silently drop every comment in the file and reorder/reformat keys, which
// is unacceptable for a file whose header comments explain the matcher
// model (see cli/policies/default.yaml). Only the target sequence node is
// mutated; everything else in the document tree — comments, ordering,
// quoting style — passes through untouched.
func AppendAlwaysPattern(path string, verdict decision.Verdict, pattern string) error {
	key, err := alwaysKeyFor(verdict)
	if err != nil {
		return err
	}

	// matchGlobPattern (patterns.go) treats any entry ending in "*" as a
	// prefix wildcard — the vocabulary documented for hand-authored
	// always_allow/always_deny entries in cli/policies/default.yaml. An
	// auto-persisted pattern is meant to mean "this exact command, nothing
	// broader" (docs/cli-reference.md §12), so if the approved raw command
	// itself happens to end in a literal "*" (a realistic shell glob, e.g.
	// "rm -rf ./dist/*"), silently appending it here would have it
	// reinterpreted as a broader wildcard match the moment the policy file
	// is next reloaded — a real, silent scope-broadening the human never
	// approved. Refusing outright is safer than persisting something whose
	// on-disk meaning secretly diverges from what was actually confirmed;
	// both call sites (cli/cmd/hook.go, cli/adapter/mcp/wrap.go's
	// resolvePrompt) already surface this error the same way they surface
	// any other persist failure.
	if strings.HasSuffix(pattern, "*") {
		return fmt.Errorf("policy: cannot persist %q as an exact always-%s pattern — it ends in \"*\", which would be reinterpreted as a wildcard on reload", pattern, key[len("always_"):])
	}

	raw, err := os.ReadFile(path) // #nosec G304 -- path is the local user's own policy file (~/.damping default or their own --config flag), not an attacker-influenced path; no cross-trust-boundary traversal risk
	if err != nil {
		return fmt.Errorf("policy: reading %s: %w", path, err)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("policy: parsing %s: %w", path, err)
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("policy: %s is not a YAML mapping document", path)
	}
	root := doc.Content[0]

	seq := findMappingValue(root, key)
	if seq == nil || seq.Kind != yaml.SequenceNode {
		return fmt.Errorf("policy: %s has no top-level %q sequence to append to", path, key)
	}

	for _, item := range seq.Content {
		if item.Value == pattern {
			return nil // already persisted; nothing to do
		}
	}
	seq.Content = append(seq.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: pattern})

	out, err := yaml.Marshal(&doc)
	if err != nil {
		return fmt.Errorf("policy: encoding %s: %w", path, err)
	}
	return writeFileAtomically(path, out)
}

// writeFileAtomically writes to a temp file in the same directory as path
// (so the final rename is on the same filesystem, which POSIX guarantees is
// atomic) and renames it into place, rather than writing path directly.
// Found via code review: a plain os.WriteFile truncates the destination
// before writing its new content, so a crash or a concurrent reader hitting
// the file mid-write can see a corrupt or empty policy file — the one file
// this whole tool depends on being loadable. This does not by itself
// serialize concurrent *writers* (two processes appending different
// patterns at once can still race, with one update winning), but it does
// guarantee every reader always sees either the old complete file or the
// new complete file, never a partial one.
func writeFileAtomically(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".damping-policy-*.tmp")
	if err != nil {
		return fmt.Errorf("policy: creating temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }() // no-op once the rename below succeeds

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close() // already returning the real error below; best-effort cleanup
		return fmt.Errorf("policy: writing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("policy: closing temp file: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return fmt.Errorf("policy: setting permissions on temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("policy: renaming temp file into place: %w", err)
	}
	return nil
}

func alwaysKeyFor(v decision.Verdict) (string, error) {
	switch v {
	case decision.Allow:
		return "always_allow", nil
	case decision.Deny:
		return "always_deny", nil
	default:
		return "", fmt.Errorf("policy: cannot persist a pattern for verdict %q (only allow/deny make sense)", v)
	}
}

func findMappingValue(mapping *yaml.Node, key string) *yaml.Node {
	if mapping.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1]
		}
	}
	return nil
}
