package policy

import (
	"fmt"
	"os"

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

	raw, err := os.ReadFile(path)
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
	return os.WriteFile(path, out, 0o600)
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
