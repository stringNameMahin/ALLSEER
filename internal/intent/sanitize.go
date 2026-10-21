package intent

import (
	"context"
	"fmt"
	"strings"
	"unicode"
)

// RuleSanitizer is the deterministic Sanitizer.
//
// It does two things. It removes characters a reader cannot see: format
// characters such as zero-width spaces and the bidirectional overrides that
// can make a prompt read differently on screen than to a program, and control
// characters other than newline and tab. And it flags phrases addressed to the
// governor rather than to the task: instructions to ignore earlier text, to
// stop monitoring, or to grant broad access.
//
// Flagged phrases are left in the prompt. The analyzer cannot grant anything
// itself and the generator is bounded by the catalog, so the defence that
// matters is a human seeing the indicator before approving the envelope.
// Rewriting the text would change what was asked without saying so.
type RuleSanitizer struct{}

var _ Sanitizer = RuleSanitizer{}

// governorPhrases are matched case-insensitively against the prompt with runs
// of whitespace collapsed.
var governorPhrases = []string{
	"ignore previous instructions", "ignore all previous", "ignore the above", "ignore prior instructions",
	"disregard previous", "disregard the above", "disregard all prior", "forget your instructions",
	"new instructions:", "system prompt", "you are now",
	"disable allseer", "stop allseer", "turn off allseer", "bypass allseer",
	"disable monitoring", "turn off monitoring", "without monitoring", "do not monitor",
	"grant full access", "grant all permissions", "unrestricted access", "full network access",
	"full filesystem access", "allow everything", "approve everything",
}

// Sanitize implements Sanitizer.
func (RuleSanitizer) Sanitize(_ context.Context, prompt string) (string, []string, error) {
	var (
		b       strings.Builder
		removed int
	)
	for _, r := range prompt {
		if hidden(r) {
			removed++
			continue
		}
		b.WriteRune(r)
	}
	clean := b.String()

	var indicators []string
	if removed > 0 {
		indicators = append(indicators, fmt.Sprintf("%d invisible or direction-changing characters were removed before analysis", removed))
	}
	flat := strings.ToLower(strings.Join(strings.Fields(clean), " "))
	for _, p := range governorPhrases {
		if strings.Contains(flat, p) {
			indicators = append(indicators, fmt.Sprintf("the prompt addresses the governor rather than the task: %q", p))
		}
	}
	return clean, indicators, nil
}

// hidden reports characters that change what a program reads without changing
// what a person sees.
func hidden(r rune) bool {
	if r == '\n' || r == '\t' {
		return false
	}
	return unicode.Is(unicode.Cf, r) || unicode.IsControl(r)
}
