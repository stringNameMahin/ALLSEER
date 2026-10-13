package envelope

import (
	"fmt"
	"strings"

	"github.com/stringNameMahin/ALLSEER/pkg/capability"
)

// DescribeSelector renders a selector on one line for an approver.
func DescribeSelector(s capability.Selector) string {
	var parts []string
	add := func(label string, v []string) {
		if len(v) == 0 {
			return
		}
		const show = 6
		if len(v) > show {
			parts = append(parts, fmt.Sprintf("%s %s (+%d more)", label, strings.Join(v[:show], ", "), len(v)-show))
			return
		}
		parts = append(parts, label+" "+strings.Join(v, ", "))
	}
	add("paths", s.PathPatterns)
	add("hosts", s.Hosts)
	if len(s.Ports) > 0 {
		var ps []string
		for _, p := range s.Ports {
			ps = append(ps, fmt.Sprint(p))
		}
		add("ports", ps)
	}
	add("protocols", s.Protocols)
	add("executables", s.Executables)
	add("args", s.ArgPatterns)
	if s.MaxCount > 0 {
		parts = append(parts, fmt.Sprintf("at most %d times", s.MaxCount))
	}
	if len(parts) == 0 {
		return "(any target)"
	}
	return strings.Join(parts, "; ")
}
