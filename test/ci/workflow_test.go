// Package ci tests the CI workflow and the scripts it runs.
package ci

import (
	"fmt"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// scripts/ci/tools.sh builds libbpf from source, which needs these headers.
// A host that has them hides a job that does not install them: 63550a8 made
// ci-lint build libbpf and only GitHub saw the missing headers.
var libbpfHeaders = []string{"libelf-dev", "zlib1g-dev"}

type workflow struct {
	Jobs map[string]struct {
		Steps []struct {
			Run string `yaml:"run"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

var (
	ruleLine   = regexp.MustCompile(`^([A-Za-z0-9_.-]+(?:[ \t]+[A-Za-z0-9_.-]+)*)[ \t]*:(.*)$`)
	assignment = regexp.MustCompile(`^[ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*[:+?]?=`)
)

// recipes maps each Makefile target to its recipe commands, with backslash
// continuations joined.
func recipes(makefile string) map[string][]string {
	out := map[string][]string{}
	var targets []string
	var cmd strings.Builder
	for _, line := range strings.Split(makefile, "\n") {
		if strings.HasPrefix(line, "\t") {
			if targets == nil {
				continue
			}
			cmd.WriteString(strings.TrimSuffix(line, "\\") + " ")
			if !strings.HasSuffix(line, "\\") {
				for _, t := range targets {
					out[t] = append(out[t], cmd.String())
				}
				cmd.Reset()
			}
			continue
		}
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = nil
		m := ruleLine.FindStringSubmatch(line)
		if m == nil || strings.HasPrefix(m[2], "=") || strings.HasPrefix(m[2], ":") || assignment.MatchString(m[2]) {
			continue
		}
		targets = strings.Fields(m[1])
	}
	return out
}

// commandArgs cuts words at the end of the shell command they start.
func commandArgs(words []string) []string {
	for i, w := range words {
		switch {
		case w == ";" || w == "&&" || w == "||" || w == "|":
			return words[:i]
		case strings.HasSuffix(w, ";"):
			return append(words[:i:i], strings.TrimSuffix(w, ";"))
		}
	}
	return words
}

// buildsLibbpf reports whether target, or a target its recipe runs with
// $(MAKE), runs scripts/ci/tools.sh for libbpf or for every tool.
func buildsLibbpf(r map[string][]string, target string, seen map[string]bool) bool {
	if seen[target] {
		return false
	}
	seen[target] = true
	for _, cmd := range r[target] {
		words := strings.Fields(cmd)
		for i, w := range words {
			args := commandArgs(words[i+1:])
			switch {
			case strings.HasSuffix(w, "scripts/ci/tools.sh"):
				if len(args) == 0 || slices.Contains(args, "libbpf") {
					return true
				}
			case w == "$(MAKE)":
				for _, a := range args {
					if !strings.HasPrefix(a, "-") && !strings.Contains(a, "=") && buildsLibbpf(r, a, seen) {
						return true
					}
				}
			}
		}
	}
	return false
}

// missingHeaders returns one problem per header package a job lacks when a
// make step builds libbpf, counting only apt-get installs in earlier steps.
// checked is the number of make targets found to build libbpf.
func missingHeaders(workflowYAML, makefile []byte) (problems []string, checked int, err error) {
	var wf workflow
	if err := yaml.Unmarshal(workflowYAML, &wf); err != nil {
		return nil, 0, err
	}
	r := recipes(string(makefile))
	for _, name := range slices.Sorted(maps.Keys(wf.Jobs)) {
		installed := map[string]bool{}
		for _, step := range wf.Jobs[name].Steps {
			for _, line := range strings.Split(strings.ReplaceAll(step.Run, "\\\n", " "), "\n") {
				words := strings.Fields(line)
				if i := slices.Index(words, "install"); i > 0 && slices.Contains(words[:i], "apt-get") {
					for _, w := range words[i+1:] {
						installed[w] = true
					}
				}
				if len(words) == 0 || words[0] != "make" {
					continue
				}
				for _, target := range words[1:] {
					if strings.HasPrefix(target, "-") || strings.Contains(target, "=") ||
						!buildsLibbpf(r, target, map[string]bool{}) {
						continue
					}
					checked++
					for _, pkg := range libbpfHeaders {
						if !installed[pkg] {
							problems = append(problems, fmt.Sprintf(
								"job %s: make %s builds libbpf, but no earlier step installs %s", name, target, pkg))
						}
					}
				}
			}
		}
	}
	return problems, checked, nil
}

func TestJobsThatBuildLibbpfInstallItsHeaders(t *testing.T) {
	wf, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	mk, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	problems, checked, err := missingHeaders(wf, mk)
	if err != nil {
		t.Fatal(err)
	}
	// No job building libbpf means the parsing broke, not that all is well.
	if checked == 0 {
		t.Fatal("no workflow step was found to build libbpf")
	}
	for _, p := range problems {
		t.Error(p)
	}
}

const sampleMakefile = `
LDFLAGS := -s \
	-X a=b

.PHONY: direct
direct: ## builds libbpf
	./scripts/ci/tools.sh golangci-lint libbpf

all-tools:
	@./scripts/ci/tools.sh

nested:
	$(MAKE) other DESTDIR=x
	CPATH=y $(MAKE) direct

other:
	go build ./...
EXTRA := a \
	./scripts/ci/tools.sh libbpf

other-tools:
	./scripts/ci/tools.sh gitleaks && echo libbpf

direct other: CGO_LDFLAGS :=
`

func TestMissingHeadersFindsEachGap(t *testing.T) {
	apt := "      - run: sudo apt-get install -y -q libelf-dev zlib1g-dev\n"
	job := func(steps ...string) string {
		return "jobs:\n  j:\n    steps:\n" + strings.Join(steps, "")
	}
	cases := []struct {
		name     string
		workflow string
		problems int
		checked  int
	}{
		{"installed", job(apt, "      - run: make direct\n"), 0, 1},
		{"not installed", job("      - run: make direct\n"), 2, 1},
		{"one of two", job("      - run: sudo apt-get install libelf-dev\n", "      - run: make direct\n"), 1, 1},
		{"installed after", job("      - run: make direct\n", apt), 2, 1},
		{"split apt line", job("      - run: |\n          sudo apt-get install -y \\\n            libelf-dev zlib1g-dev\n", "      - run: make direct\n"), 0, 1},
		{"through $(MAKE)", job("      - run: make nested\n"), 2, 1},
		{"every tool", job("      - run: make all-tools\n"), 2, 1},
		{"no libbpf", job("      - run: make other other-tools\n"), 0, 0},
		{"multi-line run", job("      - run: |\n          echo start\n          make direct\n"), 2, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			problems, checked, err := missingHeaders([]byte(c.workflow), []byte(sampleMakefile))
			if err != nil {
				t.Fatal(err)
			}
			if len(problems) != c.problems || checked != c.checked {
				t.Errorf("got %d problems (%q) and %d checked, want %d and %d",
					len(problems), problems, checked, c.problems, c.checked)
			}
		})
	}
}
