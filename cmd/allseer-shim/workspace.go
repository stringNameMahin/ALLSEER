package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/stringNameMahin/ALLSEER/internal/intent"
)

// markers map a top-level file name to the language and build system it
// implies. Only names are read, never contents: file contents reaching the
// analyzer would be a prompt injection channel.
var markers = map[string][2]string{
	"go.mod":           {"go", "go"},
	"package.json":     {"javascript", "npm"},
	"tsconfig.json":    {"typescript", ""},
	"pyproject.toml":   {"python", "python"},
	"requirements.txt": {"python", "pip"},
	"setup.py":         {"python", "python"},
	"Cargo.toml":       {"rust", "cargo"},
	"pom.xml":          {"java", "maven"},
	"build.gradle":     {"java", "gradle"},
	"Makefile":         {"", "make"},
	"CMakeLists.txt":   {"c", "cmake"},
}

func isSensitiveName(n string) bool {
	l := strings.ToLower(n)
	return strings.HasPrefix(l, ".env") || strings.HasSuffix(l, ".pem") || strings.HasSuffix(l, ".key") ||
		l == ".ssh" || l == ".aws" || l == ".npmrc" || l == ".netrc" || strings.Contains(l, "secret") ||
		strings.HasPrefix(l, "id_rsa") || strings.HasPrefix(l, "id_ed25519")
}

func gatherWorkspace(root string) intent.WorkspaceContext {
	var wc intent.WorkspaceContext
	entries, err := os.ReadDir(root)
	if err != nil {
		return wc
	}
	langs, builds := map[string]bool{}, map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if m, ok := markers[name]; ok {
			if m[0] != "" {
				langs[m[0]] = true
			}
			if m[1] != "" {
				builds[m[1]] = true
			}
		}
		if name == ".git" {
			wc.HasVCS = true
		}
		if isSensitiveName(name) {
			wc.SensitivePaths = append(wc.SensitivePaths, filepath.Join(root, name))
		}
		if e.IsDir() && !strings.HasPrefix(name, ".") && len(wc.TopLevelDirs) < 64 {
			wc.TopLevelDirs = append(wc.TopLevelDirs, name)
		}
	}
	for l := range langs {
		wc.Languages = append(wc.Languages, l)
	}
	for b := range builds {
		wc.BuildSystems = append(wc.BuildSystems, b)
	}
	sort.Strings(wc.Languages)
	sort.Strings(wc.BuildSystems)
	return wc
}
