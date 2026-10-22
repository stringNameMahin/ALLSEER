package ci

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func needRPM(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"rpmbuild", "rpm", "rpm2cpio", "cpio"} {
		if _, err := exec.LookPath(tool); err != nil {
			if os.Getenv("CI") != "" {
				t.Fatalf("%s is missing on a CI runner", tool)
			}
			t.Skipf("%s not installed", tool)
		}
	}
}

// rpmSpec is what a test package is built from. files is staged and packed;
// filesSection, when set, replaces the plain list of them.
type rpmSpec struct {
	packager     string
	buildhost    bool // keep the real build host instead of the fixed name
	files        map[string]string
	filesSection string
	scripts      string
}

// buildRPM builds a noarch package from s and returns its path.
func buildRPM(t *testing.T, s rpmSpec) string {
	t.Helper()
	stage := tree(t, s.files)
	if err := os.MkdirAll(filepath.Join(stage, "var/lib/allseer"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(stage, "var/lib/allseer"), 0o700); err != nil {
		t.Fatal(err)
	}
	section := s.filesSection
	if section == "" {
		var names []string
		for name := range s.files {
			names = append(names, "/"+name)
		}
		sort.Strings(names)
		section = strings.Join(names, "\n")
	}
	var spec strings.Builder
	if !s.buildhost {
		spec.WriteString("%define _buildhost allseer-build\n")
	}
	spec.WriteString("%define debug_package %{nil}\n%global __os_install_post %{nil}\n" +
		"Name: allseer\nVersion: 1.0\nRelease: 1\nSummary: test\nLicense: NOASSERTION\n" +
		"URL: https://example.org/allseer\nBuildArch: noarch\nPackager: " + s.packager + "\n" +
		"%description\ntest package\n%install\ncp -a " + stage + "/. %{buildroot}/\n" +
		s.scripts + "%files\n%defattr(-,root,root,-)\n" + section + "\n")
	top, out := t.TempDir(), t.TempDir()
	specPath := filepath.Join(top, "t.spec")
	if err := os.WriteFile(specPath, []byte(spec.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("rpmbuild", "-bb", "--quiet", "--define", "_topdir "+top, "--define", "_rpmdir "+out,
		"--define", "_build_name_fmt test.rpm", specPath)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("rpmbuild: %v\n%s", err, b)
	}
	return filepath.Join(out, "test.rpm")
}

func TestCheckEmailsOnRPMPackages(t *testing.T) {
	needRPM(t)
	payload := map[string]string{"etc/allseer/a.yaml": "x: 1\n"}
	cases := []struct {
		name string
		spec rpmSpec
		want int
	}{
		{"clean", rpmSpec{packager: placeholder, files: payload}, 0},
		{"in Packager", rpmSpec{packager: "Someone <" + leak + ">", files: payload}, 1},
		{"in the payload", rpmSpec{packager: placeholder, files: map[string]string{"etc/allseer/b.yaml": "by: " + leak}}, 1},
		{"in a scriptlet", rpmSpec{packager: placeholder, files: payload, scripts: "%post\necho " + leak + "\n"}, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out := run(t, "", "check-emails.sh", buildRPM(t, c.spec))
			if code != c.want {
				t.Fatalf("exit %d, want %d\n%s", code, c.want, out)
			}
			if strings.Contains(out, leak) {
				t.Errorf("the output shows the address:\n%s", out)
			}
		})
	}

	clean := buildRPM(t, rpmSpec{packager: placeholder, files: map[string]string{"etc/allseer/b.yaml": strings.Repeat("y", 8192)}})
	t.Run("truncated", func(t *testing.T) {
		b, err := os.ReadFile(clean)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(t.TempDir(), "cut.rpm")
		if err := os.WriteFile(p, b[:len(b)/2], 0o644); err != nil {
			t.Fatal(err)
		}
		if code, out := run(t, "", "check-emails.sh", p); code == 0 {
			t.Fatalf("passed:\n%s", out)
		}
	})
	for name, tools := range map[string]map[string]string{
		"rpm fails":      {"rpm": "exit 1"},
		"rpm2cpio fails": {"rpm2cpio": "exit 1"},
		"cpio fails":     {"cpio": "cat >/dev/null; exit 2"},
	} {
		t.Run(name, func(t *testing.T) {
			code, out := run(t, fakes(t, tools), "check-emails.sh", clean)
			if code == 0 || !strings.Contains(out, "cannot extract") {
				t.Fatalf("exit %d, want a failure saying it cannot extract:\n%s", code, out)
			}
		})
	}
	t.Run("not named .rpm", func(t *testing.T) {
		b, err := os.ReadFile(clean)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "package"), b, 0o644); err != nil {
			t.Fatal(err)
		}
		if code, out := run(t, "", "check-emails.sh", dir); code == 0 || !strings.Contains(out, "cannot be searched") {
			t.Fatalf("exit %d, want it refused as unsearchable:\n%s", code, out)
		}
	})
}

// check-rpm.sh is the guard make rpm runs, as check-deb.sh is for the .deb.
func TestCheckRPMRefusesAnIdentity(t *testing.T) {
	needRPM(t)
	files := map[string]string{
		"usr/bin/allseerd":                        "\x7fELF",
		"usr/bin/allseer-shim":                    "\x7fELF",
		"usr/bin/allseerctl":                      "\x7fELF",
		"usr/lib/allseer/allseer.bpf.o":           "\x7fELF",
		"usr/lib/systemd/system/allseerd.service": "[Service]\n",
		"etc/allseer/allseerd.yaml":               "x: 1\n",
		"etc/allseer/rules.yaml":                  "x: 1\n",
		"etc/allseer/sensitivity.yaml":            "x: 1\n",
	}
	section := func(config string) string {
		return "/usr/bin/allseerd\n/usr/bin/allseer-shim\n/usr/bin/allseerctl\n" +
			"/usr/lib/allseer/allseer.bpf.o\n/usr/lib/systemd/system/allseerd.service\n" +
			config + " /etc/allseer/allseerd.yaml\n" + config + " /etc/allseer/rules.yaml\n" +
			config + " /etc/allseer/sensitivity.yaml\n%dir %attr(0700,root,root) /var/lib/allseer"
	}
	with := func(extra map[string]string) map[string]string {
		f := map[string]string{}
		for k, v := range files {
			f[k] = v
		}
		for k, v := range extra {
			f[k] = v
		}
		return f
	}
	cases := []struct {
		name string
		spec rpmSpec
		want int
	}{
		{"clean", rpmSpec{packager: placeholder, files: files, filesSection: section("%config(noreplace)")}, 0},
		{"address as Packager", rpmSpec{packager: "Someone <" + leak + ">", files: files, filesSection: section("%config(noreplace)")}, 1},
		{"another Packager", rpmSpec{packager: "Someone Else", files: files, filesSection: section("%config(noreplace)")}, 1},
		{"build host recorded", rpmSpec{packager: placeholder, buildhost: true, files: files, filesSection: section("%config(noreplace)")}, 1},
		{"config replaced on upgrade", rpmSpec{packager: placeholder, files: files, filesSection: section("%config")}, 1},
		{"address in the payload", rpmSpec{packager: placeholder, files: with(map[string]string{"etc/allseer/rules.yaml": "# " + leak + "\n"}),
			filesSection: section("%config(noreplace)")}, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out := run(t, "", "check-rpm.sh", buildRPM(t, c.spec))
			if code != c.want {
				t.Fatalf("exit %d, want %d\n%s", code, c.want, out)
			}
			if strings.Contains(out, leak) {
				t.Errorf("the output shows the address:\n%s", out)
			}
		})
	}
}
