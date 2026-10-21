package ci

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A made-up address: the tests must not need anyone's real one.
const leak = "leak.test@example.org"

const placeholder = "ALLSEER Maintainers <<placeholder>@gmail.com>"

// run runs a script from scripts/ci and returns its exit code and output.
func run(t *testing.T, path string, script string, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{"../../scripts/ci/" + script}, args...)...)
	if path != "" {
		cmd.Env = append(os.Environ(), "PATH="+path+":"+os.Getenv("PATH"))
	}
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0, string(out)
	case errors.As(err, &exit):
		return exit.ExitCode(), string(out)
	}
	t.Fatal(err)
	return 0, ""
}

// tree writes files, keyed by slash path, under a new directory.
func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0o644)
		if strings.HasPrefix(name, "usr/bin/") || strings.HasPrefix(name, "DEBIAN/post") {
			mode = 0o755
		}
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		// Not left to the umask: check-deb.sh checks modes.
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func needDpkgDeb(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("dpkg-deb"); err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("dpkg-deb is missing on a CI runner")
		}
		t.Skip("dpkg-deb not installed")
	}
}

// deb builds a package from files, which must include DEBIAN/control.
func deb(t *testing.T, files map[string]string) string {
	t.Helper()
	root := tree(t, files)
	out := filepath.Join(t.TempDir(), "test.deb")
	cmd := exec.Command("dpkg-deb", "--root-owner-group", "--build", root, out)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("dpkg-deb: %v\n%s", err, b)
	}
	return out
}

func control(maintainer string) string {
	return "Package: allseer\nVersion: 1.0\nArchitecture: all\nMaintainer: " + maintainer +
		"\nDepends: libc6\nDescription: test\n test package\n"
}

func gzipped(t *testing.T, s string) string {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// fakes puts scripts named after the tools they replace first on PATH.
func fakes(t *testing.T, tools map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range tools {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/bash\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestCheckEmailsOnFilesAndDirectories(t *testing.T) {
	clean := map[string]string{
		"DEBIAN/control":       control(placeholder),
		"etc/allseer/a.yaml":   "listen: /run/allseer.sock\nmodule: example.org/x@v1.2.3\n",
		"usr/bin/allseerd":     "\x7fELF\x00\x00+@reflect.Value.Bytes\x00CString@github.com/stringNameMahin/ALLSEER\x00",
		"usr/share/doc/a/note": "mail goes to nobody\n",
	}
	cases := []struct {
		name  string
		files map[string]string
		want  int
	}{
		{"clean", clean, 0},
		{"in a text file", map[string]string{"etc/a.yaml": "owner: " + leak + "\n"}, 1},
		{"as a path in a text file", map[string]string{"etc/a.yaml": "home: /home/" + leak + "/x\n"}, 1},
		{"in a binary", map[string]string{"usr/bin/x": "\x7fELF\x00" + leak + "\x00"}, 1},
		{"at the end of a file", map[string]string{"usr/bin/x": "\x7fELF\x00" + leak}, 1},
		{"other case", map[string]string{"etc/a": "Leak.Test@Example.ORG"}, 1},
		{"in a file name", map[string]string{"usr/share/doc/" + leak: "x"}, 1},
		{"in a file's name and contents", map[string]string{"usr/share/doc/" + leak + "/a": leak}, 1},
		{"in a gzip file", map[string]string{"usr/share/doc/changelog.gz": gzipped(t, leak)}, 1},
		{"gzip without an address", map[string]string{"usr/share/doc/changelog.gz": gzipped(t, "none")}, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out := run(t, "", "check-emails.sh", tree(t, c.files))
			if code != c.want {
				t.Fatalf("exit %d, want %d\n%s", code, c.want, out)
			}
			if strings.Contains(strings.ToLower(out), leak) {
				t.Errorf("the output shows the address:\n%s", out)
			}
		})
	}

	t.Run("one file", func(t *testing.T) {
		dir := tree(t, map[string]string{"bin/x": leak})
		if code, out := run(t, "", "check-emails.sh", filepath.Join(dir, "bin/x")); code != 1 {
			t.Fatalf("exit %d, want 1\n%s", code, out)
		}
	})
	t.Run("a clean path does not clear a dirty one", func(t *testing.T) {
		code, out := run(t, "", "check-emails.sh", tree(t, map[string]string{"a": leak}), tree(t, clean))
		if code != 1 {
			t.Fatalf("exit %d, want 1\n%s", code, out)
		}
	})
	for name, args := range map[string][]string{
		"no paths":  nil,
		"missing":   {filepath.Join(t.TempDir(), "absent")},
		"empty dir": {t.TempDir()},
	} {
		t.Run(name, func(t *testing.T) {
			if code, out := run(t, "", "check-emails.sh", args...); code == 0 {
				t.Fatalf("passed:\n%s", out)
			}
		})
	}
}

// tarball writes members, in order, to a new uncompressed tar.
func tarball(t *testing.T, members ...[2]string) string {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	for _, m := range members {
		if err := w.WriteHeader(&tar.Header{Name: m[0], Mode: 0o644, Size: int64(len(m[1]))}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(m[1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "build.tar")
	if err := os.WriteFile(p, b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCheckEmailsOnTarballsAndLinks(t *testing.T) {
	bin := [2]string{"bin/allseerd", "\x7fELF\x00"}
	big := [2]string{"bin/allseerctl", strings.Repeat("y", 8192)}
	type scan struct {
		name string
		path string
		want int // 2 stands for any failure that is not a finding
	}
	trunc := tarball(t, bin, big)
	if err := os.Truncate(trunc, 2048); err != nil {
		t.Fatal(err)
	}
	link := tree(t, map[string]string{"etc/a": "x"})
	if err := os.Symlink("/home/"+leak+"/a", filepath.Join(link, "etc/b")); err != nil {
		t.Fatal(err)
	}
	cases := []scan{
		{"clean tar", tarball(t, bin, big), 0},
		{"in a member", tarball(t, bin, [2]string{"bin/x", "\x00" + leak}), 1},
		{"gzip member", tarball(t, bin, [2]string{"doc/changelog.gz", gzipped(t, leak)}), 1},
		{"truncated tar", trunc, 2},
		{"symlink target", link, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out := run(t, "", "check-emails.sh", c.path)
			if (c.want == 2 && code == 0) || (c.want != 2 && code != c.want) {
				t.Fatalf("exit %d, want %d\n%s", code, c.want, out)
			}
			if strings.Contains(out, leak) {
				t.Errorf("the output shows the address:\n%s", out)
			}
		})
	}
}

func TestCheckEmailsOnPackages(t *testing.T) {
	needDpkgDeb(t)
	files := func(maintainer string, extra map[string]string) map[string]string {
		f := map[string]string{"DEBIAN/control": control(maintainer), "etc/allseer/a.yaml": "x: 1\n"}
		for k, v := range extra {
			f[k] = v
		}
		return f
	}
	cases := []struct {
		name  string
		files map[string]string
		want  int
	}{
		{"clean", files(placeholder, nil), 0},
		{"in Maintainer", files("Someone <"+leak+">", nil), 1},
		{"in the payload", files(placeholder, map[string]string{"etc/allseer/b.yaml": "by: " + leak}), 1},
		{"in a maintainer script", files(placeholder, map[string]string{"DEBIAN/postinst": "#!/bin/sh\n# " + leak + "\n"}), 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out := run(t, "", "check-emails.sh", deb(t, c.files))
			if code != c.want {
				t.Fatalf("exit %d, want %d\n%s", code, c.want, out)
			}
			if strings.Contains(out, leak) {
				t.Errorf("the output shows the address:\n%s", out)
			}
		})
	}

	t.Run("truncated", func(t *testing.T) {
		p := deb(t, files(placeholder, map[string]string{"etc/allseer/b.yaml": strings.Repeat("y", 4096)}))
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b[:len(b)/2], 0o644); err != nil {
			t.Fatal(err)
		}
		if code, out := run(t, "", "check-emails.sh", p); code == 0 {
			t.Fatalf("passed:\n%s", out)
		}
	})
}

// A tool that fails must fail the check, never let it pass unsearched.
func TestCheckEmailsFailsWhenAToolFails(t *testing.T) {
	needDpkgDeb(t)
	grep, err := exec.LookPath("grep")
	if err != nil {
		t.Fatal(err)
	}
	dir := tree(t, map[string]string{"etc/a.yaml": "x: 1\n"})
	pkg := deb(t, map[string]string{"DEBIAN/control": control(placeholder), "etc/a.yaml": "x: 1\n"})
	if code, out := run(t, "", "check-emails.sh", dir, pkg); code != 0 {
		t.Fatalf("clean inputs failed: exit %d\n%s", code, out)
	}
	// failOn makes grep fail when one of its short options is flag.
	failOn := func(flag string) string {
		return `for a in "$@"; do [[ $a == -* && $a != --* && $a == *` + flag + `* ]] && exit 2; done; exec ` +
			grep + ` "$@"`
	}
	cases := []struct {
		name  string
		tools map[string]string
		want  string
	}{
		{"grep always fails", map[string]string{"grep": "exit 2"}, "does not match a known address"},
		{"recursive grep fails", map[string]string{"grep": failOn("r")}, ": the search failed"},
		{"file name grep fails", map[string]string{"grep": failOn("z")}, "the file name search failed"},
		{"find fails", map[string]string{"find": "exit 1"}, "cannot list"},
		{"od fails", map[string]string{"od": "exit 1"}, "cannot read"},
		{"sort fails", map[string]string{"sort": "exit 1"}, ": the search failed"},
		{"dpkg-deb fails", map[string]string{"dpkg-deb": "exit 2"}, "cannot extract"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out := run(t, fakes(t, c.tools), "check-emails.sh", dir, pkg)
			if code == 0 || !strings.Contains(out, c.want) {
				t.Fatalf("exit %d, want a failure saying %q:\n%s", code, c.want, out)
			}
		})
	}
}

// check-deb.sh is the guard make deb runs: it must refuse a package that
// carries an address or a Maintainer other than the placeholder.
func TestCheckDebRefusesAnIdentity(t *testing.T) {
	needDpkgDeb(t)
	files := func(maintainer string, extra map[string]string) map[string]string {
		f := map[string]string{
			"DEBIAN/control":                          control(maintainer),
			"DEBIAN/conffiles":                        "/etc/allseer/allseerd.yaml\n/etc/allseer/rules.yaml\n/etc/allseer/sensitivity.yaml\n",
			"usr/bin/allseerd":                        "\x7fELF",
			"usr/bin/allseer-shim":                    "\x7fELF",
			"usr/bin/allseerctl":                      "\x7fELF",
			"usr/lib/allseer/allseer.bpf.o":           "\x7fELF",
			"usr/lib/systemd/system/allseerd.service": "[Service]\n",
			"etc/allseer/allseerd.yaml":               "x: 1\n",
			"etc/allseer/rules.yaml":                  "x: 1\n",
			"etc/allseer/sensitivity.yaml":            "x: 1\n",
			"var/lib/allseer/.keep":                   "",
		}
		for k, v := range extra {
			f[k] = v
		}
		return f
	}
	build := func(t *testing.T, f map[string]string) string {
		root := tree(t, f)
		if err := os.Remove(filepath.Join(root, "var/lib/allseer/.keep")); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(root, "var/lib/allseer"), 0o700); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(t.TempDir(), "allseer.deb")
		if b, err := exec.Command("dpkg-deb", "--root-owner-group", "--build", root, out).CombinedOutput(); err != nil {
			t.Fatalf("dpkg-deb: %v\n%s", err, b)
		}
		return out
	}
	cases := []struct {
		name  string
		files map[string]string
		want  int
	}{
		{"clean", files(placeholder, nil), 0},
		{"address as Maintainer", files("Someone <"+leak+">", nil), 1},
		{"another Maintainer", files("Someone Else", nil), 1},
		{"address in the payload", files(placeholder, map[string]string{"etc/allseer/rules.yaml": "# " + leak + "\n"}), 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out := run(t, "", "check-deb.sh", build(t, c.files))
			if code != c.want {
				t.Fatalf("exit %d, want %d\n%s", code, c.want, out)
			}
			if strings.Contains(out, leak) {
				t.Errorf("the output shows the address:\n%s", out)
			}
		})
	}
}
