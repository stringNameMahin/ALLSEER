package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stringNameMahin/ALLSEER/internal/config"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
)

// openRotating opens a sink that rotates at limit bytes. The configuration is
// in megabytes, so the limit is set on the sink directly.
func openRotating(t *testing.T, limit int64, keep int) (*JSONLSink, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s, err := Open(config.AuditConfig{Path: path, RecordAllEvents: true, MaxSizeMB: 1, MaxFiles: keep})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	s.maxBytes, s.limit = limit, limit
	return s, path
}

// emit writes n numbered records of roughly 330 bytes each.
func emit(t *testing.T, s *JSONLSink, from, n int) {
	t.Helper()
	for i := from; i < from+n; i++ {
		r := decision.SessionEnd{SessionID: fmt.Sprintf("s-%03d", i), Reason: strings.Repeat("x", 150)}
		if err := s.EmitRecord(context.Background(), r); err != nil {
			t.Fatal(err)
		}
	}
}

// readLog returns the session IDs in the live file and every rotated one,
// oldest first, failing on any line that is not a whole record.
func readLog(t *testing.T, path string) (ids []string, files int) {
	t.Helper()
	var names []string
	for i := 1; ; i++ {
		p := fmt.Sprintf("%s.%d", path, i)
		if _, err := os.Stat(p); err != nil {
			break
		}
		names = append([]string{p}, names...)
	}
	names = append(names, path)
	for _, p := range names {
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			var r decision.SessionEnd
			if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
				t.Fatalf("%s holds a line that is not a whole record: %v\n%s", p, err, sc.Bytes())
			}
			ids = append(ids, r.SessionID)
		}
		f.Close()
	}
	return ids, len(names)
}

func sequence(from, to int) []string {
	var out []string
	for i := from; i < to; i++ {
		out = append(out, fmt.Sprintf("s-%03d", i))
	}
	return out
}

// Every record survives rotation, whole and in order, and no file passes the
// limit by more than the record that started it.
func TestRotationKeepsEveryRecordWholeAndInOrder(t *testing.T) {
	s, path := openRotating(t, 1000, 0)
	emit(t, s, 0, 20)
	ids, files := readLog(t, path)
	if fmt.Sprint(ids) != fmt.Sprint(sequence(0, 20)) {
		t.Fatalf("records across %d files = %v", files, ids)
	}
	if files < 4 {
		t.Fatalf("%d files for about 5000 bytes at a 1000 byte limit", files)
	}
	for i := 1; i < files; i++ {
		fi, err := os.Stat(fmt.Sprintf("%s.%d", path, i))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Size() > 1000 {
			t.Errorf("%s.%d is %d bytes, over the 1000 byte limit", path, i, fi.Size())
		}
	}
	if st := s.Stats(); st.Rotations != uint64(files-1) || st.RotationFailures != 0 || st.Errors != 0 {
		t.Errorf("stats = %+v, want %d rotations and no failures", st, files-1)
	}
}

// max_files bounds the disk: the oldest rotated file is deleted, and so are
// files an earlier, larger max_files left behind.
func TestRotationKeepsAtMostMaxFiles(t *testing.T) {
	s, path := openRotating(t, 1000, 2)
	for _, stale := range []string{".3", ".4"} {
		if err := os.WriteFile(path+stale, []byte("{}\n"), FileMode); err != nil {
			t.Fatal(err)
		}
	}
	emit(t, s, 0, 30)
	for _, stale := range []string{".3", ".4"} {
		if _, err := os.Stat(path + stale); err == nil {
			t.Fatalf("%s%s was kept with max_files 2", path, stale)
		}
	}
	ids, files := readLog(t, path)
	if files != 3 {
		t.Fatalf("%d files, want the live one and two rotated", files)
	}
	if len(ids) == 0 || ids[len(ids)-1] != "s-029" || fmt.Sprint(ids) != fmt.Sprint(sequence(30-len(ids), 30)) {
		t.Fatalf("kept records = %v, want an unbroken run ending at the newest", ids)
	}
}

// A log already over its limit when the daemon starts rotates on the first
// write, not after another full file.
func TestAnOversizedLogRotatesOnFirstWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	old, err := json.Marshal(decision.SessionEnd{SessionID: "s-old", Reason: strings.Repeat("y", 1200)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(old, '\n'), FileMode); err != nil {
		t.Fatal(err)
	}
	s, err := Open(config.AuditConfig{Path: path, RecordAllEvents: true, MaxSizeMB: 1, MaxFiles: 3})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.maxBytes, s.limit = 1000, 1000
	emit(t, s, 0, 1)
	ids, files := readLog(t, path)
	if files != 2 || fmt.Sprint(ids) != "[s-old s-000]" {
		t.Fatalf("after one write: %d files, %v", files, ids)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != FileMode {
		t.Errorf("the new file has mode %v, want %v", fi.Mode().Perm(), FileMode)
	}
}

// A rotation that cannot complete loses nothing: the record goes to the
// current file, each failure is counted and reported, and it is retried after
// another limit's worth of growth rather than on every record.
func TestRotationFailureKeepsWritingAndIsReported(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root renames in a read-only directory")
	}
	s, path := openRotating(t, 1000, 3)
	var reported []error
	s.OnRotationError(func(err error) { reported = append(reported, err) })
	emit(t, s, 0, 2)

	dir := filepath.Dir(path)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	emit(t, s, 2, 6)

	ids, files := readLog(t, path)
	if files != 1 || fmt.Sprint(ids) != fmt.Sprint(sequence(0, 8)) {
		t.Fatalf("%d files holding %v, want every record in the live file", files, ids)
	}
	// Six records past the limit, each about a third of it: retried once per
	// limit's worth of growth, so three attempts. Per record would be six.
	st := s.Stats()
	if st.RotationFailures == 0 || st.RotationFailures >= 6 || len(reported) != int(st.RotationFailures) || st.Errors != 0 {
		t.Fatalf("stats %+v, %d reported, want a few reported failures, fewer than one per record, and no write errors",
			st, len(reported))
	}
}
