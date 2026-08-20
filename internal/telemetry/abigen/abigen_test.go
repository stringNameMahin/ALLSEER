package abigen

import (
	"strings"
	"testing"
)

// What these tests are about is the generator, not the ABI. The ABI's own
// expectations live in internal/telemetry/abi, where they are compared against
// the real header. Here the input is synthetic and the question is narrower:
// does the parser refuse what it cannot handle, and does the layout engine
// compute C's rules correctly?

// --- refusals ------------------------------------------------------------------
//
// The single most important property of this generator. A parser that silently
// skipped a construct it did not understand would emit a Go struct missing a
// field — which is exactly the drift the generator exists to prevent, arriving
// through the tool meant to stop it. Every one of these must be an error.

func TestParseRefusesUnsupportedConstructs(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string // substring the error must contain
	}{
		{
			name: "pointer field",
			src:  "struct s { __u64 *p; };",
			want: "pointer",
		},
		{
			name: "bitfield",
			src:  "struct s { __u32 flags : 3; };",
			want: "bitfield",
		},
		{
			name: "non-fixed-width type",
			src:  "struct s { int n; };",
			want: "not a supported fixed-width type",
		},
		{
			name: "multiple declarators on one line",
			src:  "struct s { __u32 a, b; };",
			want: "more than one name",
		},
		{
			name: "enum member without an explicit value",
			src:  "enum e { A = 0, B, };\nstruct s { __u32 x; };",
			want: "no explicit value",
		},
		{
			name: "non-integer define",
			src:  "#define THING \"x\"\nstruct s { __u32 x; };",
			want: "non-integer value",
		},
		{
			name: "unknown array bound",
			src:  "struct s { char p[SOMETHING_ELSE]; };",
			want: "neither an integer literal nor a known #define",
		},
		{
			name: "typedef",
			src:  "typedef unsigned long u64;\nstruct s { __u32 x; };",
			want: "unsupported top-level construct",
		},
		{
			name: "named union",
			src:  "struct s { union named { __u32 a; } u; };",
			want: "names the union type",
		},
		{
			name: "anonymous struct declaration",
			src:  "struct { __u32 x; };",
			want: "anonymous top-level",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, err := Parse(tc.src)
			if err == nil {
				// Some refusals only become visible at layout time, which is
				// fine — what matters is that the pipeline as a whole refuses.
				if _, lerr := Layout(h); lerr != nil {
					err = lerr
				}
			}
			if err == nil {
				t.Fatalf("accepted an unsupported construct; a generator that guesses here emits a "+
					"decoder missing a field, which is the drift it exists to prevent\nsource: %s", tc.src)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// --- layout --------------------------------------------------------------------

func TestLayoutComputesNaturalAlignment(t *testing.T) {
	// A struct whose fields are deliberately not largest-first, so implicit
	// padding appears and has to be accounted for. The header's own rules
	// discourage this shape; the layout engine still has to model it, because
	// modelling C wrongly is how the Go side and the C side disagree.
	src := `
struct inner { __u32 a; };
struct outer {
    __u8  b;
    __u64 c;
    __u16 d;
    struct inner in;
    char  name[3];
};`
	h, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	m, err := Layout(h)
	if err != nil {
		t.Fatalf("Layout: %v", err)
	}

	outer := m.Structs[1]
	want := []struct {
		name   string
		offset int
		size   int
	}{
		{"b", 0, 1},     // then 7 bytes of padding
		{"c", 8, 8},     //
		{"d", 16, 2},    // then 2 bytes of padding
		{"in", 20, 4},   //
		{"name", 24, 3}, // then 5 bytes of trailing padding
	}
	if len(outer.Fields) != len(want) {
		t.Fatalf("got %d fields, want %d", len(outer.Fields), len(want))
	}
	for i, w := range want {
		got := outer.Fields[i]
		if got.Name != w.name || got.Offset != w.offset || got.Size != w.size {
			t.Errorf("field %d = %s@%d size %d, want %s@%d size %d",
				i, got.Name, got.Offset, got.Size, w.name, w.offset, w.size)
		}
	}
	if outer.Align != 8 {
		t.Errorf("align = %d, want 8 (the widest member)", outer.Align)
	}
	if outer.Size != 32 {
		t.Errorf("size = %d, want 32 (27 rounded up to the 8-byte alignment)", outer.Size)
	}
	if outer.InternalPad != 9 {
		t.Errorf("InternalPad = %d, want 9 (7 before c, 2 before in); trailing padding is not counted",
			outer.InternalPad)
	}
}

func TestLayoutUnionTakesTheLargestMember(t *testing.T) {
	src := `
struct small { __u32 a; };
struct big { __u64 a; char b[20]; };
struct rec {
    __u32 type;
    union {
        struct small s;
        struct big   b;
    } payload;
};`
	h, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	m, err := Layout(h)
	if err != nil {
		t.Fatalf("Layout: %v", err)
	}

	rec := m.Structs[2]
	payload := rec.Fields[1]
	if !payload.IsUnion() {
		t.Fatal("payload was not recognized as a union")
	}
	// struct big is 8 + 20 = 28, rounded to its 8-byte alignment = 32.
	if payload.Size != 32 {
		t.Errorf("union size = %d, want 32 (the largest member, aligned)", payload.Size)
	}
	if payload.Offset != 8 {
		t.Errorf("union offset = %d, want 8 (aligned past the u32 type to the union's 8-byte alignment)", payload.Offset)
	}
	if m.Root != "rec" {
		t.Errorf("Root = %q, want rec; the record is the struct nothing embeds", m.Root)
	}
}

// The root is derived rather than named, so a header that grows a second
// unembedded struct has to say which one the ring buffer carries.
func TestLayoutRefusesAmbiguousRoot(t *testing.T) {
	src := "struct a { __u32 x; };\nstruct b { __u32 y; };"
	h, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := Layout(h); err == nil {
		t.Fatal("accepted two candidate root records")
	} else if !strings.Contains(err.Error(), "more than one struct") {
		t.Errorf("error = %q, want it to name the ambiguity", err)
	}
}

// --- determinism and portability -------------------------------------------------

// The staleness check compares bytes, so generation must be a function of the
// header alone. Map iteration order leaking into the output would make the
// check fire at random.
func TestGenerateIsDeterministic(t *testing.T) {
	src := []byte(miniHeader)
	first, err := Generate(src, "mini.h", "abi")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for i := 0; i < 20; i++ {
		again, err := Generate(src, "mini.h", "abi")
		if err != nil {
			t.Fatalf("Generate run %d: %v", i, err)
		}
		if string(again) != string(first) {
			t.Fatalf("run %d produced different bytes; generation is not a pure function of the header", i)
		}
	}
}

// The property that keeps the staleness check honest across a Windows checkout
// and a Linux one. .gitattributes leaves source line endings to core.autocrlf,
// so the same header is CRLF here and LF there; if that changed the output, the
// check would report drift that is not drift.
func TestGenerateIgnoresLineEndings(t *testing.T) {
	lf := strings.ReplaceAll(miniHeader, "\r\n", "\n")
	crlf := strings.ReplaceAll(lf, "\n", "\r\n")

	a, err := Generate([]byte(lf), "mini.h", "abi")
	if err != nil {
		t.Fatalf("Generate(LF): %v", err)
	}
	b, err := Generate([]byte(crlf), "mini.h", "abi")
	if err != nil {
		t.Fatalf("Generate(CRLF): %v", err)
	}
	if string(a) != string(b) {
		t.Error("CRLF and LF headers generated different output; the staleness check would fail " +
			"on whichever platform did not generate the committed file")
	}
	if !strings.Contains(string(a), "Source SHA-256") {
		t.Error("the generated file carries no header digest")
	}
}

// The generated bytes must not depend on how the generator was invoked. This
// caught a real defect: `go generate` runs in the package directory and reaches
// the header as ../../../bpf/include/..., while the Makefile target and the
// staleness test reach it from the repository root. The path is recorded in the
// output, so each invocation reported the other's file as stale.
func TestGenerateIgnoresTheInvocationDirectory(t *testing.T) {
	src := []byte(miniHeader)
	paths := []string{
		"bpf/include/mini.h",
		"./bpf/include/mini.h",
		"../../../bpf/include/mini.h",
		`..\..\..\bpf\include\mini.h`,
	}

	first, err := Generate(src, paths[0], "abi")
	if err != nil {
		t.Fatalf("Generate(%q): %v", paths[0], err)
	}
	for _, p := range paths[1:] {
		got, err := Generate(src, p, "abi")
		if err != nil {
			t.Fatalf("Generate(%q): %v", p, err)
		}
		if string(got) != string(first) {
			t.Errorf("invoking with %q produced different bytes from %q; the staleness check "+
				"would then fire on how it was called rather than on what changed", p, paths[0])
		}
	}
	if !strings.Contains(string(first), "Source:            bpf/include/mini.h") {
		t.Error("the recorded source path was not canonicalized to a repository-relative form")
	}
}

// --- naming ---------------------------------------------------------------------

func TestNamingRules(t *testing.T) {
	t.Run("camel", func(t *testing.T) {
		cases := map[string]string{
			"cgroup_id":      "CgroupID",
			"start_time":     "StartTime",
			"pid":            "PID",
			"ppid":           "PPID",
			"old_uid":        "OldUID",
			"_pad":           "Pad",
			"sock_type":      "SockType",
			"caps_effective": "CapsEffective",
			"PATH_MAX":       "PathMax",
		}
		for in, want := range cases {
			if got := camel(in); got != want {
				t.Errorf("camel(%q) = %q, want %q", in, got, want)
			}
		}
	})

	t.Run("enum members", func(t *testing.T) {
		members := []EnumMember{
			{Name: "ALLSEER_EVT_UNKNOWN"},
			{Name: "ALLSEER_EVT_FILE_OPEN"},
			{Name: "ALLSEER_EVT_NET_CONNECT"},
		}
		prefix := memberPrefix(members)
		if prefix != "ALLSEER_EVT_" {
			t.Fatalf("memberPrefix = %q, want ALLSEER_EVT_", prefix)
		}
		cases := map[string]string{
			"ALLSEER_EVT_UNKNOWN":     "EvtUnknown",
			"ALLSEER_EVT_FILE_OPEN":   "EvtFileOpen",
			"ALLSEER_EVT_NET_CONNECT": "EvtNetConnect",
		}
		for in, want := range cases {
			if got := goEnumMember(in, prefix); got != want {
				t.Errorf("goEnumMember(%q) = %q, want %q", in, got, want)
			}
		}
	})

	t.Run("a shared prefix never consumes a whole name", func(t *testing.T) {
		// Two members differing only in their last component must still keep
		// that component, or they would collide.
		members := []EnumMember{{Name: "A_B_C"}, {Name: "A_B_D"}}
		if p := memberPrefix(members); p != "A_B_" {
			t.Errorf("memberPrefix = %q, want A_B_", p)
		}
	})
}

// --- comment handling -------------------------------------------------------------

func TestStripCommentsPreservesLineNumbers(t *testing.T) {
	src := "a\n/* two\nlines */\nb"
	got := stripComments(src)
	if strings.Count(got, "\n") != strings.Count(src, "\n") {
		t.Errorf("line count changed: %q -> %q; error messages would point at the wrong line", src, got)
	}
	if strings.Contains(got, "two") {
		t.Error("comment body survived")
	}
}

// miniHeader is a stand-in with every construct the real header uses, small
// enough to reason about. It is not a copy of allseer_event.h — that one is
// exercised against its own expectations in internal/telemetry/abi.
const miniHeader = `#ifndef __MINI_H
#define __MINI_H

#define MINI_NAME_LEN 8
#define MINI_ARGV_MAX 2

enum mini_event_type {
    MINI_EVT_UNKNOWN = 0,
    MINI_EVT_OPEN    = 1,
};

struct mini_proc {
    __u64 cgroup_id;
    __u32 pid;
    __u32 _pad;
    char  comm[MINI_NAME_LEN];
};

struct mini_file {
    __u64 inode;
    __s32 flags;
    __u32 _pad;
};

struct mini_exec {
    __u32 argc;
    __u32 _pad;
    char  argv[MINI_ARGV_MAX][MINI_NAME_LEN];
};

struct mini_event {
    __u64 timestamp;
    __u32 type;
    __s32 ret;
    struct mini_proc proc;
    union {
        struct mini_file file;
        struct mini_exec exec;
    } payload;
};

#endif /* __MINI_H */
`
