package event

import (
	"testing"

	"github.com/stringNameMahin/ALLSEER/pkg/capability"
)

func TestExercisedKinds(t *testing.T) {
	const (
		rdOnly = 0x0
		wrOnly = 0x1
		rdWr   = 0x2
		creat  = 0x40
		trunc  = 0x200
		appnd  = 0x400
	)
	cases := []struct {
		name  string
		flags int32
		want  []capability.Kind
	}{
		{"read only", rdOnly, []capability.Kind{capability.KindFileRead}},
		{"write only", wrOnly, []capability.Kind{capability.KindFileWrite}},
		{
			// The case this exists for: an O_RDWR open reads as well, so a
			// denial on fs.read has to be consulted for it.
			"read write", rdWr,
			[]capability.Kind{capability.KindFileRead, capability.KindFileWrite},
		},
		{
			"create write only", wrOnly | creat,
			[]capability.Kind{capability.KindFileWrite, capability.KindFileCreate},
		},
		{
			"create read write", rdWr | creat,
			[]capability.Kind{capability.KindFileRead, capability.KindFileWrite, capability.KindFileCreate},
		},
		{
			// O_CREAT with a read-only access mode can still produce the file.
			"create read only", rdOnly | creat,
			[]capability.Kind{capability.KindFileRead, capability.KindFileCreate, capability.KindFileWrite},
		},
		{
			"other flags do not change the answer", rdWr | trunc | appnd,
			[]capability.Kind{capability.KindFileRead, capability.KindFileWrite},
		},
		{
			// The fourth access-mode encoding has no O_ name and is used by
			// O_PATH. Write is the safer reading.
			"unnamed access mode", 0x3,
			[]capability.Kind{capability.KindFileWrite},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := (&FilePayload{Flags: c.flags}).ExercisedKinds()
			if len(got) != len(c.want) {
				t.Fatalf("ExercisedKinds(%#x) = %v, want %v", c.flags, got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("ExercisedKinds(%#x) = %v, want %v", c.flags, got, c.want)
				}
			}
		})
	}
}

func TestExercisedKindsOnNilPayload(t *testing.T) {
	var p *FilePayload
	if got := p.ExercisedKinds(); got != nil {
		t.Fatalf("nil payload returned %v", got)
	}
}
