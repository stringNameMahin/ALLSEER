package risk

import (
	"context"
	"path/filepath"

	"github.com/stringNameMahin/ALLSEER/pkg/decision"
)

// FactorUnverifiablePath charges a file or exec event whose path the kernel
// itself could not vouch for.
const FactorUnverifiablePath = "unverifiable_path"

// UnverifiablePathPoints equals outside_envelope's verdict weight. It carries
// an indeterminate event across the 50 boundary the shipped rule set draws
// between indeterminate-low-risk and indeterminate-high-risk.
const UnverifiablePathPoints = 30

// Evidence keys for unverifiable_path. EvidenceRawPath is the name as the
// probe captured it, which may be relative, a prefix, or empty.
const (
	EvidencePathProblem = "problem"
	EvidenceDirStatus   = "dir_status"
	EvidenceDirSource   = "dir_source"
	EvidenceRawPath     = "raw_path"
	EvidenceResult      = "result"
	EvidenceProcess     = "process"
)

// UnverifiablePathScorer separates two kinds of unresolved path. A file that
// was opened and then removed before enrichment is ordinary and is not
// charged. A path the probe reported as truncated or unreadable, a relative
// path whose directory walk was truncated, deleted or unavailable, or a path
// read only at syscall exit that the opened inode did not confirm, is what an
// agent produces when it pads a path past the kernel buffer, opens through a
// removed directory or rewrites the name under the kernel to evade a denial,
// and is charged.
type UnverifiablePathScorer struct{}

var (
	_ Scorer      = UnverifiablePathScorer{}
	_ localScorer = UnverifiablePathScorer{}
)

func (UnverifiablePathScorer) Name() string    { return FactorUnverifiablePath }
func (UnverifiablePathScorer) Weight() float64 { return UnverifiablePathPoints }

// Evaluate implements Scorer.
func (s UnverifiablePathScorer) Evaluate(_ context.Context, req ScoreRequest) (*decision.Factor, error) {
	if req.Validation == nil {
		return nil, ErrNoValidation
	}
	f, applied, err := s.evaluate(newScoreCtx(req))
	if err != nil || !applied {
		return nil, err
	}
	return &f, nil
}

func (UnverifiablePathScorer) evaluate(sc *scoreCtx) (decision.Factor, bool, error) {
	e := sc.req.Event
	if e == nil || !sc.departed {
		return decision.Factor{}, false, nil
	}
	ev := map[string]string{}
	raw := ""
	switch {
	case e.Exec != nil && e.Exec.Truncated:
		ev[EvidencePathProblem] = "exec filename truncated or unreadable in the kernel"
		raw = e.Exec.Filename
	case e.File != nil && e.File.Truncated:
		ev[EvidencePathProblem] = "path truncated or unreadable in the kernel"
		raw = e.File.Path
	case e.File != nil && e.File.PathLate && e.File.ResolvedPath == "":
		ev[EvidencePathProblem] = "path read after the syscall and not confirmed by the opened inode"
		raw = e.File.Path
	case e.File != nil && e.File.Path != "" && !filepath.IsAbs(e.File.Path) &&
		(e.File.DirStatus == "truncated" || e.File.DirStatus == "deleted" || e.File.DirStatus == "unavailable"):
		ev[EvidencePathProblem] = "base directory of a relative path could not be established"
		ev[EvidenceDirStatus] = e.File.DirStatus
		ev[EvidenceDirSource] = e.File.DirSource
		raw = e.File.Path
	default:
		return decision.Factor{}, false, nil
	}
	ev[EvidenceRawPath] = raw
	switch {
	case e.Result.Succeeded:
		ev[EvidenceResult] = "succeeded"
	case e.Result.Errno != "":
		ev[EvidenceResult] = e.Result.Errno
	default:
		ev[EvidenceResult] = "failed"
	}
	if proc := e.Process.Executable; proc != "" {
		ev[EvidenceProcess] = proc
	} else if e.Process.Comm != "" {
		ev[EvidenceProcess] = e.Process.Comm
	}
	return decision.Factor{
		Name:        FactorUnverifiablePath,
		Weight:      UnverifiablePathPoints,
		Description: "the kernel could not vouch for the path this event names",
		Evidence:    ev,
	}, true, nil
}
