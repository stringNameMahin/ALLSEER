package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/stringNameMahin/ALLSEER/internal/telemetry"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
)

// runCapabilities prints the capability catalog this build knows about.
//
// Two things an operator needs. It is the vocabulary an envelope may use, so it
// answers "what can I write in a grant?" without reading the schema, and with a
// live daemon it answers the sharper question of which Kinds have a probe
// behind them.
//
// Until the daemon exists there are no probes to report, so the observable set
// is empty and the command says so rather than implying coverage this build
// does not have.
//
// It does report the PROBE column, which is a different question and answerable
// without a daemon: whether this build carries a probe for the Kind at all. A
// grant for a Kind with no probe cannot be enforced on any host, which is worse
// than one whose probe simply is not loaded here, and the two used to read
// identically.
func runCapabilities(args []string) int {
	fs := flag.NewFlagSet("capabilities", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "Usage: allseerctl capabilities [flags]\n\n"+
			"List the capability vocabulary an envelope may use.\n\n"+
			"Flags:\n")
		fs.PrintDefaults()
	}

	var (
		asJSON = fs.Bool("json", false, "Emit the catalog as JSON")
		domain = fs.String("domain", "", "Show only one domain (filesystem, process, network, privilege, ipc, kernel)")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cat := capability.NewCatalog()

	kinds := cat.Kinds()
	if *domain != "" {
		kinds = capability.KindsInDomain(capability.Domain(*domain))
		if len(kinds) == 0 {
			fmt.Fprintf(os.Stderr, "allseerctl capabilities: unknown domain %q\n", *domain)
			fmt.Fprintf(os.Stderr, "known domains: %s\n", joinDomains(capability.AllDomains()))
			return 2
		}
	}

	if *asJSON {
		descs := make([]capability.Descriptor, 0, len(kinds))
		for _, k := range kinds {
			if d, ok := cat.Lookup(k); ok {
				descs = append(descs, d)
			}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(descs); err != nil {
			fmt.Fprintf(os.Stderr, "allseerctl capabilities: %v\n", err)
			return 1
		}
		return 0
	}

	probed := probedKinds()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "KIND\tDOMAIN\tSEVERITY\tPROBE\tOBSERVABLE\tSUMMARY")
	for _, k := range kinds {
		d, ok := cat.Lookup(k)
		if !ok {
			continue
		}
		observable := "no"
		if cat.Observable(k) {
			observable = "yes"
		}
		probe := "none"
		if probed[k] {
			probe = "yes"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			d.Kind, d.Domain, d.BaselineSeverity, probe, observable, d.Summary)
	}
	_ = w.Flush()

	if len(cat.ObservableKinds()) == 0 {
		withProbe := 0
		for _, k := range kinds {
			if probed[k] {
				withProbe++
			}
		}
		fmt.Fprintf(os.Stderr,
			"\n%d capabilities known, %d with a probe in this build, 0 observable:\n"+
				"no probes are loaded in this process. An envelope granting an\n"+
				"unobservable capability cannot be enforced.\n",
			len(kinds), withProbe)
		if withProbe < len(kinds) {
			fmt.Fprintf(os.Stderr,
				"The %d showing PROBE=none have no probe on any host, which no\n"+
					"daemon can fix.\n", len(kinds)-withProbe)
		}
	}
	return 0
}

func joinDomains(ds []capability.Domain) string {
	out := make([]string, len(ds))
	for i, d := range ds {
		out[i] = string(d)
	}
	return strings.Join(out, ", ")
}

// probedKinds is every Kind this build carries a probe for.
//
// Read from the probe table rather than from a list kept here, so a family
// added to the object shows up without this command being edited.
func probedKinds() map[capability.Kind]bool {
	out := make(map[capability.Kind]bool)
	for _, f := range telemetry.AllProbeFamilies() {
		for _, k := range f.Capabilities {
			out[k] = true
		}
	}
	return out
}
