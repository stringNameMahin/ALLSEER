package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

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

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "KIND\tDOMAIN\tSEVERITY\tOBSERVABLE\tSUMMARY")
	for _, k := range kinds {
		d, ok := cat.Lookup(k)
		if !ok {
			continue
		}
		observable := "no"
		if cat.Observable(k) {
			observable = "yes"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", d.Kind, d.Domain, d.BaselineSeverity, observable, d.Summary)
	}
	_ = w.Flush()

	if len(cat.ObservableKinds()) == 0 {
		fmt.Fprintf(os.Stderr,
			"\n%d capabilities known, 0 observable: no probes are loaded in this build.\n"+
				"An envelope granting an unobservable capability cannot be enforced.\n",
			len(kinds))
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
