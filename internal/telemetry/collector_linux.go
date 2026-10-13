//go:build linux && ebpf

package telemetry

// NewBPFCollector returns a live collector over a libbpf loader for cfg.
func NewBPFCollector(cfg Config) (*LiveCollector, error) {
	return NewLiveCollector(cfg, CollectorOptions{Loader: NewLoader(cfg, nil)})
}
