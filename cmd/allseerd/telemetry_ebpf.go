//go:build linux && ebpf

package main

import (
	"context"

	"github.com/stringNameMahin/ALLSEER/internal/daemon"
	"github.com/stringNameMahin/ALLSEER/internal/telemetry"
)

func newTelemetry(ctx context.Context, cfg telemetry.Config) (daemon.Telemetry, error) {
	c, err := telemetry.NewBPFCollector(cfg)
	if err != nil {
		return nil, err
	}
	if err := c.Start(ctx); err != nil {
		return nil, err
	}
	return c, nil
}
