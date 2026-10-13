//go:build !(linux && ebpf)

package main

import (
	"context"
	"errors"

	"github.com/stringNameMahin/ALLSEER/internal/daemon"
	"github.com/stringNameMahin/ALLSEER/internal/telemetry"
)

func newTelemetry(context.Context, telemetry.Config) (daemon.Telemetry, error) {
	return nil, errors.New("this allseerd was built without the eBPF collector; build it with make build-ebpf")
}
