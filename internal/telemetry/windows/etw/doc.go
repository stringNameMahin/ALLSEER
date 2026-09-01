//go:build windows

// Package etw will acquire Windows telemetry through Event Tracing for Windows.
//
// Empty by design. It exists so the ETW work has an agreed home before it
// starts, and so the Windows-only dependencies it will take sit behind a build
// boundary from the beginning rather than after the first accidental import
// from shared code.
//
// No provider is named, no session is opened, and no capability is claimed to
// be observable. Which providers ALLSEER consumes, what each can honestly
// report, and what privilege each requires are the subject of the mechanism
// research stage.
package etw
