//go:build !linux

package telemetry

import "errors"

var errNoCgroups = errors.New("telemetry: cgroups are Linux-only")

// CgroupPathOfPID is unavailable off Linux.
func CgroupPathOfPID(int32) (string, error) { return "", errNoCgroups }

// CgroupIDOfPath is unavailable off Linux.
func CgroupIDOfPath(string) (uint64, error) { return 0, errNoCgroups }

// CgroupIDOfPID is unavailable off Linux.
func CgroupIDOfPID(int32) (uint64, error) { return 0, errNoCgroups }
