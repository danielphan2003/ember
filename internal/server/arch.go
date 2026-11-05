package server

import "runtime"

// runnerArch maps GOARCH to the RUNNER_ARCH names GitHub-style actions expect.
func runnerArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "X64"
	case "arm64":
		return "ARM64"
	default:
		return runtime.GOARCH
	}
}
