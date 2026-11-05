// Package agentbin embeds the ember-agent binary that is installed into
// every guest root filesystem. `just build` (or `make`) compiles the agent
// into bin/ before building ember.
package agentbin

import "embed"

//go:embed bin
var files embed.FS

// Agent returns the embedded agent, or nil when ember was built without it.
func Agent() []byte {
	b, err := files.ReadFile("bin/ember-agent")
	if err != nil {
		return nil
	}
	return b
}
