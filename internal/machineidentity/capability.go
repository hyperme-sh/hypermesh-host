package machineidentity

import "encoding/json"

// CapabilityCall binds exact tool arguments to the immutable capability graph.
// It grants nothing: AIuditor and the local controller must still approve.
type CapabilityCall struct {
	Scope        string          `json:"scope"`
	Owner        string          `json:"owner"`
	ID           string          `json:"capability_id"`
	Revision     string          `json:"revision"`
	SourceSHA256 string          `json:"source_sha256"`
	GraphSHA256  string          `json:"graph_sha256"`
	CallID       string          `json:"call_id"`
	Arguments    json.RawMessage `json:"arguments"`
}
