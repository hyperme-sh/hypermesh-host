//go:build !linux && !darwin

package machineidentity

import (
	"context"
	"fmt"
)

func (Provider) SignCapability(context.Context, string, string, string, string, CapabilityCall) ([]byte, error) {
	return nil, fmt.Errorf("machine capability signing requires Linux or macOS")
}
