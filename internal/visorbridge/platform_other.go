//go:build !linux

package visorbridge

import (
	"context"
	"net/http"
)

func trustedExecutable(string) error        { return refused }
func Load(string) (Config, error)           { return Config{}, refused }
func (*Bridge) Serve(context.Context) error { return refused }

func trustedConfiguration(string) error { return refused }

func serveSocket(context.Context, string, uint32, http.Handler) error { return refused }
func controllerStateDir(string) error                                 { return refused }
