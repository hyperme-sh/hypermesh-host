package visorbundle

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

func TestControllerDescriptionUsesStdoutAndErrorsUseStderr(t *testing.T) {
	var out, diagnostic bytes.Buffer
	if code := Run(context.Background(), []string{"controller", "--describe"}, &out, &diagnostic); code != 0 || diagnostic.Len() != 0 || !json.Valid(out.Bytes()) {
		t.Fatalf("description must be JSON on stdout: code=%d stdout=%q stderr=%q", code, out.String(), diagnostic.String())
	}
	out.Reset()
	diagnostic.Reset()
	if code := Run(context.Background(), []string{"controller", "--unknown"}, &out, &diagnostic); code != 2 || out.Len() != 0 || diagnostic.Len() == 0 {
		t.Fatal("parse errors must use stderr")
	}
}
