package api

import (
	"encoding/json"
	"errors"

	"github.com/FyberLabs/hypermesh-host/internal/runtime"
)

// UnmarshalJSON accepts an additive runtime_image spelling while retaining the
// existing image_digest wire shape for journals and independently updated peers.
func (job *Job) UnmarshalJSON(data []byte) error {
	type legacyJob Job
	var decoded legacyJob
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if raw, present := fields["runtime_image"]; present {
		if _, old := fields["image_digest"]; old {
			return errors.New("ambiguous runtime image fields")
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return err
		}
		ref, err := runtime.ChannelRef(value)
		if err != nil {
			return err
		}
		decoded.ImageDigest = ref
	}
	*job = Job(decoded)
	return nil
}
