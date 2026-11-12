package runtime

import (
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var serviceRepository = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[0-9]{1,5})?/[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$`)
var serviceTag = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)

// ServiceImageRef implements the shared tag-only runtime reference contract.
// It never resolves a reference or rewrites the caller's tag.
func ServiceImageRef(value, repository string) (string, error) {
	if !serviceRepository.MatchString(repository) {
		return "", errors.New("invalid approved runtime repository")
	}
	registry := strings.SplitN(repository, "/", 2)[0]
	if _, port, ok := strings.Cut(registry, ":"); ok {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return "", errors.New("invalid runtime registry port")
		}
	}
	tag, ok := strings.CutPrefix(value, repository+":")
	if !ok || !serviceTag.MatchString(tag) {
		return "", errors.New("runtime image requires approved repository and explicit tag")
	}
	return value, nil
}

// ChannelRef checks deployment-owned policy, independently of model hashes.
func ChannelRef(value string) (string, error) {
	raw := os.Getenv("HYPERMESH_RUNTIME_IMAGE_REPOSITORIES")
	var repositories []string
	if len(raw) > 65536 || json.Unmarshal([]byte(raw), &repositories) != nil || len(repositories) == 0 || len(repositories) > 32 {
		return "", errors.New("runtime repository policy is unavailable")
	}
	seen := map[string]bool{}
	for _, repository := range repositories {
		if _, err := ServiceImageRef(repository+":test", repository); err != nil || seen[repository] {
			return "", errors.New("invalid runtime repository policy")
		}
		seen[repository] = true
	}
	for _, repository := range repositories {
		if ref, err := ServiceImageRef(value, repository); err == nil {
			return ref, nil
		}
	}
	return "", errors.New("runtime image is outside approved repositories")
}
