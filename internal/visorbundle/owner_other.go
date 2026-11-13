//go:build !linux && !darwin

package visorbundle

import "os"

func owned(info os.FileInfo) bool { return false }

func trustedOwner(info os.FileInfo) bool { return false }
