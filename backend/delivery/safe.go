package delivery

import (
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
)

// SafeError strips dialled addresses and URLs from network errors so the API
// does not echo what it reached (or failed to reach) back to the caller.
func SafeError(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Err != nil {
		return opErr.Err
	}
	return err
}

// OutputRoot is the only directory a file destination may write under.
func OutputRoot() string {
	if root := os.Getenv("OUTPUT_DIR"); root != "" {
		return filepath.Clean(root)
	}
	return "/tmp/output"
}

// ResolveOutputPath returns the absolute path for a file destination, or an
// error when it would fall outside OutputRoot (including through a symlink).
func ResolveOutputPath(p string) (string, error) {
	root, err := filepath.Abs(OutputRoot())
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	if !inside(root, abs) {
		return "", errors.New("file path must be inside the output directory")
	}
	// The directory may already exist as a symlink; resolve it before trusting it.
	if real, err := filepath.EvalSymlinks(filepath.Dir(abs)); err == nil {
		realRoot, _ := filepath.EvalSymlinks(root)
		if realRoot == "" {
			realRoot = root
		}
		if !inside(realRoot, filepath.Join(real, filepath.Base(abs))) {
			return "", errors.New("file path must be inside the output directory")
		}
	}
	return abs, nil
}

func inside(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return false
	}
	return rel != ".." && !filepath.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
