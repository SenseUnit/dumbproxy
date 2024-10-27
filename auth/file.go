package auth

import (
	"fmt"
	"os"
	"time"
)

func openIfModified(filename string, since time.Time) (*os.File, time.Time, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("openIfModified(): can't open file %q: %w", filename, err)
	}

	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, time.Time{}, fmt.Errorf("openIfModified(): can't stat file %q: %w", filename, err)
	}

	modTime := fi.ModTime()
	if (since != time.Time{}) && !since.Before(modTime) {
		f.Close()
		return nil, modTime, nil
	}

	return f, modTime, nil
}
