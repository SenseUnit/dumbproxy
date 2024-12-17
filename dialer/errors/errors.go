package errors

import "fmt"

type ErrAccessDenied struct {
	Err error
}

func (e ErrAccessDenied) Error() string {
	return fmt.Sprintf("access denied: %v", e.Err)
}

func (e ErrAccessDenied) Unwrap() error {
	return e.Err
}
