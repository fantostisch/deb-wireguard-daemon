package wgmanager

import "fmt"

type ParsePublicKeyErrorList struct {
	errors []ParsePublicKeyError
}

func (e ParsePublicKeyErrorList) Error() string {
	return fmt.Sprintf("could not parse public keys: %v", e.errors)
}

type ParsePublicKeyError struct {
	publicKey string
	err       error
}

func (e ParsePublicKeyError) Error() string {
	return fmt.Sprintf("could not parse public keys: %s", e.publicKey)
}

func (e ParsePublicKeyError) Unwrap() error {
	return e.err
}
