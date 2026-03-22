//go:build !linux

package localsigner

import (
	"fmt"
	"log/slog"
)

func newDBusSigner(logger *slog.Logger) (*dbusSigner, error) {
	return nil, fmt.Errorf("D-Bus not supported on this platform")
}

type dbusSigner struct{}

func (s *dbusSigner) GetPublicKey() (string, error)    { return "", fmt.Errorf("stub") }
func (s *dbusSigner) SignEvent(string) (string, error) { return "", fmt.Errorf("stub") }
