package localsigner

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"
)

const (
	nip5fMaxFrame = 1 << 20 // 1 MiB
	nip5fTimeout  = 10 * time.Second
)

// nip5fSigner speaks the NIP-5F Unix socket protocol:
// 4-byte big-endian length prefix + UTF-8 JSON body, max 1 MiB.
type nip5fSigner struct {
	sockPath string
	logger   *slog.Logger
}

type nip5fRequest struct {
	ID     string `json:"id"`
	Method string `json:"method"`
	Params []any  `json:"params"`
}

type nip5fResponse struct {
	ID     string          `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *nip5fError     `json:"error"`
}

type nip5fError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (s *nip5fSigner) call(method string, params []any) (json.RawMessage, error) {
	conn, err := net.DialTimeout("unix", s.sockPath, nip5fTimeout)
	if err != nil {
		return nil, fmt.Errorf("connect NIP-5F socket: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(nip5fTimeout))

	// Read server banner (4-byte framed).
	if _, err := readFrame(conn); err != nil {
		return nil, fmt.Errorf("read NIP-5F banner: %w", err)
	}

	// Send client handshake.
	hello, _ := json.Marshal(map[string]string{"client": "grasp-local-signer"})
	if err := writeFrame(conn, hello); err != nil {
		return nil, fmt.Errorf("write NIP-5F handshake: %w", err)
	}

	// Send method request.
	req := nip5fRequest{ID: "1", Method: method, Params: params}
	reqBytes, _ := json.Marshal(req)
	if err := writeFrame(conn, reqBytes); err != nil {
		return nil, fmt.Errorf("write NIP-5F request: %w", err)
	}

	// Read response.
	respBytes, err := readFrame(conn)
	if err != nil {
		return nil, fmt.Errorf("read NIP-5F response: %w", err)
	}

	var resp nip5fResponse
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return nil, fmt.Errorf("parse NIP-5F response: %w", err)
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("NIP-5F error %d: %s", resp.Error.Code, resp.Error.Message)
	}
	return resp.Result, nil
}

func (s *nip5fSigner) GetPublicKey() (string, error) {
	result, err := s.call("get_public_key", []any{})
	if err != nil {
		return "", err
	}
	var pk string
	if err := json.Unmarshal(result, &pk); err != nil {
		return "", fmt.Errorf("parse pubkey: %w", err)
	}
	return pk, nil
}

func (s *nip5fSigner) SignEvent(eventJSON string) (string, error) {
	var evt json.RawMessage = json.RawMessage(eventJSON)
	result, err := s.call("sign_event", []any{evt, ""})
	if err != nil {
		return "", err
	}
	// result is the signed event object — return as compact JSON string.
	return string(result), nil
}

// --- framing helpers ---

func writeFrame(w io.Writer, data []byte) error {
	if len(data) > nip5fMaxFrame {
		return fmt.Errorf("frame too large: %d bytes", len(data))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(data)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(hdr[:])
	if length > nip5fMaxFrame {
		return nil, fmt.Errorf("frame too large: %d", length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
