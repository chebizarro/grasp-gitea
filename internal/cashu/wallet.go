// Package cashu provides the Loom-facing boundary around a persistent Cashu wallet.
package cashu

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	gocashu "github.com/elnosh/gonuts/cashu"
	gowallet "github.com/elnosh/gonuts/wallet"
)

// Payment is an exact serialized token created for one durable Loom spend.
type Payment struct {
	Token   string
	QuoteID string
	Amount  uint64
}

// PaymentRequest describes a pubkey-locked prepayment.
type PaymentRequest struct {
	Amount       uint64
	MintURL      string
	WorkerPubkey string
}

// Wallet is intentionally small so Loom can test payment idempotency without a mint.
type Wallet interface {
	CreatePayment(context.Context, PaymentRequest) (Payment, error)
	RedeemChange(context.Context, string) (uint64, error)
	ReceivePubkey() string
	Close() error
}

// Config configures a persistent gonuts wallet. Operators fund this wallet
// out-of-band; LoadWallet connects it to MintURL and retains proofs on disk.
type Config struct {
	MintURL string
	Path    string
}

// GonutsWallet implements Cashu NUT-03/NUT-11 swaps using gonuts.
type GonutsWallet struct {
	mu      sync.Mutex
	mintURL string
	wallet  *gowallet.Wallet
}

// New opens (or creates) a persistent wallet for a configured HTTPS mint.
func New(cfg Config) (*GonutsWallet, error) {
	mintURL, err := NormalizeMintURL(cfg.MintURL)
	if err != nil {
		return nil, err
	}
	path := strings.TrimSpace(cfg.Path)
	if path == "" {
		return nil, fmt.Errorf("Cashu wallet path is required")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return nil, fmt.Errorf("create Cashu wallet directory: %w", err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return nil, fmt.Errorf("secure Cashu wallet directory: %w", err)
	}
	w, err := gowallet.LoadWallet(gowallet.Config{WalletPath: path, CurrentMintURL: mintURL})
	if err != nil {
		return nil, fmt.Errorf("load Cashu wallet: %w", err)
	}
	return &GonutsWallet{mintURL: mintURL, wallet: w}, nil
}

// NormalizeMintURL canonicalizes the configured/advertised mint identity.
func NormalizeMintURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || !strings.EqualFold(u.Scheme, "https") || u.Hostname() == "" ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("Cashu mint URL must be an absolute HTTPS URL without credentials, query, or fragment")
	}
	u.Scheme = "https"
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	return u.String(), nil
}

// PaymentAmount computes the exact integer token amount. Durations are billed in
// whole seconds and must already be bounded by the selected worker advertisement.
func PaymentAmount(pricePerSecond uint64, duration time.Duration) (uint64, error) {
	if pricePerSecond == 0 {
		return 0, nil
	}
	if duration <= 0 || duration%time.Second != 0 {
		return 0, fmt.Errorf("Cashu payment duration must be a positive whole number of seconds")
	}
	seconds := uint64(duration / time.Second)
	if seconds > math.MaxUint64/pricePerSecond {
		return 0, fmt.Errorf("Cashu payment amount overflows uint64")
	}
	return seconds * pricePerSecond, nil
}

func (w *GonutsWallet) CreatePayment(ctx context.Context, req PaymentRequest) (Payment, error) {
	if w == nil || w.wallet == nil {
		return Payment{}, fmt.Errorf("Cashu wallet is not configured")
	}
	if err := ctx.Err(); err != nil {
		return Payment{}, err
	}
	mintURL, err := NormalizeMintURL(req.MintURL)
	if err != nil {
		return Payment{}, err
	}
	if mintURL != w.mintURL {
		return Payment{}, fmt.Errorf("worker mint %q does not match configured mint", mintURL)
	}
	if req.Amount == 0 {
		return Payment{}, fmt.Errorf("Cashu payment amount must be positive")
	}
	workerKey, err := parseNostrPubkey(req.WorkerPubkey)
	if err != nil {
		return Payment{}, fmt.Errorf("invalid worker payment pubkey: %w", err)
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	proofs, err := w.wallet.SendToPubkey(req.Amount, mintURL, workerKey, nil, false)
	if err != nil {
		return Payment{}, fmt.Errorf("create pubkey-locked Cashu payment: %w", err)
	}
	if proofs.Amount() != req.Amount {
		return Payment{}, fmt.Errorf("Cashu wallet returned amount %d, want %d", proofs.Amount(), req.Amount)
	}
	token, err := gocashu.NewTokenV4(proofs, mintURL, gocashu.Sat, true)
	if err != nil {
		return Payment{}, fmt.Errorf("encode Cashu payment: %w", err)
	}
	serialized, err := token.Serialize()
	if err != nil {
		return Payment{}, fmt.Errorf("serialize Cashu payment: %w", err)
	}
	sum := sha256.Sum256([]byte(serialized))
	return Payment{Token: serialized, QuoteID: hex.EncodeToString(sum[:]), Amount: req.Amount}, nil
}

func (w *GonutsWallet) RedeemChange(ctx context.Context, serialized string) (uint64, error) {
	if w == nil || w.wallet == nil {
		return 0, fmt.Errorf("Cashu wallet is not configured")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	token, err := gocashu.DecodeToken(strings.TrimSpace(serialized))
	if err != nil {
		return 0, fmt.Errorf("decode Cashu change: %w", err)
	}
	mintURL, err := NormalizeMintURL(token.Mint())
	if err != nil {
		return 0, err
	}
	if mintURL != w.mintURL {
		return 0, fmt.Errorf("change mint %q does not match configured mint", mintURL)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	amount, err := w.wallet.Receive(token, false)
	if err != nil {
		return 0, fmt.Errorf("redeem Cashu change: %w", err)
	}
	return amount, nil
}

func (w *GonutsWallet) ReceivePubkey() string {
	if w == nil || w.wallet == nil || w.wallet.GetReceivePubkey() == nil {
		return ""
	}
	return hex.EncodeToString(w.wallet.GetReceivePubkey().SerializeCompressed())
}

func (w *GonutsWallet) Close() error {
	if w == nil || w.wallet == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.wallet.Shutdown()
}

func parseNostrPubkey(raw string) (*btcec.PublicKey, error) {
	raw = strings.TrimSpace(raw)
	x, err := hex.DecodeString(raw)
	if err != nil || len(x) != 32 {
		return nil, fmt.Errorf("expected 32-byte hex x-only key")
	}
	compressed := append([]byte{0x02}, x...)
	return btcec.ParsePubKey(compressed)
}
