package cashu

import (
	"math"
	"testing"
	"time"
)

func TestPaymentAmountExactAndBounded(t *testing.T) {
	got, err := PaymentAmount(10, 234*time.Second)
	if err != nil || got != 2340 {
		t.Fatalf("PaymentAmount = %d, %v; want 2340", got, err)
	}
	if got, err := PaymentAmount(0, time.Minute); err != nil || got != 0 {
		t.Fatalf("free PaymentAmount = %d, %v", got, err)
	}
	if _, err := PaymentAmount(1, 1500*time.Millisecond); err == nil {
		t.Fatal("fractional-second duration accepted")
	}
	if _, err := PaymentAmount(math.MaxUint64, 2*time.Second); err == nil {
		t.Fatal("overflow accepted")
	}
}

func TestNormalizeMintURL(t *testing.T) {
	got, err := NormalizeMintURL("https://MINT.example/path/")
	if err != nil || got != "https://mint.example/path" {
		t.Fatalf("NormalizeMintURL = %q, %v", got, err)
	}
	for _, raw := range []string{"http://mint.example", "https://user@mint.example", "https://mint.example?q=1"} {
		if _, err := NormalizeMintURL(raw); err == nil {
			t.Fatalf("unsafe mint URL accepted: %s", raw)
		}
	}
}
