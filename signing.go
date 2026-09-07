package gonsu

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SignedRequest adalah bahan yang ditandatangani installation.
type SignedRequest struct {
	InstallationID string
	Method         string
	Path           string
	Timestamp      time.Time
	Nonce          string
	Body           []byte
}

// SigningPayload menyusun kalimat yang ditandatangani.
//
// Ini adalah CERMIN dari licensing.SigningPayload di sisi server, dan wajib
// menghasilkan byte yang identik. Duplikasi ini tidak dapat dihindari — SDK
// adalah module tersendiri supaya produk pelanggan tidak menarik seluruh
// dependency platform — sehingga yang menjaganya adalah test lintas module
// (internal/licensing/sdk_compat_test.go) yang membandingkan keduanya byte per
// byte. Tanpa test itu, kedua salinan akan menyimpang diam-diam dan gejalanya
// baru muncul sebagai penolakan tanda tangan di lapangan.
//
// Method dan path ikut ditandatangani supaya tanda tangan yang sah untuk satu
// endpoint tidak dapat dipindahkan ke endpoint lain.
func SigningPayload(request SignedRequest) []byte {
	digest := sha256.Sum256(request.Body)

	return []byte(strings.Join([]string{
		strings.ToUpper(request.Method),
		request.Path,
		request.InstallationID,
		strconv.FormatInt(request.Timestamp.Unix(), 10),
		request.Nonce,
		hex.EncodeToString(digest[:]),
	}, "\n"))
}

// Sign menandatangani sebuah request dengan kunci privat installation.
func Sign(key ed25519.PrivateKey, request SignedRequest) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(key, SigningPayload(request)))
}

// newNonce membangkitkan nonce sekali pakai.
//
// Server menolak nonce yang pernah dipakai, sehingga request yang direkam
// seseorang di tengah jalan tidak dapat diputar ulang.
func newNonce() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("membangkitkan nonce: %w", err)
	}
	return hex.EncodeToString(buf[:]), nil
}
