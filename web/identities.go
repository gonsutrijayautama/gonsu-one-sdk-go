package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Identity adalah akun GONSU seseorang yang boleh diberi akses di pemasangan
// ini.
type Identity struct {
	// Subject adalah `sub` orang itu di GONSU — kunci tabel pengguna produk.
	Subject     string `json:"subject"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	// TemporaryPassword hanya terisi ketika akun GONSU-nya BARU dibuat.
	// Tampilkan sekali kepada admin, jangan simpan di mana pun. Kosong berarti
	// orangnya sudah punya akun — keadaan biasa, bukan kegagalan.
	TemporaryPassword string `json:"temporary_password,omitempty"`
}

// IdentityErrorKind mengelompokkan penolakan pemberian akses.
type IdentityErrorKind string

// Jenis penolakan pemberian akses.
const (
	// IdentityUnavailable: GONSU tidak memberi pemasangan ini jalan pemberian
	// akses — tanpa agent, dan tanpa GONSU_IDENTITY_TOKEN di cloud. GONSU
	// tidak dipanggil sama sekali.
	IdentityUnavailable IdentityErrorKind = "unavailable"
	// IdentityRateLimited: kuota pembuatan akun hari ini habis.
	IdentityRateLimited IdentityErrorKind = "rate_limited"
	// IdentityUnauthorized: GONSU menolak kredensial pemasangan.
	IdentityUnauthorized IdentityErrorKind = "unauthorized"
	// IdentityRevoked: pemasangan dicabut di GONSU.
	IdentityRevoked IdentityErrorKind = "revoked"
	// IdentityInvalidEmail: GONSU menolak alamat emailnya.
	IdentityInvalidEmail IdentityErrorKind = "invalid_email"
	// IdentityDown: GONSU atau penyedia identitasnya tidak dapat dihubungi.
	IdentityDown IdentityErrorKind = "down"
	// IdentityRejected: penolakan lain.
	IdentityRejected IdentityErrorKind = "rejected"
)

// IdentityError adalah penolakan pemberian akses. Message ditulis untuk
// manusia dan aman ditampilkan: kalimat dari GONSU sudah disanitasi, dan
// sisanya kalimat kit.
type IdentityError struct {
	Kind    IdentityErrorKind
	Status  int
	Message string
}

func (e *IdentityError) Error() string { return e.Message }

// Identities meminta GONSU membuatkan — atau menemukan — akun GONSU seseorang,
// untuk layar "beri akses login" produk.
//
//	self-host  POST $GONSU_AGENT_URL/v1/identities — agent yang menandatangani
//	cloud      POST $GONSU_BASE_URL/license/v1/identities, Bearer GONSU_IDENTITY_TOKEN
type Identities struct {
	url   string
	token string
	http  *http.Client
}

// Available melaporkan apakah pemasangan ini diberi jalan pemberian akses.
func (i *Identities) Available() bool { return i.url != "" }

// Provision meminta identitas untuk email.
//
// Kuota kursi produk DIPERIKSA PRODUK sebelum memanggil ini, dari
// License.Limit — GONSU menyatakan batasnya, produk yang menegakkan.
func (i *Identities) Provision(ctx context.Context, email, displayName string) (Identity, error) {
	if !i.Available() {
		return Identity{}, &IdentityError{Kind: IdentityUnavailable,
			Message: "Pemasangan ini belum menerima jalan pemberian akses dari GONSU, jadi orang baru belum dapat ditambahkan."}
	}
	body, err := json.Marshal(map[string]string{"email": email, "display_name": displayName})
	if err != nil {
		return Identity{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, i.url, bytes.NewReader(body))
	if err != nil {
		return Identity{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if i.token != "" {
		req.Header.Set("Authorization", "Bearer "+i.token)
	}

	resp, err := i.http.Do(req)
	if err != nil {
		return Identity{}, &IdentityError{Kind: IdentityDown,
			Message: "GONSU tidak dapat dihubungi, jadi akun belum dibuat. Coba lagi sebentar lagi."}
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Identity{}, err
	}

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		var id Identity
		if err := json.Unmarshal(raw, &id); err != nil || strings.TrimSpace(id.Subject) == "" {
			return Identity{}, fmt.Errorf("jawaban pemberian identitas GONSU tidak dapat dibaca (%d)", resp.StatusCode)
		}
		return id, nil
	}
	return Identity{}, identityRejection(resp.StatusCode, gonsuMessage(raw))
}

// identityRejection memetakan status GONSU — atau agent, yang meneruskannya
// apa adanya — ke jenis penolakan.
func identityRejection(status int, message string) *IdentityError {
	e := &IdentityError{Status: status}
	switch {
	case status == http.StatusTooManyRequests:
		e.Kind, e.Message = IdentityRateLimited, orDefault(message,
			"Kuota pembuatan akun GONSU hari ini untuk pemasangan ini sudah habis. Coba lagi besok.")
	case status == http.StatusUnauthorized:
		e.Kind, e.Message = IdentityUnauthorized,
			"GONSU menolak kredensial pemberian akses pemasangan ini. Hubungi GONSU untuk memperbarui pemasangan."
	case status == http.StatusForbidden:
		e.Kind, e.Message = IdentityRevoked,
			"Pemasangan ini dicabut di GONSU, jadi akses login tidak dapat diberikan."
	case status == http.StatusBadRequest || status == http.StatusUnprocessableEntity:
		e.Kind, e.Message = IdentityInvalidEmail, orDefault(message, "GONSU menolak email ini.")
	case status >= 500:
		e.Kind, e.Message = IdentityDown, orDefault(message,
			"Penyedia identitas GONSU sedang tidak dapat melayani. Coba lagi sebentar lagi.")
	default:
		e.Kind, e.Message = IdentityRejected, fmt.Sprintf("GONSU menolak permintaan pemberian akses (%d).", status)
	}
	return e
}

// gonsuMessage membaca `{"error":{"code","message"}}` — envelope GONSU dan
// agent.
func gonsuMessage(raw []byte) string {
	var env struct {
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(raw, &env) != nil || len(env.Error) == 0 {
		return ""
	}
	var body struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(env.Error, &body) == nil {
		return strings.TrimSpace(body.Message)
	}
	var plain string
	if json.Unmarshal(env.Error, &plain) == nil {
		return strings.TrimSpace(plain)
	}
	return ""
}

func orDefault(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
