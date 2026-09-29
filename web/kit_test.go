package web

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gonsutrijayautama/gonsu-one-sdk-go/auth"
)

var hooks = Hooks{
	Granted:      func(context.Context, string) (bool, error) { return false, nil },
	StartSession: func(http.ResponseWriter, *http.Request, auth.Login, string) error { return nil },
}

func TestNew_MenolakTanpaYangWajib(t *testing.T) {
	empty := func(string) string { return "" }
	for name, options := range map[string]Options{
		"tanpa ProductCode":  {Hooks: hooks, Getenv: empty},
		"tanpa Granted":      {ProductCode: "garment", Hooks: Hooks{StartSession: hooks.StartSession}, Getenv: empty},
		"tanpa StartSession": {ProductCode: "garment", Hooks: Hooks{Granted: hooks.Granted}, Getenv: empty},
		"environment rusak":  {ProductCode: "garment", Hooks: hooks, Getenv: envFrom(map[string]string{"GONSU_AGENT_URL": "bukan-url"})},
	} {
		if _, err := New(options); err == nil {
			t.Errorf("%s: diterima", name)
		}
	}
}

// Lisensi cloud tanpa kunci publik: aplikasi tetap start, hak pakai tidak
// dibedakan, dan statusnya berkata begitu.
func TestNew_CloudTanpaKunciTidakMengunci(t *testing.T) {
	kit, err := New(Options{ProductCode: "garment", Hooks: hooks, Getenv: envFrom(map[string]string{
		"GONSU_BASE_URL": "https://api.gonsu.example", "GONSU_INSTALLATION_ID": "inst_1",
		"GONSU_STATE_DIR": t.TempDir(),
	})})
	if err != nil {
		t.Fatal(err)
	}
	if kit.Mode() != ModeCloud || kit.License().Status(ctx).Phase != PhaseUnlicensed {
		t.Errorf("mode=%s status=%+v", kit.Mode(), kit.License().Status(ctx))
	}
}

// Kunci yang tidak dapat dibaca tidak menghentikan aplikasi.
func TestNew_KunciRusakTidakMenghentikanStart(t *testing.T) {
	kit, err := New(Options{ProductCode: "garment", Hooks: hooks, Getenv: envFrom(map[string]string{
		"GONSU_BASE_URL": "https://api.gonsu.example", "GONSU_INSTALLATION_ID": "inst_1",
		"GONSU_STATE_DIR": t.TempDir(), "GONSU_LICENSE_PUBLIC_KEYS": "bukan-kunci",
	})})
	if err != nil {
		t.Fatal(err)
	}
	if kit.License().Status(ctx).Phase != PhaseUnlicensed {
		t.Errorf("status = %+v", kit.License().Status(ctx))
	}
}

func TestInstallation_CloudDariEnvironment(t *testing.T) {
	kit, err := New(Options{ProductCode: "garment", Hooks: hooks, Getenv: envFrom(map[string]string{
		"GONSU_ORGANIZATION_ID": "org_1", "GONSU_OWNER_SUBJECT": "usr_1",
	})})
	if err != nil {
		t.Fatal(err)
	}
	if org, owner := kit.Installation(ctx); org != "org_1" || owner != "usr_1" {
		t.Errorf("pemasangan = %q, %q", org, owner)
	}
}

func TestIdentities_SelfHostLewatAgentTanpaBearer(t *testing.T) {
	var path, authorization, body string
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, authorization = r.URL.Path, r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
		_, _ = io.WriteString(w, `{"subject":"usr_budi","email":"budi@konveksiku.test","temporary_password":"Sementara-1"}`)
	}))
	t.Cleanup(agent.Close)
	kit, err := New(Options{ProductCode: "garment", Hooks: hooks, Getenv: envFrom(map[string]string{"GONSU_AGENT_URL": agent.URL})})
	if err != nil {
		t.Fatal(err)
	}

	id, err := kit.Identities().Provision(ctx, "budi@konveksiku.test", "Budi")
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject != "usr_budi" || id.TemporaryPassword != "Sementara-1" {
		t.Errorf("identitas = %+v", id)
	}
	if path != "/v1/identities" || authorization != "" || !strings.Contains(body, `"email":"budi@konveksiku.test"`) {
		t.Errorf("permintaan ke %q, Authorization %q, badan %s", path, authorization, body)
	}
}

func TestIdentities_CloudDenganTokenPemasangan(t *testing.T) {
	var path, authorization string
	gonsu := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, authorization = r.URL.Path, r.Header.Get("Authorization")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"subject":"usr_budi"}`)
	}))
	t.Cleanup(gonsu.Close)
	kit, err := New(Options{ProductCode: "garment", Hooks: hooks, Getenv: envFrom(map[string]string{
		"GONSU_BASE_URL": gonsu.URL, "GONSU_IDENTITY_TOKEN": "gid_inst_1.ttd",
	})})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kit.Identities().Provision(ctx, "budi@konveksiku.test", ""); err != nil {
		t.Fatal(err)
	}
	if path != "/license/v1/identities" || authorization != "Bearer gid_inst_1.ttd" {
		t.Errorf("permintaan ke %q dengan %q", path, authorization)
	}
}

func TestIdentities_TanpaJalanTidakMemanggilGONSU(t *testing.T) {
	kit, err := New(Options{ProductCode: "garment", Hooks: hooks, Getenv: envFrom(nil)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = kit.Identities().Provision(ctx, "budi@konveksiku.test", "")
	var ie *IdentityError
	if !errors.As(err, &ie) || ie.Kind != IdentityUnavailable || kit.Identities().Available() {
		t.Errorf("err = %v", err)
	}
}

func TestIdentities_PenolakanDipetakan(t *testing.T) {
	cases := []struct {
		status int
		body   string
		kind   IdentityErrorKind
		msg    string
	}{
		{http.StatusTooManyRequests, ``, IdentityRateLimited, "Kuota"},
		{http.StatusUnauthorized, ``, IdentityUnauthorized, "kredensial"},
		{http.StatusForbidden, ``, IdentityRevoked, "dicabut"},
		{http.StatusUnprocessableEntity, `{"error":{"code":"invalid_email","message":"Alamat email tidak sah."}}`, IdentityInvalidEmail, "Alamat email tidak sah."},
		{http.StatusBadGateway, ``, IdentityDown, "Penyedia identitas"},
		{http.StatusConflict, ``, IdentityRejected, "(409)"},
	}
	for _, tc := range cases {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = io.WriteString(w, tc.body)
		}))
		i := &Identities{url: server.URL, http: server.Client()}
		_, err := i.Provision(ctx, "x@y.test", "")
		server.Close()
		var ie *IdentityError
		if !errors.As(err, &ie) || ie.Kind != tc.kind || !strings.Contains(ie.Message, tc.msg) {
			t.Errorf("%d: %+v", tc.status, err)
		}
	}
}

func TestMemoryPending_SekaliAmbilDanKedaluwarsa(t *testing.T) {
	m := newMemoryPending()
	now := time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }

	_ = m.Put(ctx, "a", PendingLogin{Next: "/x", ExpiresAt: now.Add(time.Minute)})
	if got, ok, _ := m.Take(ctx, "a"); !ok || got.Next != "/x" {
		t.Fatalf("pertama: %+v %v", got, ok)
	}
	if _, ok, _ := m.Take(ctx, "a"); ok {
		t.Error("login yang sama dapat diambil dua kali")
	}

	_ = m.Put(ctx, "b", PendingLogin{ExpiresAt: now.Add(time.Minute)})
	now = now.Add(2 * time.Minute)
	if _, ok, _ := m.Take(ctx, "b"); ok {
		t.Error("login kedaluwarsa masih diterima")
	}
}

func TestMemoryPending_Terbatas(t *testing.T) {
	m := newMemoryPending()
	now := time.Now()
	m.now = func() time.Time { return now }
	for i := range memoryPendingLimit {
		if err := m.Put(ctx, string(rune(i)), PendingLogin{ExpiresAt: now.Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Put(ctx, "lebih", PendingLogin{ExpiresAt: now.Add(time.Minute)}); !errors.Is(err, errPendingFull) {
		t.Errorf("penuh tetapi diterima: %v", err)
	}
	// Yang kedaluwarsa dibuang lebih dulu, lalu tempatnya dipakai.
	now = now.Add(2 * time.Minute)
	if err := m.Put(ctx, "lebih", PendingLogin{ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Errorf("sesudah kedaluwarsa: %v", err)
	}
}

func TestLocalPath(t *testing.T) {
	for in, want := range map[string]string{
		"/orders/1?x=2": "/orders/1?x=2", "/": "/",
		"//evil.test": "", "https://evil.test/": "", "/\\evil.test": "", "orders": "", "/a\r\nb": "", "": "",
	} {
		if got := localPath(in); got != want {
			t.Errorf("localPath(%q) = %q, mau %q", in, got, want)
		}
	}
}

// Lisensi cloud membaca hak pakai dari lease bertanda tangan di direktori
// state — yang membuat paket benar-benar berbeda di dalam produk.
func TestLicense_CloudMembacaLease(t *testing.T) {
	stateDir := t.TempDir()
	public := writeSignedLease(t, stateDir, "garment")
	kit, err := New(Options{ProductCode: "garment", Hooks: hooks, Getenv: envFrom(map[string]string{
		"GONSU_BASE_URL": "https://api.gonsu.example", "GONSU_INSTALLATION_ID": "inst_1",
		"GONSU_STATE_DIR": stateDir, "GONSU_LICENSE_PUBLIC_KEYS": public,
	})})
	if err != nil {
		t.Fatal(err)
	}
	l := kit.License()
	if v, unlimited := l.Limit(ctx, "users.max"); v != 5 || unlimited {
		t.Errorf("users.max = %d, %v", v, unlimited)
	}
	if !l.Feature(ctx, "garment.pattern_studio") || l.Feature(ctx, "garment.integration_pack") {
		t.Error("fitur dibaca salah")
	}
	if s := l.Status(ctx); s.Phase != PhaseNormal || s.PlanName != "Starter" || !s.Allowed {
		t.Errorf("status = %+v", s)
	}
}

// Lease sah milik produk lain tidak dipakai: seluruh produk diverifikasi
// dengan kunci yang sama.
func TestLicense_CloudMenolakLeaseProdukLain(t *testing.T) {
	stateDir := t.TempDir()
	public := writeSignedLease(t, stateDir, "produk-lain")
	kit, err := New(Options{ProductCode: "garment", Hooks: hooks, Getenv: envFrom(map[string]string{
		"GONSU_BASE_URL": "https://api.gonsu.example", "GONSU_INSTALLATION_ID": "inst_1",
		"GONSU_STATE_DIR": stateDir, "GONSU_LICENSE_PUBLIC_KEYS": public,
	})})
	if err != nil {
		t.Fatal(err)
	}
	if s := kit.License().Status(ctx); s.Phase != PhaseNotActivated {
		t.Errorf("lease produk lain dipakai: %+v", s)
	}
}

func writeSignedLease(t *testing.T, stateDir, productCode string) string {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	payload, _ := json.Marshal(map[string]any{
		"installation_id": "inst_1", "organization_id": "org_1", "product_code": productCode,
		"granted": true, "plan_code": "starter", "plan_name": "Starter", "status": "active",
		"schema_version": 1,
		"entries": []map[string]any{
			{"key": "users.max", "value_type": "integer", "integer": 5},
			{"key": "garment.pattern_studio", "value_type": "boolean", "boolean": true},
		},
		"issued_at": now, "expires_at": now.Add(72 * time.Hour), "grace_until": now.Add(144 * time.Hour),
		"heartbeat_seconds": 3600,
	})
	signature := ed25519.Sign(private, payload)
	signed, _ := json.Marshal(map[string]string{
		"lease":     base64.StdEncoding.EncodeToString(payload),
		"signature": "vault:v1:" + base64.StdEncoding.EncodeToString(signature),
		"key":       "license-signing-v1",
	})
	if err := os.WriteFile(filepath.Join(stateDir, "lease.json"), signed, 0o600); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(public)
}
