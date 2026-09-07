package gonsu_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	gonsu "github.com/gonsutrijayautama/gonsu-one-sdk-go"
)

// fakePlatform meniru /license/v1 secukupnya untuk menguji SDK.
type fakePlatform struct {
	server *httptest.Server
	key    ed25519.PrivateKey
	issued time.Time
	// permintaan menghitung berapa kali heartbeat sampai.
	permintaan int
}

func newFakePlatform(t *testing.T, issued time.Time) *fakePlatform {
	t.Helper()

	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("membangkitkan kunci vendor: %v", err)
	}

	platform := &fakePlatform{key: private, issued: issued}
	mux := http.NewServeMux()
	mux.HandleFunc("/license/v1/activate", platform.jawab)
	mux.HandleFunc("/license/v1/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		platform.permintaan++
		// Tanda tangan request diperiksa sekadar keberadaannya: yang diuji di
		// sini adalah perilaku SDK terhadap lease, bukan verifikasi server —
		// itu sudah diuji di sisi server, dan formatnya dijaga test lintas
		// module (internal/licensing/sdk_compat_test.go).
		if r.Header.Get("X-GONSU-Signature") == "" {
			http.Error(w, `{"error":{"code":"unauthenticated"}}`, http.StatusUnauthorized)
			return
		}
		platform.jawab(w, r)
	})

	mux.HandleFunc("/license/v1/deactivate", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-GONSU-Signature") == "" {
			http.Error(w, `{"error":{"code":"unauthenticated"}}`, http.StatusUnauthorized)
			return
		}
		// 204 tanpa badan, persis seperti GONSU sungguhan.
		w.WriteHeader(http.StatusNoContent)
	})

	platform.server = httptest.NewServer(mux)
	t.Cleanup(platform.server.Close)
	return platform
}

func (p *fakePlatform) jawab(w http.ResponseWriter, _ *http.Request) {
	lease := sampleLease(p.issued)
	signed := gonsu.SignedLease{}
	payload, _ := json.Marshal(lease)
	signed.Lease = encode(payload)
	signed.Signature = "vault:v1:" + encode(ed25519.Sign(p.key, payload))
	signed.KeyName = "license-signing-v1"

	response := map[string]any{
		"installation":    map[string]any{"id": "ins_01M1", "status": "active"},
		"organization_id": "org_01M1",
		"application":     map[string]any{"slug": "garment", "product_code": "garment"},
		"lease":           signed,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (p *fakePlatform) vendorKey() gonsu.VendorKey {
	public, _ := p.key.Public().(ed25519.PublicKey)
	return gonsu.VendorKey(public)
}

func encode(payload []byte) string {
	return base64Std.EncodeToString(payload)
}

// Kriteria keluar Phase 2: instalasi tetap berjalan ketika GONSU tidak dapat
// dihubungi sama sekali, dan berhenti sendiri setelah masa tenggang habis.
func TestInstalasiBertahanSaatPlatformTidakDapatDihubungi(t *testing.T) {
	issued := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	platform := newFakePlatform(t, issued)
	stateDir := t.TempDir()

	sekarang := issued.Add(time.Minute)
	buka := func() *gonsu.License {
		t.Helper()
		license, err := gonsu.Open(gonsu.Options{
			BaseURL:        platform.server.URL,
			InstallationID: "ins_01M1",
			StateDir:       stateDir,
			VendorKeys:     []gonsu.VendorKey{platform.vendorKey()},
			Version:        "1.0.0",
			Platform:       "linux/amd64",
			Clock:          func() time.Time { return sekarang },
		})
		if err != nil {
			t.Fatalf("membuka lisensi: %v", err)
		}
		return license
	}

	// 1. Aktivasi pertama, platform sehat.
	license := buka()
	if err := license.Activate(context.Background(), "act_token"); err != nil {
		t.Fatalf("aktivasi gagal: %v", err)
	}
	if status := license.Status(); status.State != gonsu.StateActive || !status.Allowed() {
		t.Fatalf("setelah aktivasi: %s", status)
	}

	// 2. Platform mati total, produk dimulai ulang.
	platform.server.Close()

	license = buka()
	status := license.Status()
	if status.State != gonsu.StateActive || !status.Allowed() {
		t.Fatalf("instalasi berhenti padahal lease di disk masih berlaku: %s", status)
	}
	if status.Fresh {
		t.Fatal("status mengaku segar padahal belum ada heartbeat yang berhasil")
	}

	// 3. Heartbeat gagal tidak boleh membatalkan lease yang dipegang.
	if err := license.Refresh(context.Background()); err == nil {
		t.Fatal("heartbeat ke platform yang mati seharusnya gagal")
	}
	if status := license.Status(); !status.Allowed() {
		t.Fatalf("lease dibatalkan hanya karena heartbeat gagal: %s", status)
	}

	// 4. Lewat kedaluwarsa, masih di dalam tenggang: berjalan dengan peringatan.
	sekarang = issued.Add(30 * time.Hour)
	if status := license.Status(); status.State != gonsu.StateGrace || !status.Allowed() {
		t.Fatalf("di dalam masa tenggang: %s", status)
	}

	// 5. Tenggang habis: berhenti, tanpa perlu ada yang memberitahu.
	sekarang = issued.Add(120 * time.Hour)
	if status := license.Status(); status.State != gonsu.StateExpired || status.Allowed() {
		t.Fatalf("setelah tenggang habis: %s", status)
	}
}

// Cache yang diubah orang ditolak, dan produk berperilaku seolah belum pernah
// menerima lease sama sekali.
func TestCacheYangDiubahDitolak(t *testing.T) {
	issued := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	platform := newFakePlatform(t, issued)
	stateDir := t.TempDir()

	options := gonsu.Options{
		BaseURL:        platform.server.URL,
		InstallationID: "ins_01M1",
		StateDir:       stateDir,
		VendorKeys:     []gonsu.VendorKey{platform.vendorKey()},
	}
	options.Clock = func() time.Time { return issued.Add(time.Minute) }

	license, err := gonsu.Open(options)
	if err != nil {
		t.Fatalf("membuka lisensi: %v", err)
	}
	if err := license.Activate(context.Background(), "act_token"); err != nil {
		t.Fatalf("aktivasi gagal: %v", err)
	}

	// Seseorang mengubah isi lease di disk supaya paketnya naik.
	path := filepath.Join(stateDir, "lease.json")
	raw, err := os.ReadFile(path) //nolint:gosec // path dari TempDir milik test
	if err != nil {
		t.Fatalf("membaca cache: %v", err)
	}
	var signed gonsu.SignedLease
	if err := json.Unmarshal(raw, &signed); err != nil {
		t.Fatalf("membaca cache: %v", err)
	}
	diubah := sampleLease(issued)
	diubah.PlanCode = "enterprise"
	diubah.GraceUntil = issued.AddDate(10, 0, 0)
	payload, _ := json.Marshal(diubah)
	signed.Lease = encode(payload)
	diganti, _ := json.Marshal(signed)
	if err := os.WriteFile(path, diganti, 0o600); err != nil {
		t.Fatalf("menulis cache: %v", err)
	}

	license, err = gonsu.Open(options)
	if err != nil {
		t.Fatalf("membuka lisensi: %v", err)
	}
	if status := license.Status(); status.State != gonsu.StateUnknown || status.Allowed() {
		t.Fatalf("lease yang diubah diterima: %s", status)
	}
}

// Direktori state yang disalin dari mesin lain tidak boleh membuat satu lisensi
// dapat dipakai berapa pun banyaknya instalasi.
func TestLeaseMilikInstalasiLainDitolak(t *testing.T) {
	issued := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	platform := newFakePlatform(t, issued)
	stateDir := t.TempDir()

	license, err := gonsu.Open(gonsu.Options{
		BaseURL:        platform.server.URL,
		InstallationID: "ins_01M1",
		StateDir:       stateDir,
		VendorKeys:     []gonsu.VendorKey{platform.vendorKey()},
		Clock:          func() time.Time { return issued.Add(time.Minute) },
	})
	if err != nil {
		t.Fatalf("membuka lisensi: %v", err)
	}
	if err := license.Activate(context.Background(), "act_token"); err != nil {
		t.Fatalf("aktivasi gagal: %v", err)
	}

	// Direktori yang sama, tetapi dipakai instalasi dengan id berbeda.
	lain, err := gonsu.Open(gonsu.Options{
		BaseURL:        platform.server.URL,
		InstallationID: "ins_LAIN",
		StateDir:       stateDir,
		VendorKeys:     []gonsu.VendorKey{platform.vendorKey()},
		Clock:          func() time.Time { return issued.Add(time.Minute) },
	})
	if err != nil {
		t.Fatalf("membuka lisensi: %v", err)
	}
	if status := lain.Status(); status.State != gonsu.StateUnknown || status.Allowed() {
		t.Fatalf("lease milik instalasi lain diterima: %s", status)
	}
}

func TestHeartbeatMembawaTandaTangan(t *testing.T) {
	issued := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	platform := newFakePlatform(t, issued)

	license, err := gonsu.Open(gonsu.Options{
		BaseURL:        platform.server.URL,
		InstallationID: "ins_01M1",
		StateDir:       t.TempDir(),
		VendorKeys:     []gonsu.VendorKey{platform.vendorKey()},
		Clock:          func() time.Time { return issued.Add(time.Minute) },
	})
	if err != nil {
		t.Fatalf("membuka lisensi: %v", err)
	}
	if err := license.Activate(context.Background(), "act_token"); err != nil {
		t.Fatalf("aktivasi gagal: %v", err)
	}
	if err := license.Refresh(context.Background()); err != nil {
		t.Fatalf("heartbeat gagal: %v", err)
	}
	if platform.permintaan != 1 {
		t.Fatalf("heartbeat sampai %d kali, diharapkan 1", platform.permintaan)
	}
	if status := license.Status(); !status.Fresh {
		t.Fatal("status tidak ditandai segar setelah heartbeat berhasil")
	}
}
