package gonsu_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	gonsu "github.com/gonsutrijayautama/gonsu-one-sdk-go"
)

// ---------------------------------------------------------------------------
// MEMBUKA
// ---------------------------------------------------------------------------

// Kunci privat instalasi lahir SEKALI dan tinggal di StateDir.
//
// Kalau ia dibuat ulang setiap kali produk dimulai, instalasi kehilangan
// identitasnya pada restart pertama — dan lisensi offline yang sudah terikat
// pada kunci lama menjadi tidak berlaku tanpa ada yang tahu sebabnya.
func TestPublicKey_TetapSamaAntarPembukaan(t *testing.T) {
	t.Parallel()

	stateDir := t.TempDir()
	buka := func() *gonsu.License {
		t.Helper()
		license, err := gonsu.Open(gonsu.Options{
			BaseURL: "https://api.contoh.invalid", InstallationID: "ins_01M1",
			StateDir: stateDir, VendorKeys: kunciVendorUji(t),
		})
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		return license
	}

	pertama := buka().PublicKey()
	if pertama == "" {
		t.Fatal("kunci publik kosong")
	}
	if kedua := buka().PublicKey(); kedua != pertama {
		t.Fatalf("kunci berubah antar pembukaan: %q lalu %q", pertama, kedua)
	}
	// Berkas kuncinya juga harus benar-benar ada di disk, bukan hanya di memori.
	if _, err := os.Stat(filepath.Join(stateDir, "installation.key")); err != nil {
		t.Fatalf("kunci tidak tersimpan: %v", err)
	}
}

func kunciVendorUji(t *testing.T) []gonsu.VendorKey {
	t.Helper()
	public, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("membangkitkan kunci: %v", err)
	}
	return []gonsu.VendorKey{gonsu.VendorKey(public)}
}

// ---------------------------------------------------------------------------
// KUNCI VENDOR
// ---------------------------------------------------------------------------

func TestParseVendorKeys(t *testing.T) {
	t.Parallel()

	sah := func() string {
		public, _, _ := ed25519.GenerateKey(nil)
		return base64.StdEncoding.EncodeToString(public)
	}

	if _, err := gonsu.ParseVendorKeys(sah(), sah()); err != nil {
		t.Fatalf("dua kunci sah ditolak: %v", err)
	}

	// Satu kunci rusak membuat SELURUH panggilan gagal. Kunci yang diam-diam
	// dilewati adalah kunci yang tidak ada — dan pada hari rotasi itu berarti
	// produk berhenti tanpa ada yang tahu sebabnya.
	if _, err := gonsu.ParseVendorKeys(sah(), "bukan-base64"); err == nil {
		t.Fatal("kunci rusak diterima diam-diam")
	}
	if _, err := gonsu.ParseVendorKeys(); err == nil {
		t.Fatal("daftar kosong diterima")
	}
}

func TestMustVendorKeys_PanicSaatSalah(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Fatal("MustVendorKeys tidak panic untuk kunci yang salah")
		}
	}()
	// Untuk kunci yang ditanam saat build: kalau nilainya salah, produk memang
	// tidak boleh berjalan sama sekali. Gagal saat start jauh lebih baik
	// daripada gagal pada pemasangan pelanggan berbulan-bulan kemudian.
	gonsu.MustVendorKeys("bukan-base64")
}

// ---------------------------------------------------------------------------
// LISENSI OFFLINE
// ---------------------------------------------------------------------------

func leaseOfflineUji(t *testing.T, key ed25519.PrivateKey, publicKeyMesin string) gonsu.SignedLease {
	t.Helper()

	terbit := time.Now().UTC()
	payload, err := json.Marshal(gonsu.Lease{
		InstallationID: "ins_01M1", Granted: true, PlanCode: "enterprise",
		InstallationPublicKey: publicKeyMesin, Offline: true,
		IssuedAt: terbit, ExpiresAt: terbit.Add(90 * 24 * time.Hour),
		GraceUntil: terbit.Add(90 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("menyusun lease: %v", err)
	}
	return gonsu.SignedLease{
		Lease:     base64.StdEncoding.EncodeToString(payload),
		Signature: "vault:v1:" + base64.StdEncoding.EncodeToString(ed25519.Sign(key, payload)),
		KeyName:   "license-signing-v1",
	}
}

func TestInstallOffline_DipasangDanBertahan(t *testing.T) {
	t.Parallel()

	public, private, _ := ed25519.GenerateKey(nil)
	stateDir := t.TempDir()
	opsi := gonsu.Options{
		BaseURL: "https://api.contoh.invalid", InstallationID: "ins_01M1",
		StateDir: stateDir, VendorKeys: []gonsu.VendorKey{gonsu.VendorKey(public)},
	}

	license, err := gonsu.Open(opsi)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := license.InstallOffline(leaseOfflineUji(t, private, license.PublicKey())); err != nil {
		t.Fatalf("InstallOffline: %v", err)
	}
	if !license.Status().Allowed() {
		t.Fatal("lisensi offline terpasang tetapi tidak memberi hak")
	}

	// Dibuka ulang TANPA jaringan: inilah gunanya lisensi offline.
	lagi, err := gonsu.Open(opsi)
	if err != nil {
		t.Fatalf("Open ulang: %v", err)
	}
	if !lagi.Status().Allowed() {
		t.Fatal("lisensi offline tidak bertahan antar pembukaan")
	}
	if !lagi.Status().Lease.Offline {
		t.Error("lease yang dibaca tidak lagi ditandai offline")
	}
}

// Berkas yang ditolak TIDAK boleh tersimpan: lisensi yang gagal lalu tetap
// tertulis ke disk hanya membingungkan pemeriksaan berikutnya.
func TestInstallOffline_YangDitolakTidakDisimpan(t *testing.T) {
	t.Parallel()

	public, private, _ := ed25519.GenerateKey(nil)
	stateDir := t.TempDir()
	license, err := gonsu.Open(gonsu.Options{
		BaseURL: "https://api.contoh.invalid", InstallationID: "ins_01M1",
		StateDir: stateDir, VendorKeys: []gonsu.VendorKey{gonsu.VendorKey(public)},
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Terikat pada mesin LAIN.
	mesinLain, _, _ := ed25519.GenerateKey(nil)
	err = license.InstallOffline(leaseOfflineUji(t, private,
		base64.StdEncoding.EncodeToString(mesinLain)))
	if !errors.Is(err, gonsu.ErrLeaseBukanUntukMesinIni) {
		t.Fatalf("lisensi mesin lain diterima: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "lease.json")); !os.IsNotExist(err) {
		t.Fatal("lease yang ditolak tetap ditulis ke disk")
	}
	if license.Status().Allowed() {
		t.Fatal("hak diberikan padahal lisensinya ditolak")
	}
}

// ---------------------------------------------------------------------------
// MENCOPOT
// ---------------------------------------------------------------------------

func TestDeactivate_MelepaskanDanMembuangLeaseLokal(t *testing.T) {
	t.Parallel()

	issued := time.Now().UTC()
	platform := platformBaru(t, issued)
	stateDir := t.TempDir()

	license, err := gonsu.Open(gonsu.Options{
		BaseURL: platform.server.URL, InstallationID: "ins_01M1",
		StateDir: stateDir, VendorKeys: []gonsu.VendorKey{platform.vendorKey()},
		Clock: func() time.Time { return issued.Add(time.Minute) },
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := license.Activate(t.Context(), "token-aktivasi"); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if !license.Status().Allowed() {
		t.Fatal("belum aktif setelah Activate")
	}

	if err := license.Deactivate(t.Context()); err != nil {
		t.Fatalf("Deactivate: %v", err)
	}
	if license.Status().State != gonsu.StateUnknown {
		t.Fatalf("state setelah dicopot = %s, mau unknown", license.Status().State)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "lease.json")); !os.IsNotExist(err) {
		t.Fatal("lease lokal tidak dibuang saat pencopotan")
	}
}

// Jaringan yang putus TIDAK membatalkan keputusan pelanggan mencopot.
//
// Lease lokal tetap dibuang: meninggalkan lease yang masih berlaku di disk
// mesin yang sudah dicopot hanya menyisakan berkas yang dapat dipakai orang
// lain. Galatnya dikembalikan supaya pemanggil dapat mencatatnya, bukan supaya
// pencopotan dibatalkan.
func TestDeactivate_GONSUTidakTerjangkauTetapMembuangLease(t *testing.T) {
	t.Parallel()

	issued := time.Now().UTC()
	platform := platformBaru(t, issued)
	stateDir := t.TempDir()

	license, err := gonsu.Open(gonsu.Options{
		BaseURL: platform.server.URL, InstallationID: "ins_01M1",
		StateDir: stateDir, VendorKeys: []gonsu.VendorKey{platform.vendorKey()},
		Clock: func() time.Time { return issued.Add(time.Minute) },
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := license.Activate(t.Context(), "token-aktivasi"); err != nil {
		t.Fatalf("Activate: %v", err)
	}

	platform.server.Close() // GONSU hilang di tengah pencopotan

	if err := license.Deactivate(t.Context()); err == nil {
		t.Fatal("kegagalan menghubungi GONSU tidak dilaporkan")
	}
	if _, err := os.Stat(filepath.Join(stateDir, "lease.json")); !os.IsNotExist(err) {
		t.Fatal("lease lokal tetap ada padahal pelanggan sudah mencopot")
	}
	if license.Status().Allowed() {
		t.Fatal("hak masih diberikan setelah dicopot")
	}
}

// Endpoint yang dipanggil harus /license/v1/deactivate dan bertanda tangan.
// Salah alamat berarti GONSU tidak pernah tahu pemasangan ini dicopot.
func TestDeactivate_MemanggilEndpointYangBenar(t *testing.T) {
	t.Parallel()

	var jalur, tandaTangan string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jalur = r.URL.Path
		tandaTangan = r.Header.Get("X-GONSU-Signature")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	license, err := gonsu.Open(gonsu.Options{
		BaseURL: server.URL, InstallationID: "ins_01M1",
		StateDir: t.TempDir(), VendorKeys: kunciVendorUji(t),
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := license.Deactivate(t.Context()); err != nil {
		t.Fatalf("Deactivate: %v", err)
	}
	if jalur != "/license/v1/deactivate" {
		t.Fatalf("jalur = %q", jalur)
	}
	if tandaTangan == "" {
		t.Fatal("permintaan pencopotan tidak ditandatangani")
	}
}

// ---------------------------------------------------------------------------
// PEMBARUAN DAN KREDENSIAL REGISTRY
// ---------------------------------------------------------------------------

func TestCheckUpdate_MembacaTawaranRilis(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/license/v1/update" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"current_version":"1.0.0","up_to_date":false,
			"latest":{"version":"1.2.0","channel":"stable"}}`))
	}))
	t.Cleanup(server.Close)

	license, err := gonsu.Open(gonsu.Options{
		BaseURL: server.URL, InstallationID: "ins_01M1",
		StateDir: t.TempDir(), VendorKeys: kunciVendorUji(t), Version: "1.0.0",
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	offer, err := license.CheckUpdate(t.Context())
	if err != nil {
		t.Fatalf("CheckUpdate: %v", err)
	}
	if offer.UpToDate || offer.Latest == nil || offer.Latest.Version != "1.2.0" {
		t.Fatalf("tawaran salah dibaca: %+v", offer)
	}
}

func TestRegistryCredential_Dibaca(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/license/v1/registry-credential" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"registry":"registry.gonsu.example","username":"ins_01M1",
			"password":"rahasia","expires_at":"2027-01-01T00:00:00Z"}`))
	}))
	t.Cleanup(server.Close)

	license, err := gonsu.Open(gonsu.Options{
		BaseURL: server.URL, InstallationID: "ins_01M1",
		StateDir: t.TempDir(), VendorKeys: kunciVendorUji(t),
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	cred, err := license.RegistryCredential(t.Context())
	if err != nil {
		t.Fatalf("RegistryCredential: %v", err)
	}
	if cred.Registry == "" || cred.Username != "ins_01M1" || cred.Password == "" {
		t.Fatalf("kredensial tidak lengkap: registry=%q user=%q", cred.Registry, cred.Username)
	}
}

// ---------------------------------------------------------------------------
// MEMBEDAKAN DITOLAK DARI TIDAK TERJANGKAU
// ---------------------------------------------------------------------------

// Perbedaan ini menentukan perilaku: yang ditolak tidak akan berubah dengan
// dicoba lagi lebih cepat, sedangkan yang tidak terjangkau justru harus.
// Menyamakannya berarti instalasi yang dicabut membanjiri GONSU dengan
// percobaan ulang, atau gangguan jaringan lima menit menghentikan pelanggan.
func TestIsUnauthorized_MembedakanPenolakanDariGangguan(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":"unauthenticated","message":"Installation dicabut."}}`))
	}))
	t.Cleanup(server.Close)

	license, err := gonsu.Open(gonsu.Options{
		BaseURL: server.URL, InstallationID: "ins_01M1",
		StateDir: t.TempDir(), VendorKeys: kunciVendorUji(t),
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	err = license.Refresh(t.Context())
	if err == nil {
		t.Fatal("penolakan tidak dilaporkan")
	}
	if !gonsu.IsUnauthorized(err) {
		t.Fatalf("penolakan tidak dikenali sebagai unauthorized: %v", err)
	}
	// Pesannya harus terbaca manusia; kodenya yang dijadikan pegangan program.
	if err.Error() == "" {
		t.Fatal("galat tanpa pesan")
	}

	// Server yang mati adalah gangguan, BUKAN penolakan.
	server.Close()
	if err := license.Refresh(t.Context()); gonsu.IsUnauthorized(err) {
		t.Fatalf("gangguan jaringan dikira penolakan: %v", err)
	}
}
