package gonsu_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	gonsu "github.com/gonsutrijayautama/gonsu-one-sdk-go"
)

// TestOIDC_DiterimaDariSapaan membuktikan produk mendapat nilai yang
// dibutuhkannya untuk memulai login — tanpa satu pun rahasia ikut.
func TestOIDC_DiterimaDariSapaan(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"installation": {"id":"ins_01M1","application_id":"app_01M1","status":"active"},
			"organization_id": "org_01M1",
			"application": {"slug":"pgn","product_code":"garment"},
			"oidc": {
				"issuer": "https://id.gonsu.example",
				"client_id": "abc123",
				"redirect_uri": "https://erp.pabrik-abc.co.id/auth/gonsu/callback"
			}
		}`))
	}))
	t.Cleanup(server.Close)

	license, err := gonsu.Open(gonsu.Options{
		BaseURL: server.URL, InstallationID: "ins_01M1",
		StateDir: t.TempDir(), VendorKeys: testVendorKeys(t),
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Sebelum sapaan pertama, belum ada apa pun — dan itu keadaan yang sah.
	if license.OIDC() != nil {
		t.Fatal("konfigurasi login ada sebelum sapaan pertama")
	}

	if err := license.Refresh(t.Context()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	config := license.OIDC()
	if config == nil {
		t.Fatal("konfigurasi login tidak diterima")
	}
	if config.Issuer != "https://id.gonsu.example" || config.ClientID != "abc123" {
		t.Errorf("konfigurasi = %+v", config)
	}
	if config.RedirectURI != "https://erp.pabrik-abc.co.id/auth/gonsu/callback" {
		t.Errorf("redirect_uri = %q", config.RedirectURI)
	}
}

// TestOIDC_TetapDiterimaWalauLeaseTidakAda menjaga urutan di dalam adopt yang
// paling mudah salah.
//
// Platform tanpa penandatangan lease TETAP dapat menerbitkan login. Kalau
// ketiadaan lease membuat fungsi itu keluar lebih dulu, konfigurasi login ikut
// terbuang — dan gejalanya adalah login yang tidak pernah dapat dimulai pada
// platform yang sebenarnya sudah menyiapkannya.
func TestOIDC_TetapDiterimaWalauLeaseTidakAda(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Tanpa `lease` sama sekali.
		_, _ = w.Write([]byte(`{
			"installation": {"id":"ins_01M1","application_id":"app_01M1","status":"active"},
			"organization_id": "org_01M1",
			"application": {"slug":"pgn","product_code":"garment"},
			"oidc": {"issuer":"https://id.gonsu.example","client_id":"abc123",
			         "redirect_uri":"https://erp.pabrik-abc.co.id/auth/gonsu/callback"}
		}`))
	}))
	t.Cleanup(server.Close)

	license, err := gonsu.Open(gonsu.Options{
		BaseURL: server.URL, InstallationID: "ins_01M1",
		StateDir: t.TempDir(), VendorKeys: testVendorKeys(t),
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := license.Refresh(t.Context()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	if license.OIDC() == nil {
		t.Fatal("konfigurasi login ikut terbuang karena lease tidak ada")
	}
}

// TestOIDC_SalinanBukanRujukan menjaga supaya pemanggil tidak dapat mengubah
// keadaan di dalam SDK.
//
// Produk yang menyimpan hasilnya lalu menimpanya akan mengubah apa yang
// dijawab pemanggil berikutnya — bug yang hanya muncul pada produk dengan lebih
// dari satu jalur login, dan tidak pernah pada test yang memanggilnya sekali.
func TestOIDC_SalinanBukanRujukan(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"installation": {"id":"ins_01M1","application_id":"app_01M1","status":"active"},
			"oidc": {"issuer":"https://id.gonsu.example","client_id":"abc123",
			         "redirect_uri":"https://erp.pabrik-abc.co.id/auth/gonsu/callback"}
		}`))
	}))
	t.Cleanup(server.Close)

	license, err := gonsu.Open(gonsu.Options{
		BaseURL: server.URL, InstallationID: "ins_01M1",
		StateDir: t.TempDir(), VendorKeys: testVendorKeys(t),
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := license.Refresh(t.Context()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	pertama := license.OIDC()
	pertama.ClientID = "diubah"

	if license.OIDC().ClientID != "abc123" {
		t.Fatal("pemanggil dapat mengubah keadaan di dalam SDK")
	}
}
