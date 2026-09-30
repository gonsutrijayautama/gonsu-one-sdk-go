package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Jalur Portal mengantar ke halaman bisnis dan produk pemasangan ini; alamat
// tujuannya disusun kit, tidak pernah dari request.
func TestPortal_CloudMengantarKeHalamanBisnis(t *testing.T) {
	kit, err := New(Options{ProductCode: "garment", Hooks: hooks, Getenv: envFrom(map[string]string{
		"GONSU_PORTAL_URL":      "https://portal.gonsu.example/",
		"GONSU_ORGANIZATION_ID": "org_01H/x",
	})})
	if err != nil {
		t.Fatal(err)
	}
	if !kit.PortalConfigured() {
		t.Fatal("PortalConfigured = false padahal GONSU_PORTAL_URL terisi")
	}
	for path, want := range map[string]string{
		PortalSubscriptionPath: "https://portal.gonsu.example/organizations/org_01H%2Fx/subscriptions",
		PortalInvoicesPath:     "https://portal.gonsu.example/organizations/org_01H%2Fx/invoices",
		PortalPlansPath:        "https://portal.gonsu.example/organizations/org_01H%2Fx/catalog/garment",
		PortalPlansPath + "?to=https://attacker.test": "https://portal.gonsu.example/organizations/org_01H%2Fx/catalog/garment",
	} {
		rec := httptest.NewRecorder()
		kit.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != want {
			t.Errorf("%s: %d %q, ingin 303 %q", path, rec.Code, rec.Header().Get("Location"), want)
		}
	}
}

// Organization belum diketahui: halaman muka Portal, yang mengantar orangnya
// ke bisnisnya sendiri.
func TestPortal_TanpaOrganizationKeHalamanMuka(t *testing.T) {
	kit, err := New(Options{ProductCode: "garment", Hooks: hooks, Getenv: envFrom(map[string]string{
		"GONSU_PORTAL_URL": "https://portal.gonsu.example",
	})})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	kit.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, PortalSubscriptionPath, nil))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "https://portal.gonsu.example/" {
		t.Errorf("%d %q", rec.Code, rec.Header().Get("Location"))
	}
}

// Tanpa GONSU_PORTAL_URL: tidak ada tautan untuk ditampilkan, dan jalurnya 404
// alih-alih mengantar ke tempat yang ditebak.
func TestPortal_TanpaAlamatPortal(t *testing.T) {
	kit, err := New(Options{ProductCode: "garment", Hooks: hooks, Getenv: envFrom(map[string]string{
		"GONSU_ORGANIZATION_ID": "org_1",
	})})
	if err != nil {
		t.Fatal(err)
	}
	if kit.PortalConfigured() {
		t.Error("PortalConfigured = true tanpa GONSU_PORTAL_URL")
	}
	if _, ok := kit.PortalURL(ctx, PortalPlans); ok {
		t.Error("PortalURL ok tanpa GONSU_PORTAL_URL")
	}
	rec := httptest.NewRecorder()
	kit.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, PortalInvoicesPath, nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status %d, ingin 404", rec.Code)
	}
}

// Alamat Portal yang bukan http(s) menggagalkan start, sama seperti alamat
// GONSU lain: salah ketik di berkas env ketahuan saat itu juga.
func TestPortal_AlamatRusakDitolak(t *testing.T) {
	if _, err := New(Options{ProductCode: "garment", Hooks: hooks, Getenv: envFrom(map[string]string{
		"GONSU_PORTAL_URL": "portal.gonsu.example",
	})}); err == nil {
		t.Error("GONSU_PORTAL_URL tanpa skema diterima")
	}
}
