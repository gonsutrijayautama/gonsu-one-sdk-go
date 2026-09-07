package gonsu_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	gonsu "github.com/gonsutrijayautama/gonsu-one-sdk-go"
)

// issueLease menyusun lease bertanda tangan seperti yang dilakukan GONSU.
func issueLease(t *testing.T, key ed25519.PrivateKey, lease gonsu.Lease) gonsu.SignedLease {
	t.Helper()

	payload, err := json.Marshal(lease)
	if err != nil {
		t.Fatalf("menyusun lease: %v", err)
	}
	return gonsu.SignedLease{
		Lease:     base64.StdEncoding.EncodeToString(payload),
		Signature: "vault:v1:" + base64.StdEncoding.EncodeToString(ed25519.Sign(key, payload)),
		KeyName:   "license-signing-v1",
	}
}

func sampleLease(issued time.Time) gonsu.Lease {
	return gonsu.Lease{
		InstallationID: "ins_01M1",
		ProductCode:    "garment",
		Granted:        true,
		PlanCode:       "pro",
		Status:         "active",
		Entries: []gonsu.GrantEntry{
			{Key: "modul_penggajian", ValueType: "boolean", Boolean: true},
			{Key: "max_users", ValueType: "integer", Integer: 25},
			{Key: "max_lokasi", ValueType: "integer", Unlimited: true},
		},
		IssuedAt:         issued,
		ExpiresAt:        issued.Add(24 * time.Hour),
		GraceUntil:       issued.Add(96 * time.Hour),
		HeartbeatSeconds: 900,
	}
}

func TestVerifyLeaseMenerimaYangSah(t *testing.T) {
	t.Parallel()

	public, private, _ := ed25519.GenerateKey(nil)
	issued := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)

	lease, err := gonsu.VerifyLease([]gonsu.VendorKey{gonsu.VendorKey(public)}, issueLease(t, private, sampleLease(issued)))
	if err != nil {
		t.Fatalf("lease sah ditolak: %v", err)
	}
	if lease.PlanCode != "pro" || !lease.Granted {
		t.Fatalf("isi lease tidak sesuai: %+v", lease)
	}
}

// Inilah kriteria keluar Phase 2 yang paling menentukan: lease yang diubah
// orang harus ditolak, apa pun bagian yang diubahnya.
func TestVerifyLeaseMenolakYangDiubah(t *testing.T) {
	t.Parallel()

	public, private, _ := ed25519.GenerateKey(nil)
	_, penyerang, _ := ed25519.GenerateKey(nil)
	issued := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	asli := issueLease(t, private, sampleLease(issued))

	// Lease dengan isi yang menguntungkan penyerang, ditandatangani kunci lain.
	dipalsukan := sampleLease(issued)
	dipalsukan.PlanCode = "enterprise"
	dipalsukan.GraceUntil = issued.AddDate(10, 0, 0)
	palsu := issueLease(t, penyerang, dipalsukan)

	// Isi diubah, tanda tangan asli dipertahankan.
	diubah := sampleLease(issued)
	diubah.Entries[1].Integer = 100000
	payloadDiubah, err := json.Marshal(diubah)
	if err != nil {
		t.Fatalf("menyusun lease: %v", err)
	}

	cases := []struct {
		name   string
		signed gonsu.SignedLease
	}{
		{
			name:   "isi diubah, tanda tangan asli dipertahankan",
			signed: gonsu.SignedLease{Lease: base64.StdEncoding.EncodeToString(payloadDiubah), Signature: asli.Signature},
		},
		{
			name:   "ditandatangani kunci yang bukan kunci GONSU",
			signed: palsu,
		},
		{
			name:   "tanda tangan dari lease lain",
			signed: gonsu.SignedLease{Lease: asli.Lease, Signature: palsu.Signature},
		},
		{
			name:   "tanda tangan dibuang",
			signed: gonsu.SignedLease{Lease: asli.Lease},
		},
		{
			name:   "prefiks vault dibuang",
			signed: gonsu.SignedLease{Lease: asli.Lease, Signature: strings.TrimPrefix(asli.Signature, "vault:v1:")},
		},
		{
			name:   "satu byte tanda tangan dibalik",
			signed: gonsu.SignedLease{Lease: asli.Lease, Signature: flipOneByte(t, asli.Signature)},
		},
		{
			name:   "isi bukan base64",
			signed: gonsu.SignedLease{Lease: "%%%", Signature: asli.Signature},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := gonsu.VerifyLease([]gonsu.VendorKey{gonsu.VendorKey(public)}, tc.signed); !errors.Is(err, gonsu.ErrBadLeaseSignature) {
				t.Fatalf("lease diterima padahal seharusnya ditolak, err=%v", err)
			}
		})
	}
}

// balikSatuByte mengubah satu byte di dalam tanda tangan.
func flipOneByte(t *testing.T, signature string) string {
	t.Helper()

	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(signature, "vault:v1:"))
	if err != nil {
		t.Fatalf("tanda tangan bukan base64: %v", err)
	}
	raw[0] ^= 0x01
	return "vault:v1:" + base64.StdEncoding.EncodeToString(raw)
}

func TestStatusMengikutiUmurLease(t *testing.T) {
	t.Parallel()

	issued := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	lease := sampleLease(issued)

	cases := []struct {
		name    string
		now     time.Time
		state   gonsu.State
		allowed bool
	}{
		{"baru diterbitkan", issued.Add(time.Minute), gonsu.StateActive, true},
		{"sesaat sebelum kedaluwarsa", issued.Add(23 * time.Hour), gonsu.StateActive, true},
		{"tepat saat kedaluwarsa", issued.Add(24 * time.Hour), gonsu.StateGrace, true},
		{"di tengah masa tenggang", issued.Add(72 * time.Hour), gonsu.StateGrace, true},
		{"tepat saat tenggang habis", issued.Add(96 * time.Hour), gonsu.StateExpired, false},
		{"jauh setelah tenggang", issued.Add(240 * time.Hour), gonsu.StateExpired, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			status := gonsu.StatusAt(lease, tc.now, 0)
			if status.State != tc.state {
				t.Fatalf("state = %s, diharapkan %s", status.State, tc.state)
			}
			if status.Allowed() != tc.allowed {
				t.Fatalf("allowed = %t, diharapkan %t", status.Allowed(), tc.allowed)
			}
		})
	}
}

// Langganan yang ditangguhkan menutup hak pakai walau leasenya masih segar.
// Dua sumbu, dua keputusan yang berbeda.
func TestStatusMenolakLeaseSegarYangTidakDiberiHak(t *testing.T) {
	t.Parallel()

	issued := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	lease := sampleLease(issued)
	lease.Granted = false
	lease.Status = "suspended"

	status := gonsu.StatusAt(lease, issued.Add(time.Minute), 0)
	if status.State != gonsu.StateActive {
		t.Fatalf("state = %s, diharapkan active — leasenya memang masih segar", status.State)
	}
	if status.Allowed() {
		t.Fatal("hak pakai diberikan padahal langganan ditangguhkan")
	}
}

func TestStatusMembacaEntitlement(t *testing.T) {
	t.Parallel()

	issued := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	status := gonsu.StatusAt(sampleLease(issued), issued.Add(time.Minute), 0)

	if !status.Feature("modul_penggajian") {
		t.Fatal("modul_penggajian seharusnya menyala")
	}
	if status.Feature("modul_yang_tidak_ada") {
		t.Fatal("key yang tidak ada seharusnya dianggap padam")
	}

	value, unlimited := status.Limit("max_users")
	if value != 25 || unlimited {
		t.Fatalf("max_users = %d unlimited=%t, diharapkan 25 false", value, unlimited)
	}
	if _, unlimited := status.Limit("max_lokasi"); !unlimited {
		t.Fatal("max_lokasi seharusnya tanpa batas")
	}
	if value, unlimited := status.Limit("batas_yang_tidak_ada"); value != 0 || unlimited {
		t.Fatalf("key yang tidak ada = %d unlimited=%t, diharapkan 0 false", value, unlimited)
	}
}
