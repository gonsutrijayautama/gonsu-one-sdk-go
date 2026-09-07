package gonsu_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	gonsu "github.com/gonsutrijayautama/gonsu-one-sdk-go"
)

// ---------------------------------------------------------------------------
// KONTRAK LINTAS BAHASA
// ---------------------------------------------------------------------------
//
// testdata/contract.json dihasilkan server GONSU dan dibaca SETIAP SDK, dalam
// bahasa apa pun. Test di berkas ini adalah bukti bahwa SDK Go mematuhinya —
// dan sekaligus contoh bentuk test yang sama untuk SDK bahasa lain.
//
// Kalau berkas ini berubah, salah satu dari dua hal terjadi: format kawat
// memang sengaja diubah, atau ada yang mengubahnya tanpa sadar. Keduanya harus
// terlihat, dan keduanya terlihat di sini.

type contractFile struct {
	Version     int    `json:"version"`
	Description string `json:"description"`
	VendorKey   struct {
		Public  string `json:"public_base64"`
		Private string `json:"private_base64"`
	} `json:"vendor_key"`
	SigningPayload []struct {
		Name            string `json:"name"`
		InstallationID  string `json:"installation_id"`
		Method          string `json:"method"`
		Path            string `json:"path"`
		Timestamp       int64  `json:"timestamp_unix"`
		Nonce           string `json:"nonce"`
		BodyBase64      string `json:"body_base64"`
		PayloadBase64   string `json:"payload_base64"`
		SignatureBase64 string `json:"signature_base64"`
	} `json:"signing_payload"`
	Lease []struct {
		Name        string `json:"name"`
		Why         string `json:"why"`
		LeaseBase64 string `json:"lease_base64"`
		Signature   string `json:"signature"`
		KeyName     string `json:"key_name"`
		MachineKey  string `json:"machine_key_base64"`
		Now         string `json:"now"`
		SkewSeconds int    `json:"skew_seconds"`
		Expect      struct {
			Verified    bool   `json:"verified"`
			Error       string `json:"error"`
			State       string `json:"state"`
			Allowed     bool   `json:"allowed"`
			Offline     bool   `json:"offline"`
			SchemaAhead bool   `json:"schema_ahead"`
		} `json:"expect"`
	} `json:"lease"`
}

func loadContract(t *testing.T) contractFile {
	t.Helper()

	raw, err := os.ReadFile("testdata/contract.json")
	if err != nil {
		t.Fatalf("membaca kontrak: %v", err)
	}
	var file contractFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("mengurai kontrak: %v", err)
	}
	if len(file.SigningPayload) == 0 || len(file.Lease) == 0 {
		t.Fatal("kontrak kosong")
	}
	return file
}

// Setiap SDK WAJIB menandatangani byte yang sama persis.
//
// Bagian yang paling mudah salah dan paling sunyi ketika salah: method
// dihurufbesarkan, path ikut ditandatangani, dan badan diringkas sha256 hex.
// Tanda tangan yang salah selalu ditolak server dengan pesan yang sama seperti
// kunci yang salah — sehingga tanpa berkas ini, sebabnya dicari di tempat yang
// keliru berhari-hari.
func TestContract_SigningPayload(t *testing.T) {
	t.Parallel()

	file := loadContract(t)
	private, err := base64.StdEncoding.DecodeString(file.VendorKey.Private)
	if err != nil {
		t.Fatalf("kunci privat kontrak: %v", err)
	}

	for _, kasus := range file.SigningPayload {
		t.Run(kasus.Name, func(t *testing.T) {
			t.Parallel()

			body, err := base64.StdEncoding.DecodeString(kasus.BodyBase64)
			if err != nil {
				t.Fatalf("badan: %v", err)
			}
			payload := gonsu.SigningPayload(gonsu.SignedRequest{
				InstallationID: kasus.InstallationID,
				Method:         kasus.Method,
				Path:           kasus.Path,
				Timestamp:      time.Unix(kasus.Timestamp, 0).UTC(),
				Nonce:          kasus.Nonce,
				Body:           body,
			})

			if got := base64.StdEncoding.EncodeToString(payload); got != kasus.PayloadBase64 {
				t.Fatalf("payload berbeda dari kontrak\n  kontrak: %s\n  hasil  : %s",
					kasus.PayloadBase64, got)
			}
			if got := gonsu.Sign(ed25519.PrivateKey(private), gonsu.SignedRequest{
				InstallationID: kasus.InstallationID, Method: kasus.Method, Path: kasus.Path,
				Timestamp: time.Unix(kasus.Timestamp, 0).UTC(), Nonce: kasus.Nonce, Body: body,
			}); got != kasus.SignatureBase64 {
				t.Fatalf("tanda tangan berbeda dari kontrak")
			}
		})
	}
}

// Setiap SDK WAJIB mengambil keputusan yang sama atas lease yang sama, pada
// waktu yang sama. Inilah yang menjaga produk PHP dan produk Go memperlakukan
// pelanggan yang sama dengan cara yang sama.
func TestContract_Lease(t *testing.T) {
	t.Parallel()

	file := loadContract(t)
	public, err := base64.StdEncoding.DecodeString(file.VendorKey.Public)
	if err != nil {
		t.Fatalf("kunci publik kontrak: %v", err)
	}
	keys := []gonsu.VendorKey{gonsu.VendorKey(public)}

	for _, kasus := range file.Lease {
		t.Run(kasus.Name, func(t *testing.T) {
			t.Parallel()

			signed := gonsu.SignedLease{
				Lease: kasus.LeaseBase64, Signature: kasus.Signature, KeyName: kasus.KeyName,
			}
			lease, err := gonsu.VerifyOfflineLease(keys, signed, kasus.MachineKey)

			if !kasus.Expect.Verified {
				if err == nil {
					t.Fatalf("lease DITERIMA padahal kontrak menuntut penolakan\n  %s", kasus.Why)
				}
				// Jenis penolakan ikut diperiksa: menolak karena alasan yang
				// salah berarti perlindungan yang dikira ada sebenarnya tidak.
				harapan := map[string]error{
					"tanda_tangan":             gonsu.ErrBadLeaseSignature,
					"mesin_lain":               gonsu.ErrLeaseBukanUntukMesinIni,
					"offline_tanpa_pengikatan": gonsu.ErrLeaseOfflineTanpaPengikatan,
				}[kasus.Expect.Error]
				if harapan == nil {
					t.Fatalf("jenis galat %q belum dikenali test ini", kasus.Expect.Error)
				}
				if !errors.Is(err, harapan) {
					t.Fatalf("ditolak dengan alasan yang salah: %v, mau %v", err, harapan)
				}
				return
			}

			if err != nil {
				t.Fatalf("lease sah DITOLAK: %v\n  %s", err, kasus.Why)
			}

			now, err := time.Parse(time.RFC3339, kasus.Now)
			if err != nil {
				t.Fatalf("waktu kasus: %v", err)
			}
			status := gonsu.StatusAt(lease, now, time.Duration(kasus.SkewSeconds)*time.Second)

			if string(status.State) != kasus.Expect.State {
				t.Errorf("state = %s, kontrak menuntut %s\n  %s", status.State, kasus.Expect.State, kasus.Why)
			}
			if status.Allowed() != kasus.Expect.Allowed {
				t.Errorf("allowed = %t, kontrak menuntut %t\n  %s", status.Allowed(), kasus.Expect.Allowed, kasus.Why)
			}
			if lease.Offline != kasus.Expect.Offline {
				t.Errorf("offline = %t, kontrak menuntut %t", lease.Offline, kasus.Expect.Offline)
			}
			if status.SchemaAhead != kasus.Expect.SchemaAhead {
				t.Errorf("schema_ahead = %t, kontrak menuntut %t\n  %s",
					status.SchemaAhead, kasus.Expect.SchemaAhead, kasus.Why)
			}
		})
	}
}
