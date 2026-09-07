package gonsu_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
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
	RequestBody []struct {
		Name   string            `json:"name"`
		Path   string            `json:"path"`
		Signed bool              `json:"signed"`
		Body   string            `json:"body"`
		Input  map[string]string `json:"input"`
	} `json:"request_body"`
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
	if len(file.SigningPayload) == 0 || len(file.Lease) == 0 || len(file.RequestBody) == 0 {
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
					"signature":     gonsu.ErrBadLeaseSignature,
					"other_machine": gonsu.ErrLeaseBukanUntukMesinIni,
					"unbound":       gonsu.ErrLeaseOfflineTanpaPengikatan,
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

// TestContract_RequestBody membuktikan SDK MENGIRIM nama field yang sama.
//
// Yang dijaga di sini tidak dijaga TestContract_SigningPayload sama sekali:
// tanda tangan menutupi byte badan request, bukan artinya. SDK yang menuliskan
// `token` ketika server menunggu `activation_token` menghasilkan tanda tangan
// yang SAH atas badan yang SALAH — server menerima buktinya, lalu menolak
// isinya, dan pesan galatnya tidak menyebut field mana yang keliru.
func TestContract_RequestBody(t *testing.T) {
	t.Parallel()

	file := loadContract(t)
	private, err := base64.StdEncoding.DecodeString(file.VendorKey.Private)
	if err != nil {
		t.Fatalf("kunci uji: %v", err)
	}

	// Server palsu yang merekam apa yang dikirim. Alamatnya loopback, sehingga
	// penjagaan TLS SDK ini tidak perlu dilonggarkan untuk mengujinya.
	var (
		terekamPath string
		terekamBody []byte
		terekamTTD  string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		terekamPath = r.URL.Path
		terekamBody, _ = io.ReadAll(r.Body)
		terekamTTD = r.Header.Get("X-GONSU-Signature")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	client := gonsu.NewClient(server.URL, "ins_01M1KONTRAK0000000000000001",
		ed25519.PrivateKey(private), server.Client())

	kirim := map[string]func() error{
		"/license/v1/activate": func() error {
			_, err := client.Activate(t.Context(), "act_kontrak", "1.2.3", "linux")
			return err
		},
		"/license/v1/heartbeat": func() error {
			_, err := client.Heartbeat(t.Context(), "1.2.3", "linux")
			return err
		},
		"/license/v1/update": func() error {
			_, err := client.CheckUpdate(t.Context(), "1.2.3")
			return err
		},
		"/license/v1/deactivate": func() error {
			return client.Deactivate(t.Context())
		},
		"/license/v1/registry-credential": func() error {
			_, err := client.RegistryCredential(t.Context())
			return err
		},
	}

	for _, kasus := range file.RequestBody {
		t.Run(kasus.Name, func(t *testing.T) {
			jalankan, ada := kirim[kasus.Path]
			if !ada {
				t.Fatalf("kontrak menyebut %s tetapi SDK tidak punya method untuknya", kasus.Path)
			}
			if err := jalankan(); err != nil {
				t.Fatalf("memanggil %s: %v", kasus.Path, err)
			}

			if terekamPath != kasus.Path {
				t.Errorf("path terkirim %q, kontrak menuntut %q", terekamPath, kasus.Path)
			}
			// Dibandingkan sebagai BYTE, bukan sebagai JSON yang setara.
			// Urutan field dan spasi ikut ditandatangani, sehingga dua badan
			// yang "sama artinya" tetap menghasilkan tanda tangan berbeda.
			if string(terekamBody) != kasus.Body {
				t.Errorf("badan terkirim:\n  %s\nkontrak menuntut:\n  %s", terekamBody, kasus.Body)
			}
			if (terekamTTD != "") != kasus.Signed {
				t.Errorf("bertanda tangan=%v, kontrak menuntut %v", terekamTTD != "", kasus.Signed)
			}
		})
	}
}
