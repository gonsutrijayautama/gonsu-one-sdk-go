package gonsu_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	gonsu "github.com/gonsutrijayautama/gonsu-one-sdk-go"
)

func newKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("membangkitkan kunci: %v", err)
	}
	return public, private
}

func signature(t *testing.T, key ed25519.PrivateKey, lease gonsu.Lease, nama string) gonsu.SignedLease {
	t.Helper()
	payload, err := json.Marshal(lease)
	if err != nil {
		t.Fatalf("menyusun lease: %v", err)
	}
	return gonsu.SignedLease{
		Lease:     base64.StdEncoding.EncodeToString(payload),
		Signature: "vault:v1:" + base64.StdEncoding.EncodeToString(ed25519.Sign(key, payload)),
		KeyName:   nama,
	}
}

// ---------------------------------------------------------------------------
// ROTASI KUNCI
// ---------------------------------------------------------------------------

// Inilah alasan VendorKeys jamak: pada hari rotasi, produk memegang kunci lama
// DAN baru sekaligus. Kalau hanya satu yang bisa dipegang, setiap pemasangan
// berhenti memverifikasi pada detik GONSU berpindah kunci.
func TestRotation_LeaseKunciBaruDanLamaSamaSamaDiterima(t *testing.T) {
	t.Parallel()

	lamaPub, lamaPriv := newKeypair(t)
	baruPub, baruPriv := newKeypair(t)
	dipercaya := []gonsu.VendorKey{gonsu.VendorKey(lamaPub), gonsu.VendorKey(baruPub)}

	terbit := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	lease := gonsu.Lease{
		InstallationID: "ins_01M1", Granted: true,
		IssuedAt: terbit, ExpiresAt: terbit.Add(24 * time.Hour), GraceUntil: terbit.Add(96 * time.Hour),
	}

	for nama, priv := range map[string]ed25519.PrivateKey{
		"kunci lama": lamaPriv,
		"kunci baru": baruPriv,
	} {
		if _, err := gonsu.VerifyLease(dipercaya, signature(t, priv, lease, "license-signing-v1")); err != nil {
			t.Fatalf("%s ditolak: %v", nama, err)
		}
	}
}

// Kunci yang TIDAK ada di daftar tetap ditolak. Rotasi memperluas daftar, ia
// tidak melonggarkan pemeriksaannya.
func TestRotation_KunciDiLuarDaftarTetapDitolak(t *testing.T) {
	t.Parallel()

	dipercayaPub, _ := newKeypair(t)
	_, asingPriv := newKeypair(t)

	terbit := time.Now().UTC()
	lease := gonsu.Lease{InstallationID: "ins_01M1", IssuedAt: terbit, ExpiresAt: terbit.Add(time.Hour)}

	_, err := gonsu.VerifyLease(
		[]gonsu.VendorKey{gonsu.VendorKey(dipercayaPub)},
		signature(t, asingPriv, lease, "license-signing-v1"),
	)
	if !errors.Is(err, gonsu.ErrBadLeaseSignature) {
		t.Fatalf("tanda tangan kunci asing DITERIMA: %v", err)
	}
}

// KeyName berada di LUAR payload yang ditandatangani, jadi ia dapat ditulis
// siapa pun yang memegang berkasnya. Ia tidak boleh mempengaruhi hasil.
func TestRotation_KeyNamePalsuTidakMengubahHasil(t *testing.T) {
	t.Parallel()

	pub, priv := newKeypair(t)
	terbit := time.Now().UTC()
	lease := gonsu.Lease{InstallationID: "ins_01M1", IssuedAt: terbit, ExpiresAt: terbit.Add(time.Hour)}

	signed := signature(t, priv, lease, "kunci-yang-tidak-pernah-ada")
	if _, err := gonsu.VerifyLease([]gonsu.VendorKey{gonsu.VendorKey(pub)}, signed); err != nil {
		t.Fatalf("KeyName yang salah membuat lease sah ikut ditolak: %v", err)
	}
}

// ---------------------------------------------------------------------------
// TOLERANSI JAM
// ---------------------------------------------------------------------------

// Server pelanggan yang jamnya maju tidak boleh mematikan lisensi yang sah.
// Arah kelonggaran HANYA memperpanjang — kesalahan karena longgar berarti
// melayani beberapa menit lebih lama; kesalahan karena ketat berarti pelanggan
// yang membayar mendadak berhenti dilayani.
func TestClockSkew_JamYangMajuTidakMematikanLisensi(t *testing.T) {
	t.Parallel()

	terbit := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	habis := terbit.Add(24 * time.Hour)
	lease := gonsu.Lease{
		InstallationID: "ins_01M1", Granted: true,
		IssuedAt: terbit, ExpiresAt: habis, GraceUntil: habis.Add(72 * time.Hour),
	}

	// Jam server maju dua menit melewati batas.
	sedikitLewat := habis.Add(2 * time.Minute)

	if s := gonsu.StatusAt(lease, sedikitLewat, 0); s.State != gonsu.StateGrace {
		t.Fatalf("tanpa toleransi seharusnya sudah grace, dapat %s", s.State)
	}
	if s := gonsu.StatusAt(lease, sedikitLewat, gonsu.DefaultClockSkew); s.State != gonsu.StateActive {
		t.Fatalf("dengan toleransi 5 menit seharusnya masih active, dapat %s", s.State)
	}
}

// Toleransi tidak boleh menjadi cara memperpanjang lisensi: lewat jauh tetap
// lewat.
func TestClockSkew_TidakMenutupiKedaluwarsaSungguhan(t *testing.T) {
	t.Parallel()

	terbit := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	habis := terbit.Add(24 * time.Hour)
	lease := gonsu.Lease{
		InstallationID: "ins_01M1", Granted: true,
		IssuedAt: terbit, ExpiresAt: habis, GraceUntil: habis,
	}

	if s := gonsu.StatusAt(lease, habis.Add(time.Hour), gonsu.DefaultClockSkew); s.State != gonsu.StateExpired {
		t.Fatalf("lewat sejam masih dianggap %s", s.State)
	}
}

// Toleransi negatif diperlakukan sebagai nol, bukan sebagai pemendekan.
func TestClockSkew_NegatifTidakMemperpendek(t *testing.T) {
	t.Parallel()

	terbit := time.Now().UTC()
	lease := gonsu.Lease{
		InstallationID: "ins_01M1", Granted: true,
		IssuedAt: terbit, ExpiresAt: terbit.Add(time.Hour), GraceUntil: terbit.Add(2 * time.Hour),
	}

	if s := gonsu.StatusAt(lease, terbit.Add(30*time.Minute), -time.Hour); s.State != gonsu.StateActive {
		t.Fatalf("toleransi negatif memperpendek masa berlaku: %s", s.State)
	}
}

// ---------------------------------------------------------------------------
// VERSI SKEMA
// ---------------------------------------------------------------------------

// Skema yang lebih baru TIDAK menghentikan produk. Menghentikannya berarti
// setiap pemasangan pelanggan mati pada hari GONSU memperbarui servernya.
func TestSchema_VersiLebihBaruTetapDilayaniTetapiDitandai(t *testing.T) {
	t.Parallel()

	terbit := time.Now().UTC()
	lease := gonsu.Lease{
		SchemaVersion: gonsu.SupportedSchemaVersion + 1,
		Granted:       true, InstallationID: "ins_01M1",
		IssuedAt: terbit, ExpiresAt: terbit.Add(time.Hour), GraceUntil: terbit.Add(2 * time.Hour),
	}

	status := gonsu.StatusAt(lease, terbit.Add(time.Minute), gonsu.DefaultClockSkew)
	if !status.Allowed() {
		t.Fatal("produk berhenti melayani hanya karena skema lease lebih baru")
	}
	if !status.SchemaAhead {
		t.Fatal("skema yang lebih baru tidak ditandai; tidak ada yang tahu SDK-nya perlu diperbarui")
	}
}

// Lease lama tanpa field versi diperlakukan sebagai versi 1, bukan sebagai
// "lebih baru" maupun sebagai cacat.
func TestSchema_LeaseLamaTanpaVersiDiperlakukanSebagaiSatu(t *testing.T) {
	t.Parallel()

	terbit := time.Now().UTC()
	lease := gonsu.Lease{
		Granted: true, InstallationID: "ins_01M1",
		IssuedAt: terbit, ExpiresAt: terbit.Add(time.Hour), GraceUntil: terbit.Add(2 * time.Hour),
	}

	status := gonsu.StatusAt(lease, terbit.Add(time.Minute), gonsu.DefaultClockSkew)
	if status.SchemaAhead {
		t.Fatal("lease tanpa versi ditandai sebagai lebih baru")
	}
	if !status.Allowed() {
		t.Fatal("lease tanpa versi ditolak")
	}
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

// TLS wajib di production. SDK tidak punya gagasan tentang
// "production", jadi yang ditegakkan adalah aturan yang tidak butuh
// konfigurasi dan tidak dapat lupa dinyalakan: teks polos hanya menuju diri
// sendiri.
func TestTLS_HTTPPolosKeHostPublikDitolak(t *testing.T) {
	t.Parallel()

	kasus := []struct {
		nama    string
		baseURL string
		ditolak bool
	}{
		{"https ke host publik", "https://api.gonsu.cloud", false},
		{"http ke host publik", "http://api.gonsu.cloud", true},
		{"http ke localhost", "http://localhost:8091", false},
		{"http ke 127.0.0.1", "http://127.0.0.1:8091", false},
		{"http ke ::1", "http://[::1]:8091", false},
		// Nama yang MENGANDUNG localhost bukan localhost. Tanpa perbandingan
		// yang tepat, `localhost.penyusup.example` akan lolos.
		{"host yang menyerupai localhost", "http://localhost.penyusup.example", true},
		{"skema asing", "ftp://api.gonsu.cloud", true},
	}

	for _, k := range kasus {
		t.Run(k.nama, func(t *testing.T) {
			t.Parallel()

			_, err := gonsu.Open(gonsu.Options{
				BaseURL:        k.baseURL,
				InstallationID: "ins_01M1",
				StateDir:       t.TempDir(),
				VendorKeys:     []gonsu.VendorKey{gonsu.VendorKey(make([]byte, 32))},
			})
			ditolak := errors.Is(err, gonsu.ErrInsecureBaseURL)
			if ditolak != k.ditolak {
				t.Fatalf("BaseURL %q: ditolak=%t, mau %t (err=%v)", k.baseURL, ditolak, k.ditolak, err)
			}
		})
	}
}
