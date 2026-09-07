package gonsu

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// GrantEntry adalah satu hak pakai yang dibawa lease.
type GrantEntry struct {
	Key       string `json:"key"`
	ValueType string `json:"value_type"`
	Boolean   bool   `json:"boolean"`
	Integer   int64  `json:"integer"`
	Text      string `json:"text"`
	// Unlimited berbeda dari Integer nol, dan bedanya menentukan: nol berarti
	// tidak boleh sama sekali.
	Unlimited bool `json:"unlimited"`
}

// Lease adalah pernyataan bertanda tangan tentang apa yang boleh dijalankan
// sebuah instalasi, dan sampai kapan.
//
// Bentuknya WAJIB sama persis dengan licensing.Lease di sisi server. Field yang
// hilang di sini tidak menggagalkan verifikasi — tanda tangan menutupi byte
// mentah, bukan struct — tetapi nilainya menjadi tidak terbaca produk.
type Lease struct {
	InstallationID string `json:"installation_id"`
	OrganizationID string `json:"organization_id"`
	ApplicationID  string `json:"application_id"`
	ProductCode    string `json:"product_code"`

	Granted  bool         `json:"granted"`
	PlanCode string       `json:"plan_code"`
	PlanName string       `json:"plan_name"`
	Status   string       `json:"status"`
	Entries  []GrantEntry `json:"entries"`

	// SchemaVersion adalah versi BENTUK lease ini.
	//
	// Kontraknya satu kalimat: **naiknya versi skema wajib tetap dapat dibaca
	// pembaca lama.** GONSU boleh menambah field; ia TIDAK boleh mengubah arti
	// field yang sudah ada, dan tidak boleh menambahkan pembatasan baru yang
	// hanya dipahami pembaca baru. Pembatasan yang harus ditegakkan menempuh
	// jalan lain: masa berlaku yang lebih pendek, atau kunci penandatangan
	// baru yang memang tidak dikenali pembaca lama.
	//
	// Karena itu SDK yang menemukan versi lebih tinggi TIDAK berhenti melayani
	// — ia menandainya lewat Status.SchemaAhead dan mencatat peringatan.
	// Berhenti berarti setiap pemasangan pelanggan mati pada hari GONSU
	// memperbarui servernya, dan itu akibat yang jauh lebih buruk daripada
	// membaca lease dengan field yang belum dikenal.
	//
	// Nol berarti lease terbit sebelum bidang ini ada; diperlakukan sebagai 1.
	SchemaVersion int `json:"schema_version,omitempty"`

	// InstallationPublicKey mengikat lease ini pada SATU mesin.
	//
	// Diisi hanya untuk lisensi offline, dan justru di sanalah ia menentukan.
	// Pada instalasi online, menyalin lease ke mesin lain tidak berguna:
	// heartbeat berikutnya harus ditandatangani kunci privat yang tidak ikut
	// tersalin. Instalasi offline tidak pernah heartbeat, sehingga lease-nya
	// adalah SATU-SATUNYA penjaga.
	//
	// Bidang ini tertutup tanda tangan, jadi menghapusnya membuat tanda
	// tangannya tidak lagi cocok.
	InstallationPublicKey string `json:"installation_public_key,omitempty"`

	// Offline menandai lease yang diterbitkan untuk mesin tanpa jaringan.
	// Lease seperti ini tidak pernah dapat dicabut — hanya ExpiresAt yang
	// menghentikannya.
	Offline bool `json:"offline,omitempty"`

	IssuedAt   time.Time `json:"issued_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	GraceUntil time.Time `json:"grace_until"`

	HeartbeatSeconds int `json:"heartbeat_seconds"`
}

// SignedLease adalah lease beserta tanda tangannya, persis seperti yang dikirim
// GONSU dan persis seperti yang disimpan ke disk.
type SignedLease struct {
	// Lease adalah base64 dari JSON lease. Verifikasi dilakukan atas byte hasil
	// dekode, SEBELUM diurai — jadi apa pun yang diubah orang di dalamnya,
	// termasuk yang tidak dikenali versi SDK ini, ikut tertutup tanda tangan.
	Lease string `json:"lease"`
	// Signature dalam format OpenBao Transit: `vault:v<versi>:<base64>`.
	Signature string `json:"signature"`
	// KeyName menyebut kunci mana yang dipakai.
	KeyName string `json:"key"`
}

// ErrBadLeaseSignature berarti lease tidak ditandatangani GONSU.
//
// Yang paling mungkin: berkas cache diubah orang. Yang juga mungkin: kunci
// vendor di dalam binary sudah tidak lagi yang dipakai GONSU. Keduanya
// diperlakukan sama — lease itu tidak dipakai — karena dari sisi instalasi
// keduanya tidak dapat dibedakan.
var ErrBadLeaseSignature = errors.New("tanda tangan lease tidak sah")

// VerifyLease memeriksa tanda tangan lease dan mengurainya.
//
// Urutannya menentukan: verifikasi lebih dulu, urai kemudian. Mengurai lebih
// dulu berarti data yang belum dipercaya sudah masuk ke dalam struktur program.
func VerifyLease(keys []VendorKey, signed SignedLease) (Lease, error) {
	dipakai := 0
	for _, key := range keys {
		if len(key) == ed25519.PublicKeySize {
			dipakai++
		}
	}
	if dipakai == 0 {
		return Lease{}, errors.New("tidak ada kunci vendor yang dipasang")
	}

	payload, err := base64.StdEncoding.DecodeString(signed.Lease)
	if err != nil {
		return Lease{}, fmt.Errorf("%w: isi lease bukan base64 yang sah", ErrBadLeaseSignature)
	}

	signature, err := decodeVaultSignature(signed.Signature)
	if err != nil {
		return Lease{}, err
	}

	// SELURUH kunci dicoba, dan urutannya tidak dipilih berdasarkan
	// SignedLease.KeyName.
	//
	// KeyName berada di LUAR payload yang ditandatangani, jadi ia dapat ditulis
	// siapa pun yang memegang berkasnya. Memakainya untuk memilih kunci berarti
	// membiarkan penyusup mengarahkan verifikasi — tidak berbahaya selama
	// seluruh kandidatnya kunci GONSU, tetapi tetap kebiasaan yang salah.
	// Ia hanya dipakai untuk diagnosis.
	cocok := false
	for _, key := range keys {
		if len(key) != ed25519.PublicKeySize {
			continue
		}
		if ed25519.Verify(ed25519.PublicKey(key), payload, signature) {
			cocok = true
			break
		}
	}
	if !cocok {
		return Lease{}, ErrBadLeaseSignature
	}

	var lease Lease
	if err := json.Unmarshal(payload, &lease); err != nil {
		return Lease{}, fmt.Errorf("lease tidak dapat dibaca: %w", err)
	}
	return lease, nil
}

// ErrLeaseBukanUntukMesinIni berarti lease offline yang dibaca diterbitkan
// untuk instalasi lain.
//
// Yang paling mungkin: satu berkas lisensi disalin ke server kedua. Lisensi
// offline tidak pernah dapat dicabut, jadi pengikatan pada mesin adalah
// satu-satunya yang membatasinya pada satu pemasangan.
var ErrLeaseBukanUntukMesinIni = errors.New("lease offline diterbitkan untuk mesin lain")

// ErrLeaseOfflineTanpaPengikatan berarti lease menyebut dirinya offline tetapi
// tidak menyebut mesin mana pun.
//
// DITOLAK, bukan diterima dengan peringatan. Lease offline tanpa pengikatan
// adalah lisensi yang berlaku di berapa pun server sekaligus — dan menerimanya
// "untuk sementara" berarti tidak ada yang akan memperbaikinya.
var ErrLeaseOfflineTanpaPengikatan = errors.New("lease offline tidak mengikat mesin mana pun")

// VerifyOfflineLease memverifikasi lease offline BESERTA pengikatannya pada
// mesin ini.
//
// Terpisah dari VerifyLease dengan sengaja. Lease online tidak perlu diikat —
// menyalinnya ke mesin lain tidak berguna karena heartbeat berikutnya menuntut
// kunci privat yang tidak ikut tersalin. Lease offline tidak pernah heartbeat,
// sehingga tidak ada apa pun sesudah pemeriksaan ini yang akan menangkap
// penyalinan.
//
// publicKey adalah kunci publik instalasi ini, dalam bentuk base64 baku yang
// sama dengan yang dikirim saat meminta lisensi.
func VerifyOfflineLease(keys []VendorKey, signed SignedLease, publicKey string) (Lease, error) {
	lease, err := VerifyLease(keys, signed)
	if err != nil {
		return Lease{}, err
	}
	if !lease.Offline {
		return lease, nil
	}
	if lease.InstallationPublicKey == "" {
		return Lease{}, ErrLeaseOfflineTanpaPengikatan
	}
	// Perbandingan biasa, bukan konstan-waktu: keduanya kunci PUBLIK, dan yang
	// dibandingkan bukan rahasia. Yang dijaga di sini adalah pencocokan, bukan
	// kerahasiaan.
	if lease.InstallationPublicKey != publicKey {
		return Lease{}, ErrLeaseBukanUntukMesinIni
	}
	return lease, nil
}

// decodeVaultSignature membaca format `vault:v<versi>:<base64>`.
//
// Prefiksnya dibiarkan apa adanya alih-alih dilucuti di sisi server, supaya
// versi kunci ikut sampai ke instalasi. Ketika kunci penandatangan dirotasi,
// itulah yang memungkinkan produk mengenali lease yang ditandatangani kunci
// lama tanpa harus menebak.
func decodeVaultSignature(raw string) ([]byte, error) {
	parts := strings.SplitN(raw, ":", 3)
	if len(parts) != 3 || parts[0] != "vault" || !strings.HasPrefix(parts[1], "v") {
		return nil, fmt.Errorf("%w: bentuk tanda tangan tidak dikenali", ErrBadLeaseSignature)
	}

	signature, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: panjang tanda tangan tidak sesuai", ErrBadLeaseSignature)
	}
	return signature, nil
}

// State adalah kesegaran lease — SATU dari dua sumbu keputusan.
//
// Sumbu yang lain adalah Lease.Granted, yaitu apakah langganan sedang memberi
// hak pakai. Keduanya sengaja tidak digabung menjadi satu boolean: "langganan
// ditangguhkan" dan "instalasi ini sudah lama tidak dapat menghubungi GONSU"
// menuntut penanganan yang berbeda, dan pesan yang berbeda kepada pengguna.
type State string

const (
	// StateUnknown berarti belum ada lease sama sekali.
	StateUnknown State = "unknown"
	// StateActive berarti lease masih berlaku.
	StateActive State = "active"
	// StateGrace berarti lease sudah kedaluwarsa tetapi masih di dalam masa
	// tenggang. Produk sebaiknya memperingatkan pengguna, bukan berhenti.
	StateGrace State = "grace"
	// StateExpired berarti masa tenggang pun sudah lewat.
	StateExpired State = "expired"
)

// Status adalah jawaban yang dipakai produk untuk memutuskan.
type Status struct {
	State State
	Lease Lease
	// Fresh menandai lease berasal dari heartbeat terakhir yang berhasil, bukan
	// dari cache di disk. Hanya untuk diagnosis; keputusan tidak boleh
	// bergantung padanya.
	Fresh bool
	// SchemaAhead menandai lease memakai skema yang lebih baru daripada yang
	// dikenali SDK ini seutuhnya.
	//
	// BUKAN kegagalan, dan produk tidak boleh berhenti karenanya — lihat
	// Lease.SchemaVersion. Ia pertanda SDK-nya layak diperbarui, dan pantas
	// dicatat sekali di log, bukan ditunjukkan kepada pengguna akhir.
	SchemaAhead bool
}

// Allowed adalah pertanyaan tunggal yang biasanya ingin ditanyakan produk.
//
// Masa tenggang termasuk diizinkan, dan itu keputusan yang disengaja:
// mematikan pabrik pada detik lease kedaluwarsa adalah reaksi yang tidak dapat
// dibatalkan terhadap sesuatu yang paling sering hanyalah gangguan jaringan.
func (s Status) Allowed() bool {
	return s.Lease.Granted && (s.State == StateActive || s.State == StateGrace)
}

// Entry mencari satu hak pakai berdasarkan key.
func (s Status) Entry(key string) (GrantEntry, bool) {
	for _, entry := range s.Lease.Entries {
		if entry.Key == key {
			return entry, true
		}
	}
	return GrantEntry{}, false
}

// Feature melaporkan apakah sebuah fitur boolean menyala.
//
// Key yang tidak ada berarti TIDAK menyala. Itu arah default yang benar: hak
// pakai yang belum pernah diberikan tidak boleh menjadi aktif hanya karena
// versi produk lebih baru daripada katalog yang menerbitkannya.
func (s Status) Feature(key string) bool {
	entry, ok := s.Entry(key)
	return ok && entry.ValueType == "boolean" && entry.Boolean
}

// Limit mengembalikan batas numerik sebuah hak pakai.
//
// unlimited true berarti tanpa batas. Key yang tidak ada dikembalikan sebagai
// batas nol — tidak boleh sama sekali — dengan alasan yang sama seperti Feature.
func (s Status) Limit(key string) (value int64, unlimited bool) {
	entry, ok := s.Entry(key)
	if !ok || entry.ValueType != "integer" {
		return 0, false
	}
	return entry.Integer, entry.Unlimited
}

// StatusAt menghitung status sebuah lease pada satu titik waktu.
//
// Dipakai License.Status dengan waktu sekarang, dan diekspos supaya produk
// dapat menjawab pertanyaan seperti "kapan instalasi ini akan berhenti kalau
// jaringan tidak kunjung pulih" pada halaman diagnostiknya sendiri.
func StatusAt(lease Lease, now time.Time, skew time.Duration) Status {
	if skew < 0 {
		skew = 0
	}
	return Status{
		State:       stateAt(lease, now, skew),
		Lease:       lease,
		SchemaAhead: lease.schemaVersion() > SupportedSchemaVersion,
	}
}

// stateAt menghitung kesegaran sebuah lease pada satu titik waktu.
//
// Kelonggaran jam HANYA memperpanjang. Memperpendeknya berarti mengambil hak
// yang sudah dibayar pelanggan karena jam servernya meleset — kesalahan yang
// tidak pernah sepadan dengan beberapa menit penegakan yang didapat.
func stateAt(lease Lease, now time.Time, skew time.Duration) State {
	switch {
	case lease.ExpiresAt.IsZero():
		return StateUnknown
	case now.Before(lease.ExpiresAt.Add(skew)):
		return StateActive
	case now.Before(lease.GraceUntil.Add(skew)):
		return StateGrace
	default:
		return StateExpired
	}
}

// SupportedSchemaVersion adalah versi skema lease TERTINGGI yang dikenali SDK
// ini seutuhnya.
const SupportedSchemaVersion = 1

// DefaultClockSkew adalah kelonggaran jam bawaan.
//
// Lima menit: cukup untuk jam server yang tidak pernah menyentuh NTP, dan
// terlalu pendek untuk berguna sebagai cara memperpanjang lisensi.
const DefaultClockSkew = 5 * time.Minute

// schemaVersion membaca versi skema, memperlakukan nol sebagai 1.
func (l Lease) schemaVersion() int {
	if l.SchemaVersion <= 0 {
		return 1
	}
	return l.SchemaVersion
}

// heartbeatInterval mengembalikan irama yang disarankan lease.
func (l Lease) heartbeatInterval(fallback time.Duration) time.Duration {
	if l.HeartbeatSeconds <= 0 {
		return fallback
	}
	return time.Duration(l.HeartbeatSeconds) * time.Second
}
