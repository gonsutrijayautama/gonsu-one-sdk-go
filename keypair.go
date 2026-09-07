package gonsu

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// keypairFile adalah nama berkas kunci privat installation di dalam StateDir.
const keypairFile = "installation.key"

// loadOrCreateKeypair membaca kunci privat installation, membuatnya bila belum ada.
//
// Kunci ini adalah IDENTITAS instalasi terhadap GONSU. Yang memegangnya dapat
// berpura-pura menjadi instalasi ini — meminta lease, dan meminta identitas
// dibuatkan atas namanya. Karena itu berkasnya 0600 dan tidak pernah dikirim ke
// mana pun; yang dikirim saat aktivasi hanya kunci publiknya.
func loadOrCreateKeypair(stateDir string) (ed25519.PrivateKey, error) {
	path := filepath.Join(stateDir, keypairFile)

	raw, err := os.ReadFile(path) //nolint:gosec // path dibentuk dari StateDir milik produk sendiri
	switch {
	case err == nil:
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil || len(key) != ed25519.PrivateKeySize {
			// Kunci yang rusak TIDAK diganti diam-diam: mengganti kunci berarti
			// instalasi ini kehilangan identitasnya dan harus diaktifkan ulang
			// oleh manusia. Itu keputusan operator, bukan keputusan library.
			return nil, fmt.Errorf("kunci installation di %s rusak; aktivasi ulang diperlukan", path)
		}
		return ed25519.PrivateKey(key), nil

	case !errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("membaca kunci installation: %w", err)
	}

	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("membangkitkan kunci installation: %w", err)
	}
	if err := writeFileAtomic(path, []byte(base64.StdEncoding.EncodeToString(private)), 0o600); err != nil {
		return nil, fmt.Errorf("menyimpan kunci installation: %w", err)
	}
	return private, nil
}

// publicKeyOf mengembalikan kunci publik dalam base64 baku, bentuk yang
// diharapkan endpoint aktivasi.
func publicKeyOf(key ed25519.PrivateKey) string {
	public, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		// Tidak dapat terjadi: ed25519.PrivateKey.Public selalu Ed25519.
		return ""
	}
	return base64.StdEncoding.EncodeToString(public)
}

// VendorKey adalah kunci publik GONSU yang dipakai memverifikasi lease.
//
// Ditanam di dalam binary produk, bukan dibaca dari konfigurasi. Kunci
// verifikasi yang dapat diganti lewat berkas atau environment variable membuat
// seluruh tanda tangan tidak ada gunanya: siapa pun yang dapat mengubah
// konfigurasi dapat memasang kuncinya sendiri dan menandatangani lease apa pun.
type VendorKey ed25519.PublicKey

// ParseVendorKey membaca kunci publik GONSU dari base64.
func ParseVendorKey(encoded string) (VendorKey, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, fmt.Errorf("kunci vendor bukan base64 yang sah: %w", err)
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("kunci vendor harus %d byte, diterima %d", ed25519.PublicKeySize, len(key))
	}
	return VendorKey(key), nil
}

// MustVendorKey adalah ParseVendorKey yang panic bila kuncinya tidak sah.
//
// Ditujukan untuk konstanta yang ditanam saat build: kunci vendor yang salah
// ketik adalah kesalahan build, dan lebih baik ketahuan pada baris pertama
// daripada pada instalasi pelanggan pertama yang kehilangan jaringan.
func MustVendorKey(encoded string) VendorKey {
	key, err := ParseVendorKey(encoded)
	if err != nil {
		panic(err)
	}
	return key
}

// ParseVendorKeys membaca beberapa kunci publik GONSU sekaligus.
//
// Dipakai produk yang menanam seluruh kunci yang masih dipercaya saat build.
// Satu kunci yang tidak dapat dibaca membuat SELURUH panggilan gagal: kunci
// yang diam-diam dilewati adalah kunci yang tidak ada, dan pada hari rotasi
// itu berarti produk berhenti tanpa ada yang tahu sebabnya.
func ParseVendorKeys(encoded ...string) ([]VendorKey, error) {
	keys := make([]VendorKey, 0, len(encoded))
	for index, item := range encoded {
		key, err := ParseVendorKey(item)
		if err != nil {
			return nil, fmt.Errorf("kunci vendor ke-%d: %w", index+1, err)
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, errors.New("tidak ada kunci vendor yang diberikan")
	}
	return keys, nil
}

// MustVendorKeys sama seperti ParseVendorKeys, tetapi panic bila gagal.
//
// Untuk kunci yang ditanam saat build: kalau nilainya salah, produk memang
// tidak boleh berjalan sama sekali. Gagal saat start jauh lebih baik daripada
// gagal pada pemasangan pelanggan berbulan-bulan kemudian.
func MustVendorKeys(encoded ...string) []VendorKey {
	keys, err := ParseVendorKeys(encoded...)
	if err != nil {
		panic(err)
	}
	return keys
}
