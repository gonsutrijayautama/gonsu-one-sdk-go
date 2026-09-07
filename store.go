package gonsu

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// leaseFile adalah nama berkas cache lease di dalam StateDir.
const leaseFile = "lease.json"

// loadLease membaca lease terakhir yang tersimpan.
//
// Mengembalikan SignedLease kosong bila belum ada, dan itu BUKAN error: sebuah
// instalasi yang baru dipasang memang belum punya lease. Yang error adalah
// berkas yang ada tetapi tidak dapat dibaca.
func loadLease(stateDir string) (SignedLease, error) {
	raw, err := os.ReadFile(filepath.Join(stateDir, leaseFile)) //nolint:gosec // path dari StateDir milik produk sendiri
	if errors.Is(err, fs.ErrNotExist) {
		return SignedLease{}, nil
	}
	if err != nil {
		return SignedLease{}, fmt.Errorf("membaca cache lease: %w", err)
	}

	var signed SignedLease
	if err := json.Unmarshal(raw, &signed); err != nil {
		// Berkas rusak diperlakukan sebagai tidak ada. Aman karena isinya toh
		// harus diverifikasi sebelum dipercaya, dan alternatifnya — menolak
		// start — berarti satu berkas cache yang terpotong cukup untuk
		// menghentikan produksi.
		return SignedLease{}, nil //nolint:nilerr // cache rusak = belum ada lease, bukan kegagalan
	}
	return signed, nil
}

// saveLease menyimpan lease terbaru.
func saveLease(stateDir string, signed SignedLease) error {
	payload, err := json.Marshal(signed)
	if err != nil {
		return fmt.Errorf("menyusun cache lease: %w", err)
	}
	return writeFileAtomic(filepath.Join(stateDir, leaseFile), payload, 0o600)
}

// writeFileAtomic menulis berkas lewat berkas sementara lalu rename.
//
// Rename di dalam satu filesystem bersifat atomik, sehingga pembaca tidak
// pernah menemukan berkas yang separuh tertulis. Menulis langsung ke tujuan
// berarti mati listrik di tengah penulisan meninggalkan lease terpotong — dan
// pada instalasi self-host tidak ada siapa pun yang siap memperbaikinya.
func writeFileAtomic(path string, payload []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("menyiapkan direktori %s: %w", dir, err)
	}

	temporary, err := os.CreateTemp(dir, filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("membuat berkas sementara: %w", err)
	}
	name := temporary.Name()
	defer func() { _ = os.Remove(name) }()

	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("menulis berkas sementara: %w", err)
	}
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("menyetel izin berkas: %w", err)
	}
	// Sync sebelum rename: tanpa itu, rename dapat terlihat sudah selesai
	// sementara isinya belum benar-benar sampai ke disk.
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("menyinkronkan berkas sementara: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("menutup berkas sementara: %w", err)
	}

	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("memindahkan berkas ke %s: %w", path, err)
	}
	return nil
}

// removeLease menghapus cache lease dari disk.
//
// Berkas yang memang tidak ada BUKAN kegagalan: pencopotan harus dapat
// dijalankan dua kali tanpa yang kedua terlihat rusak.
func removeLease(stateDir string) error {
	err := os.Remove(filepath.Join(stateDir, leaseFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
