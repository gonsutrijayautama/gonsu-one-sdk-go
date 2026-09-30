package gonsu

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// Folder ini dicerminkan ke repository publik, dan cerminannya menolak
// rujukan ke dokumen internal (keputusan arsitektur, PRD, kriteria uji).
// Pemeriksaan yang sama dijalankan di sini supaya ketahuan sebelum merge,
// bukan sesudahnya ketika rilis SDK sudah tertahan.
func TestNoInternalDocumentReferences(t *testing.T) {
	// Kode kriteria uji disusun dari potongan: ditulis utuh, berkas ini
	// sendiri akan ditolak cerminannya.
	pattern := regexp.MustCompile(`ADR-[0-9]{4}|\b[0-9]{2} §[0-9]+|` + "SH" + `-ACC|` + "DEP" + `-ACC`)
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, loc := range pattern.FindAllIndex(raw, -1) {
			t.Errorf("%s: rujukan dokumen internal %q tidak boleh ikut ke repository publik", path, raw[loc[0]:loc[1]])
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
