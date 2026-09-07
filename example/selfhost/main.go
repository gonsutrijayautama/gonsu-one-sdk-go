// Command selfhost adalah contoh produk self-host yang memakai SDK lisensi.
//
// Ia sengaja dibuat sekecil mungkin — tidak melakukan apa pun selain melaporkan
// apa yang boleh dijalankannya — supaya yang terlihat hanya perilaku lisensi:
//
//	go run./example/selfhost activate # sekali, dengan token dari Portal
//	go run./example/selfhost run # jalan terus, heartbeat berkala
//	go run./example/selfhost status # sekali baca, tanpa jaringan
//
// Yang dibuktikan perintah `run`: matikan API GONSU dan produk ini TETAP
// berjalan dari lease di disk sampai masa tenggangnya habis.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	gonsu "github.com/gonsutrijayautama/gonsu-one-sdk-go"
)

// version adalah versi produk yang dilaporkan ke GONSU.
const version = "0.1.0-contoh"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gagal:", err)
		os.Exit(1)
	}
}

func run() error {
	perintah := "status"
	if len(os.Args) > 1 {
		perintah = os.Args[1]
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Di produk sungguhan, kunci vendor DITANAM saat build:
	//
	//	go build -ldflags "-X main.vendorKey=$(cat kunci-publik.txt)"
	//
	// Contoh ini membacanya dari environment karena OpenBao development
	// berjalan in-memory: kuncinya hilang setiap kali container dimulai ulang,
	// sehingga tidak ada nilai tetap yang dapat ditanam di sini.
	// Dipisah koma supaya beberapa kunci dapat dipegang sekaligus selama masa
	// rotasi. Produk sungguhan menanamnya saat build lewat -ldflags, bukan
	// membacanya dari environment — kunci yang dapat diganti pelanggan membuat
	// seluruh tanda tangan tidak ada gunanya.
	vendorKeys, err := gonsu.ParseVendorKeys(strings.Split(os.Getenv("GONSU_VENDOR_KEY"), ",")...)
	if err != nil {
		return fmt.Errorf("GONSU_VENDOR_KEY: %w", err)
	}

	license, err := gonsu.Open(gonsu.Options{
		BaseURL:        wajib("GONSU_BASE_URL"),
		InstallationID: wajib("GONSU_INSTALLATION_ID"),
		StateDir:       nilaiAtau("GONSU_STATE_DIR", "./.state"),
		VendorKeys:     vendorKeys,
		Version:        version,
		Platform:       runtime.GOOS + "/" + runtime.GOARCH,
		Logger:         logger,
	})
	if err != nil {
		return err
	}

	ctx, batal := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer batal()

	switch perintah {
	case "activate":
		token := wajib("GONSU_ACTIVATION_TOKEN")
		if err := license.Activate(ctx, token); err != nil {
			return err
		}
		laporkan(license)
		return nil

	case "status":
		// Sengaja TIDAK menyentuh jaringan. Inilah yang dijalankan produk saat
		// dimulai: ia sudah tahu apa yang boleh dijalankannya sebelum satu paket
		// pun keluar dari mesin.
		laporkan(license)
		return nil

	case "run":
		go license.Run(ctx)

		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for {
			laporkan(license)
			select {
			case <-ctx.Done():
				return nil
			case <-tick.C:
			}
		}

	default:
		return fmt.Errorf("perintah tidak dikenal: %s (activate, run, status)", perintah)
	}
}

// laporkan mencetak keputusan yang akan diambil produk sungguhan.
func laporkan(license *gonsu.License) {
	status := license.Status()

	fmt.Printf("%s %s\n", time.Now().Format(time.RFC3339), status)
	switch {
	case status.Allowed() && status.State == gonsu.StateGrace:
		fmt.Println(" -> MELAYANI, dengan peringatan: platform sudah lama tidak dapat dihubungi")
	case status.Allowed():
		fmt.Println(" -> MELAYANI")
	case status.State == gonsu.StateExpired:
		fmt.Println(" -> BERHENTI: masa tenggang habis")
	case !status.Lease.Granted && status.State != gonsu.StateUnknown:
		fmt.Println(" -> READ-ONLY: langganan sedang tidak memberi hak pakai")
	default:
		fmt.Println(" -> BELUM AKTIF: jalankan `activate` dengan token dari Portal")
	}

	// Fitur dan batas dibaca dari lease yang sama, tanpa memanggil GONSU lagi.
	// Inilah gunanya lease membawa SALINAN hak pakai: produk tidak perlu
	// bertanya kepada siapa pun untuk tahu apa yang boleh dijalankannya.
	if status.State != gonsu.StateUnknown {
		batas, tanpaBatas := status.Limit("users.max")
		if tanpaBatas {
			fmt.Println(" users.max : tanpa batas")
		} else {
			fmt.Printf(" users.max : %d\n", batas)
		}
		fmt.Printf(" backup.enabled : %t\n", status.Feature("backup.enabled"))
	}
}

func wajib(key string) string {
	value := os.Getenv(key)
	if value == "" {
		fmt.Fprintf(os.Stderr, "gagal: %s wajib diisi\n", key)
		os.Exit(1)
	}
	return value
}

func nilaiAtau(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
