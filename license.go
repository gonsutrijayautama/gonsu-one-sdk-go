package gonsu

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"
)

// Options adalah konfigurasi SDK.
type Options struct {
	// BaseURL adalah alamat API GONSU, misalnya https://api.gonsu.cloud.
	BaseURL string
	// InstallationID diberikan GONSU bersama token aktivasi. Bukan rahasia.
	InstallationID string
	// StateDir adalah direktori tempat kunci privat dan cache lease disimpan.
	// Harus bertahan antar restart; kalau tidak, instalasi kehilangan
	// identitasnya setiap kali produk dimulai ulang.
	StateDir string
	// VendorKeys adalah kunci publik GONSU yang DIPERCAYA, ditanam saat build.
	//
	// JAMAK, dan itu bukan kelebihan melainkan keharusan. Kunci penandatangan
	// akan dirotasi suatu hari — terjadwal atau karena insiden. Produk yang
	// hanya memegang satu kunci berhenti memverifikasi apa pun pada detik
	// rotasi, dan sebagian pemasangan berada di server pelanggan yang tidak
	// dapat diperbarui hari itu juga.
	//
	// Cara rotasi yang benar: tanam kunci BARU bersama yang lama, sebarkan
	// produknya, tunggu sampai seluruh pemasangan menerimanya, baru GONSU
	// mulai menandatangani dengan yang baru. Kunci lama dicabut paling akhir.
	//
	// Sebuah lease diterima bila SALAH SATU kunci di sini memverifikasinya.
	// Seluruh isinya kunci GONSU, jadi tidak ada yang melemah karenanya —
	// yang membuktikan tetap tanda tangannya, bukan namanya.
	VendorKeys []VendorKey

	// Version dan Platform dilaporkan apa adanya ke GONSU untuk diagnosis.
	Version  string
	Platform string

	// HTTPClient boleh diisi produk yang harus melewati proxy perusahaan.
	HTTPClient *http.Client
	// Logger boleh nil; bila nil, tidak ada yang dicatat.
	Logger *slog.Logger

	// ClockSkew adalah kelonggaran jam saat menilai kedaluwarsa.
	//
	// Nol berarti DefaultClockSkew, bukan nol sungguhan — jam yang tepat sampai
	// ke detik adalah asumsi yang tidak berlaku di server pelanggan, apalagi
	// yang tidak pernah menyentuh NTP karena memang tidak punya jaringan.
	//
	// Arahnya HANYA memperpanjang, tidak pernah memperpendek. Kesalahan yang
	// mungkin terjadi karena longgar adalah produk melayani beberapa menit
	// lebih lama; kesalahan karena ketat adalah pelanggan yang membayar
	// mendadak berhenti dilayani karena jam servernya maju.
	ClockSkew time.Duration

	// Clock boleh diisi produk untuk menguji perilakunya sendiri saat masa
	// tenggang habis — keadaan yang jika tidak, hanya dapat dicoba dengan
	// menunggu berhari-hari. Nil berarti waktu sebenarnya.
	//
	// Ini BUKAN lubang keamanan yang perlu ditutup: instalasi self-host berjalan
	// di mesin yang dikuasai operatornya, yang juga dapat memundurkan jam sistem
	// atau menambal binary. Lisensi sisi klien tidak pernah tahan terhadap
	// pemiliknya sendiri — yang dijaga tanda tangan adalah agar perubahan tidak
	// dapat dilakukan tanpa meninggalkan jejak, bukan agar tidak mungkin.
	Clock func() time.Time
}

// License adalah pegangan produk terhadap hak pakainya.
//
// Aman dipakai dari banyak goroutine: Status boleh dipanggil sesering apa pun
// dari request handler mana pun.
type License struct {
	options Options
	client  *Client
	logger  *slog.Logger
	now     func() time.Time

	// publicKey adalah kunci publik instalasi ini, base64 baku. Disimpan
	// karena lisensi offline terikat padanya, dan karena instalasi yang belum
	// pernah aktif tetap perlu menyebutkannya saat meminta lisensi.
	publicKey string

	mu     sync.RWMutex
	lease  Lease
	signed SignedLease
	fresh  bool
}

// Open menyiapkan SDK: memuat kunci instalasi dan lease yang tersimpan.
//
// TIDAK menghubungi jaringan. Produk yang dimulai saat GONSU tidak dapat
// dihubungi tetap dapat berjalan dari lease di disk — itulah seluruh gunanya
// lease disimpan.
func Open(options Options) (*License, error) {
	switch {
	case options.BaseURL == "":
		return nil, errors.New("BaseURL wajib diisi")
	case options.InstallationID == "":
		return nil, errors.New("InstallationID wajib diisi")
	case options.StateDir == "":
		return nil, errors.New("StateDir wajib diisi")
	case len(options.VendorKeys) == 0:
		return nil, errors.New("VendorKeys wajib diisi minimal satu kunci")
	}

	if options.Logger == nil {
		options.Logger = slog.New(slog.DiscardHandler)
	}
	if options.Clock == nil {
		options.Clock = time.Now
	}
	if options.ClockSkew <= 0 {
		options.ClockSkew = DefaultClockSkew
	}

	if err := requireTransportSecurity(options.BaseURL); err != nil {
		return nil, err
	}

	key, err := loadOrCreateKeypair(options.StateDir)
	if err != nil {
		return nil, err
	}

	license := &License{
		options:   options,
		client:    NewClient(options.BaseURL, options.InstallationID, key, options.HTTPClient),
		logger:    options.Logger,
		now:       options.Clock,
		publicKey: publicKeyOf(key),
	}

	signed, err := loadLease(options.StateDir)
	if err != nil {
		return nil, err
	}
	if signed.Lease != "" {
		// VerifyOfflineLease, bukan VerifyLease: untuk lease online keduanya
		// sama persis, tetapi lease offline juga diperiksa pengikatannya pada
		// mesin ini. Berkas lisensi offline dikirim GONSU lewat surat atau USB
		// — menyalinnya ke server kedua adalah hal termudah yang dapat
		// dilakukan siapa pun, dan tidak ada heartbeat yang akan menangkapnya.
		lease, err := VerifyOfflineLease(options.VendorKeys, signed, license.publicKey)
		switch {
		case err != nil:
			// Lease yang tidak lolos verifikasi TIDAK dipakai dan TIDAK dihapus.
			// Tidak dipakai karena tidak dapat dipercaya; tidak dihapus karena
			// kalau ia diubah orang, berkasnya adalah barang bukti.
			license.logger.Error("lease tersimpan ditolak dan diabaikan",
				slog.String("alasan", err.Error()),
				slog.String("berkas", options.StateDir+"/"+leaseFile))
		case lease.InstallationID != options.InstallationID:
			// Lease yang sah tetapi milik instalasi lain. Terjadi ketika
			// direktori state disalin dari mesin lain — dan kalau diterima,
			// satu lisensi dapat dipakai berapa pun banyaknya mesin.
			license.logger.Error("lease tersimpan milik instalasi lain dan diabaikan",
				slog.String("lease_installation_id", lease.InstallationID),
				slog.String("installation_id", options.InstallationID))
		default:
			license.lease = lease
			license.signed = signed
		}
	}

	return license, nil
}

// PublicKey mengembalikan kunci publik instalasi ini, base64 baku.
//
// Dibutuhkan untuk MEMINTA lisensi offline: GONSU mengikat lisensinya pada
// kunci ini, dan kuncinya lahir di mesin pelanggan — bukan di GONSU. Yang
// menyeberang hanyalah bagian publiknya.
func (l *License) PublicKey() string { return l.publicKey }

// InstallOffline memasang lisensi offline yang diterima dari GONSU.
//
// TIDAK menghubungi jaringan sama sekali, dan memang itu seluruh gunanya
// Yang diperiksa sebelum disimpan: tanda tangan GONSU,
// bahwa lease menyebut instalasi ini, dan bahwa ia terikat pada kunci mesin
// ini. Berkas yang gagal salah satunya TIDAK disimpan — lisensi yang ditolak
// dan tetap tertulis ke disk hanya akan membingungkan pemeriksaan berikutnya.
func (l *License) InstallOffline(signed SignedLease) error {
	lease, err := VerifyOfflineLease(l.options.VendorKeys, signed, l.publicKey)
	if err != nil {
		return err
	}
	if lease.InstallationID != l.options.InstallationID {
		return fmt.Errorf("%w: lisensi untuk instalasi %s, mesin ini %s",
			ErrLeaseBukanUntukMesinIni, lease.InstallationID, l.options.InstallationID)
	}
	if err := saveLease(l.options.StateDir, signed); err != nil {
		return err
	}

	l.mu.Lock()
	l.lease = lease
	l.signed = signed
	// fresh TETAP false. Lease offline memang tidak pernah disegarkan, dan
	// mengakuinya "segar" akan membuat status berbohong tentang sesuatu yang
	// tidak pernah terjadi.
	l.mu.Unlock()

	l.logger.Info("lisensi offline dipasang",
		slog.String("installation_id", lease.InstallationID),
		slog.Time("berlaku_sampai", lease.ExpiresAt))
	return nil
}

// Activate mendaftarkan instalasi ini dengan token aktivasi dari Portal.
//
// Dipanggil sekali seumur instalasi. Memanggilnya ulang akan ditolak GONSU:
// tokennya sekali pakai.
func (l *License) Activate(ctx context.Context, token string) error {
	response, err := l.client.Activate(ctx, token, l.options.Version, l.options.Platform)
	if err != nil {
		return err
	}
	l.adopt(response)
	l.logger.Info("instalasi aktif",
		slog.String("installation_id", response.Installation.ID),
		slog.String("product_code", response.Application.ProductCode))
	return nil
}

// Deactivate melepaskan pemasangan ini di GONSU, lalu membuang lease lokalnya.
//
// Dipanggil saat produk dicopot. Tanpa ini, pemasangan yang sudah tidak ada
// tetap terhitung aktif — dan pada produk yang dijual per pemasangan, itu
// berarti pelanggan membayar sesuatu yang sudah ia hapus.
//
// Lease lokal dibuang MESKIPUN GONSU tidak dapat dihubungi. Yang diputuskan
// pelanggan adalah mencopot; jaringan yang sedang putus tidak membatalkannya,
// dan meninggalkan lease yang masih berlaku di disk mesin yang sudah dicopot
// hanya menyisakan berkas yang dapat dipakai orang lain.
func (l *License) Deactivate(ctx context.Context) error {
	err := l.client.Deactivate(ctx)

	l.mu.Lock()
	l.lease = Lease{}
	l.signed = SignedLease{}
	l.fresh = false
	l.mu.Unlock()

	if hapus := removeLease(l.options.StateDir); hapus != nil {
		l.logger.Warn("lease lokal tidak dapat dihapus",
			slog.String("alasan", hapus.Error()))
	}

	if err != nil {
		l.logger.Warn("GONSU tidak dapat diberi tahu tentang pencopotan ini",
			slog.String("alasan", err.Error()))
		return err
	}
	l.logger.Info("pemasangan dilepaskan di GONSU")
	return nil
}

// Refresh mengambil lease terbaru dari GONSU.
//
// Kegagalan TIDAK membatalkan lease yang sudah dipegang. Jaringan yang putus
// bukan pencabutan lisensi, dan memperlakukannya begitu berarti gangguan lima
// menit di sisi GONSU menghentikan setiap pelanggan sekaligus.
func (l *License) Refresh(ctx context.Context) error {
	response, err := l.client.Heartbeat(ctx, l.options.Version, l.options.Platform)
	if err != nil {
		l.mu.Lock()
		l.fresh = false
		l.mu.Unlock()
		return err
	}
	l.adopt(response)
	return nil
}

// adopt memasang lease dari sebuah jawaban dan menyimpannya ke disk.
func (l *License) adopt(response Response) {
	if response.Lease == nil {
		// Platform tanpa penandatangan. Instalasi tetap berjalan selama masih
		// terhubung, tetapi tidak ada yang dapat disimpan untuk saat terputus.
		l.logger.Warn("GONSU tidak menyertakan lease bertanda tangan; " +
			"instalasi ini tidak akan dapat berjalan saat terputus dari platform")
		return
	}

	lease, err := VerifyLease(l.options.VendorKeys, *response.Lease)
	if err != nil {
		// Lease yang baru diterima pun diverifikasi. Kalau gagal, yang menjawab
		// di alamat itu bukan GONSU — atau sesuatu di tengah jalan mengubahnya.
		l.logger.Error("lease dari GONSU ditolak", slog.String("alasan", err.Error()))
		return
	}
	if lease.InstallationID != l.options.InstallationID {
		l.logger.Error("lease dari GONSU milik instalasi lain",
			slog.String("lease_installation_id", lease.InstallationID))
		return
	}

	l.mu.Lock()
	l.lease = lease
	l.signed = *response.Lease
	l.fresh = true
	l.mu.Unlock()

	if err := saveLease(l.options.StateDir, *response.Lease); err != nil {
		// Gagal menyimpan bukan alasan menolak lease yang sudah sah: ia tetap
		// berlaku untuk process yang sedang berjalan. Yang hilang hanya
		// kemampuan bertahan setelah restart.
		l.logger.Error("lease tidak dapat disimpan ke disk", slog.String("alasan", err.Error()))
	}
}

// CheckUpdate menanyakan rilis mana yang boleh dipasang instalasi ini.
//
// TIDAK memasangnya. Memasang berarti menghentikan dan menjalankan ulang
// container di server pelanggan, dan itu menuntut hak yang jauh melampaui apa
// yang pantas dimiliki sebuah library lisensi.
func (l *License) CheckUpdate(ctx context.Context) (UpdateOffer, error) {
	return l.client.CheckUpdate(ctx, l.options.Version)
}

// RegistryCredential meminta kredensial untuk menarik image produk.
func (l *License) RegistryCredential(ctx context.Context) (RegistryCredential, error) {
	return l.client.RegistryCredential(ctx)
}

// Status mengembalikan keadaan hak pakai saat ini.
func (l *License) Status() Status {
	l.mu.RLock()
	defer l.mu.RUnlock()

	status := StatusAt(l.lease, l.now().UTC(), l.options.ClockSkew)
	status.Fresh = l.fresh
	return status
}

// Batas backoff ketika heartbeat gagal.
const (
	// minRetryInterval adalah jeda percobaan ulang pertama. Cukup pendek untuk
	// pulih cepat dari gangguan sesaat, cukup panjang untuk tidak ikut
	// menghantam GONSU yang sedang bermasalah.
	minRetryInterval = 30 * time.Second
	// heartbeatJitter adalah pengacakan irama, sebagai pecahan dari interval.
	//
	// Tanpa ini, seluruh instalasi yang dipasang dari satu rilis akan menyapa
	// pada detik yang sama setiap kali — dan yang paling mungkin membuat GONSU
	// tidak dapat dihubungi justru instalasinya sendiri.
	heartbeatJitter = 0.1
)

// Run menjaga lease tetap segar sampai ctx selesai.
//
// Memblokir; produk menjalankannya di goroutine sendiri. Satu heartbeat
// dilakukan segera saat dipanggil, supaya instalasi yang baru dinyalakan tidak
// menunggu satu interval penuh hanya untuk mengetahui lisensinya sudah dicabut.
func (l *License) Run(ctx context.Context) {
	failures := 0

	for {
		err := l.Refresh(ctx)
		switch {
		case err == nil:
			failures = 0
			status := l.Status()
			l.logger.Debug("lease diperbarui",
				slog.String("state", string(status.State)),
				slog.Bool("granted", status.Lease.Granted),
				slog.Time("expires_at", status.Lease.ExpiresAt))

		case ctx.Err() != nil:
			return

		case IsUnauthorized(err):
			// Ditolak, bukan tidak terjangkau. Mencoba lagi lebih cepat tidak
			// akan mengubah jawabannya, dan lease yang dipegang akan habis
			// dengan sendirinya bila pencabutannya memang benar.
			failures++
			l.logger.Error("GONSU menolak heartbeat", slog.String("alasan", err.Error()))

		default:
			failures++
			l.logger.Warn("heartbeat gagal; lease tersimpan tetap dipakai",
				slog.String("alasan", err.Error()),
				slog.String("state", string(l.Status().State)))
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(l.nextInterval(failures)):
		}
	}
}

// nextInterval menghitung jeda sebelum heartbeat berikutnya.
func (l *License) nextInterval(failures int) time.Duration {
	l.mu.RLock()
	interval := l.lease.heartbeatInterval(15 * time.Minute)
	l.mu.RUnlock()

	if failures > 0 {
		// Backoff eksponensial, tetapi TIDAK pernah lebih lambat daripada irama
		// normal: instalasi yang sedang gagal justru yang paling perlu segera
		// tahu keadaan sebenarnya.
		retry := minRetryInterval << min(failures-1, 5)
		interval = min(retry, interval)
	}

	spread := float64(interval) * heartbeatJitter
	// Acak lemah memang yang dibutuhkan: yang dicegah jitter adalah instalasi
	// menyapa serempak, bukan seseorang menebak kapan giliran berikutnya.
	return interval + time.Duration((rand.Float64()*2-1)*spread) //nolint:gosec // jitter penjadwalan, bukan nilai keamanan
}

// String membuat status enak dibaca di log dan halaman diagnostik.
func (s Status) String() string {
	if s.State == StateUnknown {
		return "belum ada lease"
	}
	return fmt.Sprintf("%s, granted=%t, paket=%s, berlaku sampai %s, tenggang sampai %s",
		s.State, s.Lease.Granted, s.Lease.PlanCode,
		s.Lease.ExpiresAt.Format(time.RFC3339), s.Lease.GraceUntil.Format(time.RFC3339))
}
