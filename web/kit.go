package web

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	gonsu "github.com/gonsutrijayautama/gonsu-one-sdk-go"
	"github.com/gonsutrijayautama/gonsu-one-sdk-go/auth"
)

// Hooks adalah bagian yang hanya dapat dijawab produk.
type Hooks struct {
	// Granted menjawab apakah `subject` diberi akses di pemasangan ini: ada di
	// tabel pengguna produk dan aktif. WAJIB.
	//
	// Jangan pernah membuat pengguna di sini. Pengguna lahir dari layar "beri
	// akses login" produk, bukan dari login pertama: membuatnya dari `sub` yang
	// tidak dikenal berarti orang dari pemasangan lain dibuatkan akun alih-alih
	// ditolak.
	Granted func(ctx context.Context, subject string) (bool, error)

	// BootstrapOwner membuat admin pertama dari pemilik bisnis. Opsional.
	//
	// Kit memanggilnya HANYA bila Granted menjawab tidak dan `sub` orang itu
	// sama persis dengan pemilik pemasangan menurut GONSU. Produk WAJIB
	// menolak (false) bila tabel penggunanya sudah berisi siapa pun — diperiksa
	// di dalam transaksi yang sama dengan pembuatannya — supaya pemilik baru
	// tidak dapat menyuntikkan diri ke pemasangan yang sudah berjalan.
	BootstrapOwner func(ctx context.Context, claims auth.Claims) (created bool, err error)

	// StartSession menerbitkan sesi produk untuk login yang lolos, lalu
	// menulis jawabannya — biasanya redirect ke `next`, atau ke halaman awal
	// bila `next` kosong. WAJIB.
	//
	// Simpan login.Session bersama sesi produk (untuk VerifySession) dan
	// login.IDToken (untuk LogoutURL). `next` sudah diperiksa kit: hanya jalur
	// di aplikasi ini.
	StartSession func(w http.ResponseWriter, r *http.Request, login auth.Login, next string) error

	// LoginFailed menampilkan kegagalan login. Opsional; bawaannya halaman
	// sederhana dengan tautan mencoba lagi.
	LoginFailed func(w http.ResponseWriter, r *http.Request, reason Reason)
}

// Options adalah yang ditulis produk di kodenya sendiri, bukan konfigurasi.
type Options struct {
	// ProductCode adalah kode produk di katalog GONSU, misalnya "garment".
	// WAJIB: lease yang menyebut produk lain ditolak.
	ProductCode string
	// Version dilaporkan ke GONSU untuk diagnosis.
	Version string
	// VendorKeys adalah kunci publik GONSU yang ditanam saat build. Opsional:
	// di cloud GONSU menyerahkannya lewat GONSU_LICENSE_PUBLIC_KEYS. Yang
	// ditanam didahulukan.
	VendorKeys []gonsu.VendorKey

	Hooks Hooks

	// Pending menyimpan login yang sedang berjalan. Nil berarti di memori —
	// cukup untuk satu replica.
	Pending PendingStore
	// Logger boleh nil; bila nil, tidak ada yang dicatat.
	Logger *slog.Logger
	// HTTPClient untuk memanggil GONSU dan agent. Nil berarti bawaan kit.
	HTTPClient *http.Client
	// Getenv membaca environment. Nil berarti os.Getenv; diisi test.
	Getenv func(string) string
}

// Kit adalah pegangan produk terhadap GONSU. Aman dipakai dari banyak
// goroutine.
type Kit struct {
	env         environment
	productCode string
	hooks       Hooks
	pending     PendingStore
	logger      *slog.Logger
	oidc        *oidcSource
	license     *License
	lease       *leaseLicense
	identities  *Identities
	now         func() time.Time
}

// New membaca environment dan menyiapkan kit. Tidak menghubungi GONSU maupun
// agent: aplikasi tetap start walau keduanya belum siap.
func New(options Options) (*Kit, error) {
	var errs []error
	if strings.TrimSpace(options.ProductCode) == "" {
		errs = append(errs, errors.New("web: Options.ProductCode wajib diisi"))
	}
	if options.Hooks.Granted == nil {
		errs = append(errs, errors.New("web: Hooks.Granted wajib diisi"))
	}
	if options.Hooks.StartSession == nil {
		errs = append(errs, errors.New("web: Hooks.StartSession wajib diisi"))
	}
	getenv := options.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	env, err := readEnvironment(getenv)
	if err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	logger := options.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	client := options.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	pending := options.Pending
	if pending == nil {
		pending = newMemoryPending()
	}

	k := &Kit{
		env:         env,
		productCode: strings.TrimSpace(options.ProductCode),
		hooks:       options.Hooks,
		pending:     pending,
		logger:      logger,
		identities:  &Identities{url: env.identitiesURL(), token: env.identityToken, http: client},
		now:         time.Now,
	}

	if k.oidc, err = newOIDCSource(env, client, logger); err != nil {
		return nil, fmt.Errorf("web: konfigurasi login GONSU: %w", err)
	}

	k.license = &License{mode: env.mode}
	switch {
	case env.mode == ModeSelfHost:
		agentClient := *client
		agentClient.Timeout = agentTimeout
		k.license.agent = newAgentLicense(env.agentLicenseURL, &agentClient, logger)
	case env.leaseConfigured():
		k.lease = k.openLease(options, client)
		k.license.lease = k.lease
	}
	return k, nil
}

// openLease menyiapkan lisensi cloud. Kegagalannya tidak menghentikan
// aplikasi: di cloud, lisensi hanya membawa pembeda paket, dan aplikasi tanpa
// pembeda paket lebih berguna daripada aplikasi yang tidak start.
func (k *Kit) openLease(options Options, client *http.Client) *leaseLicense {
	keys := options.VendorKeys
	if len(keys) == 0 && len(k.env.publicKeys) > 0 {
		parsed, err := gonsu.ParseVendorKeys(k.env.publicKeys...)
		if err != nil {
			k.logger.Error("GONSU_LICENSE_PUBLIC_KEYS tidak dapat dibaca; hak pakai tidak dibedakan",
				slog.String("error", err.Error()))
			return nil
		}
		keys = parsed
	}
	if len(keys) == 0 {
		k.logger.Warn("kunci publik GONSU tidak ada; hak pakai cloud tidak dibedakan sampai GONSU menyerahkannya")
		return nil
	}
	license, err := gonsu.Open(gonsu.Options{
		BaseURL:        k.env.baseURL,
		InstallationID: k.env.installationID,
		ProductCode:    options.ProductCode,
		StateDir:       k.env.stateDir,
		VendorKeys:     keys,
		Version:        options.Version,
		Platform:       runtime.GOOS + "/" + runtime.GOARCH,
		HTTPClient:     client,
		Logger:         k.logger,
	})
	if err != nil {
		k.logger.Error("lisensi cloud tidak dapat disiapkan; hak pakai tidak dibedakan",
			slog.String("error", err.Error()))
		return nil
	}
	return &leaseLicense{license: license, activationToken: k.env.activationToken,
		logger: k.logger, missing: map[string]bool{}}
}

// Mode melaporkan mode pemasangan.
func (k *Kit) Mode() Mode { return k.env.mode }

// Run menjaga lisensi cloud tetap segar — aktivasi pertama, lalu heartbeat —
// sampai ctx selesai. Memblokir; jalankan di goroutine sendiri. Di self-host
// agent yang mengerjakannya, dan Run hanya menunggu ctx.
func (k *Kit) Run(ctx context.Context) {
	if k.lease != nil {
		k.lease.run(ctx)
		return
	}
	<-ctx.Done()
}

// License menjawab hak pakai pemasangan ini.
func (k *Kit) License() *License { return k.license }

// Identities meminta akun GONSU untuk layar "beri akses login".
func (k *Kit) Identities() *Identities { return k.identities }

// Installation mengembalikan organization pemasangan dan `sub` pemiliknya
// menurut GONSU. Kosong bila belum diserahkan — keadaan sah.
func (k *Kit) Installation(ctx context.Context) (organizationID, ownerSubject string) {
	if k.license.agent != nil {
		return k.license.agent.installation(ctx)
	}
	return k.env.organizationID, k.env.ownerSubject
}

// VerifySession memutuskan apakah sesi GONSU seseorang boleh dilanjutkan.
//
// Panggil pada request yang masuk; ia hanya menyentuh jaringan ketika sudah
// waktunya memeriksa ulang. auth.ErrSessionExpired berarti sesi produk harus
// dimatikan. SIMPAN state yang dikembalikan: refresh token dapat dirotasi.
func (k *Kit) VerifySession(ctx context.Context, state auth.SessionState) (auth.SessionState, error) {
	return k.oidc.Verify(ctx, state)
}

// LogoutURL adalah alamat keluar di GONSU, dipakai SESUDAH produk mematikan
// sesinya sendiri. Sesudah keluar, GONSU mengembalikan pengguna ke halaman
// muka aplikasi.
func (k *Kit) LogoutURL(ctx context.Context, idToken string) (string, error) {
	client, redirect, err := k.oidc.Client(ctx)
	if err != nil {
		return "", err
	}
	return client.LogoutURL(ctx, idToken, redirect)
}

// Handler melayani jalur login milik GONSU di bawah /auth/gonsu/. Pasang
// apa adanya, tanpa memotong awalan jalurnya:
//
//	mux.Handle("/auth/gonsu/", kit.Handler())
func (k *Kit) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+LoginPath, k.startLogin)
	mux.HandleFunc("GET "+CallbackPath, k.callback)
	mux.HandleFunc("GET "+AccountPath, k.account)
	mux.HandleFunc("GET "+ForgotPasswordPath, k.forgotPassword)
	mux.HandleFunc("GET "+SwitchAccountPath, k.switchAccount)
	mux.HandleFunc("GET "+PortalSubscriptionPath, k.portal(PortalSubscription))
	mux.HandleFunc("GET "+PortalInvoicesPath, k.portal(PortalInvoices))
	mux.HandleFunc("GET "+PortalPlansPath, k.portal(PortalPlans))
	return mux
}
