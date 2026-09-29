package web

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gonsutrijayautama/gonsu-one-sdk-go/auth"
)

// Reason adalah sebab login gagal, untuk Hooks.LoginFailed.
type Reason string

// Sebab login gagal.
const (
	// ReasonNotGranted: orangnya terbukti, tetapi tidak diberi akses di
	// pemasangan ini. Tawarkan masuk dengan akun lain (SwitchAccountPath).
	ReasonNotGranted Reason = "not_granted"
	// ReasonExpired: percobaan login tidak ditemukan atau sudah lewat — dibuka
	// di tab lain, terlalu lama, atau aplikasi baru dimulai ulang.
	ReasonExpired Reason = "expired"
	// ReasonUnreachable: GONSU tidak dapat dihubungi.
	ReasonUnreachable Reason = "unreachable"
	// ReasonNotConfigured: GONSU belum menerbitkan login untuk pemasangan ini.
	ReasonNotConfigured Reason = "not_configured"
	// ReasonRejected: GONSU menolak, atau token yang kembali tidak sah.
	ReasonRejected Reason = "rejected"
)

const (
	loginCookie   = "gonsu_login"
	loginLifetime = 10 * time.Minute
)

// FailLogin menampilkan kegagalan login lewat Hooks.LoginFailed, atau halaman
// bawaan kit. Boleh dipanggil dari StartSession, misalnya bila orangnya
// dicabut di antara pemeriksaan dan pencatatan.
func (k *Kit) FailLogin(w http.ResponseWriter, r *http.Request, reason Reason) {
	if k.hooks.LoginFailed != nil {
		k.hooks.LoginFailed(w, r, reason)
		return
	}
	writeFailurePage(w, reason)
}

// startLogin mengarahkan pengunjung ke GONSU. state, nonce, dan verifier PKCE
// disimpan di server; cookie hanya membawa kunci acaknya.
func (k *Kit) startLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	client, _, err := k.oidc.Client(ctx)
	if err != nil {
		k.logger.Warn("login GONSU belum tersedia", slog.String("error", err.Error()))
		k.FailLogin(w, r, ReasonNotConfigured)
		return
	}
	authorizeURL, pending, err := client.StartLogin(ctx)
	if err != nil {
		k.logger.Warn("GONSU tidak terjangkau saat memulai login", slog.String("error", err.Error()))
		k.FailLogin(w, r, ReasonUnreachable)
		return
	}

	token := rand.Text()
	login := PendingLogin{Auth: pending, Next: localPath(r.URL.Query().Get("next")), ExpiresAt: k.now().Add(loginLifetime)}
	if err := k.pending.Put(ctx, hashToken(token), login); err != nil {
		k.logger.Error("menyimpan percobaan login", slog.String("error", err.Error()))
		http.Error(w, "Login tidak dapat dimulai sekarang. Coba lagi sebentar lagi.", http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: loginCookie, Value: token, Path: "/auth/gonsu/", MaxAge: int(loginLifetime.Seconds()),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, authorizeURL, http.StatusSeeOther)
}

// callback menyelesaikan login: paket auth memverifikasi seluruh bukti, lalu
// orangnya WAJIB ditemukan di tabel pengguna produk. Terbukti login bukan
// berarti berhak masuk.
func (k *Kit) callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()
	http.SetCookie(w, &http.Cookie{Name: loginCookie, Path: "/auth/gonsu/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})

	attempt, found, err := k.takeAttempt(r)
	if err != nil {
		k.logger.Error("membaca percobaan login", slog.String("error", err.Error()))
		http.Error(w, "Login tidak dapat diselesaikan sekarang. Coba lagi.", http.StatusServiceUnavailable)
		return
	}
	switch {
	case !found && query.Get("code") == "" && query.Get("state") == "" && query.Get("error") == "":
		// Balikan sesudah keluar: GONSU mengembalikan pengguna ke alamat yang
		// sama dengan balikan login, tanpa code.
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	case query.Get("error") == "access_denied":
		// Penyedia identitas menolak orang yang tidak termasuk yang boleh masuk
		// ke pemasangan ini.
		k.FailLogin(w, r, ReasonNotGranted)
		return
	case query.Get("error") != "":
		k.logger.Info("GONSU menolak login", slog.String("error", query.Get("error")))
		k.FailLogin(w, r, ReasonRejected)
		return
	case !found:
		k.FailLogin(w, r, ReasonExpired)
		return
	}

	client, _, err := k.oidc.Client(ctx)
	if err != nil {
		k.FailLogin(w, r, ReasonNotConfigured)
		return
	}
	login, err := client.HandleCallback(ctx, attempt.Auth, query.Get("state"), query.Get("code"))
	switch {
	case errors.Is(err, auth.ErrStateMismatch):
		k.logger.Warn("balikan login dengan state yang tidak cocok")
		k.FailLogin(w, r, ReasonExpired)
		return
	case errors.Is(err, auth.ErrInvalidToken):
		k.logger.Warn("id_token GONSU ditolak", slog.String("error", err.Error()))
		k.FailLogin(w, r, ReasonRejected)
		return
	case err != nil:
		k.logger.Warn("menyelesaikan login GONSU", slog.String("error", err.Error()))
		k.FailLogin(w, r, ReasonUnreachable)
		return
	}

	err = auth.EnsureGranted(ctx, login.Claims, k.hooks.Granted)
	if errors.Is(err, auth.ErrNotGranted) {
		created, berr := k.bootstrapOwner(r, login.Claims)
		if berr != nil {
			k.logger.Error("membuat admin pertama", slog.String("error", berr.Error()))
			http.Error(w, "Login tidak dapat diselesaikan sekarang. Coba lagi.", http.StatusInternalServerError)
			return
		}
		if !created {
			k.logger.Info("login GONSU tanpa akses ke pemasangan ini", slog.String("sub", login.Claims.Subject))
			k.FailLogin(w, r, ReasonNotGranted)
			return
		}
		err = nil
	}
	if err != nil {
		k.logger.Error("memeriksa akses", slog.String("error", err.Error()))
		http.Error(w, "Login tidak dapat diselesaikan sekarang. Coba lagi.", http.StatusInternalServerError)
		return
	}

	if err := k.hooks.StartSession(w, r, login, attempt.Next); err != nil {
		k.logger.Error("menerbitkan sesi produk", slog.String("error", err.Error()))
		http.Error(w, "Login tidak dapat diselesaikan sekarang. Coba lagi.", http.StatusInternalServerError)
	}
}

// bootstrapOwner membuka jalan admin pertama HANYA bagi pemilik pemasangan
// menurut GONSU — `sub` yang cocok persis. Pemeriksaan "tabel masih kosong"
// milik produk, di dalam transaksinya.
func (k *Kit) bootstrapOwner(r *http.Request, claims auth.Claims) (bool, error) {
	if k.hooks.BootstrapOwner == nil {
		return false, nil
	}
	_, owner := k.Installation(r.Context())
	if owner == "" || subtle.ConstantTimeCompare([]byte(owner), []byte(claims.Subject)) != 1 {
		return false, nil
	}
	created, err := k.hooks.BootstrapOwner(r.Context(), claims)
	if created && err == nil {
		k.logger.Info("admin pertama pemasangan dibuat dari pemilik GONSU", slog.String("sub", claims.Subject))
	}
	return created, err
}

func (k *Kit) takeAttempt(r *http.Request) (PendingLogin, bool, error) {
	c, err := r.Cookie(loginCookie)
	if errors.Is(err, http.ErrNoCookie) {
		return PendingLogin{}, false, nil
	}
	if err != nil {
		return PendingLogin{}, false, err
	}
	if c.Value == "" {
		return PendingLogin{}, false, nil
	}
	return k.pending.Take(r.Context(), hashToken(c.Value))
}

// account membuka "Akun saya" di GONSU, dengan tombol kembali ke jalur
// `return` di aplikasi ini.
func (k *Kit) account(w http.ResponseWriter, r *http.Request) {
	client, redirect, err := k.oidc.Client(r.Context())
	if err != nil {
		k.FailLogin(w, r, ReasonNotConfigured)
		return
	}
	back := localPath(r.URL.Query().Get("return"))
	if back == "" {
		back = "/"
	}
	// `back` sudah disaring localPath, dan tujuannya selalu Account Center
	// GONSU; Account Center sendiri memeriksa ulang alamat kembalinya.
	http.Redirect(w, r, client.AccountURL(originOf(redirect)+back), http.StatusSeeOther) //nolint:gosec // lihat komentar di atas
}

// forgotPassword membuka halaman lupa sandi milik GONSU. Produk tidak punya
// layar sandi apa pun.
func (k *Kit) forgotPassword(w http.ResponseWriter, r *http.Request) {
	client, _, err := k.oidc.Client(r.Context())
	if err != nil {
		k.FailLogin(w, r, ReasonNotConfigured)
		return
	}
	http.Redirect(w, r, client.ForgotPasswordURL(), http.StatusSeeOther)
}

// switchAccount mengakhiri sesi di GONSU tanpa sesi produk, untuk orang yang
// masuk dengan akun yang tidak diberi akses dan ingin memakai akun lain.
func (k *Kit) switchAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	client, redirect, err := k.oidc.Client(ctx)
	if err != nil {
		k.FailLogin(w, r, ReasonNotConfigured)
		return
	}
	u, err := client.LogoutURL(ctx, "", redirect)
	if err != nil || u == "" {
		k.FailLogin(w, r, ReasonUnreachable)
		return
	}
	http.Redirect(w, r, u, http.StatusSeeOther)
}

// localPath menerima hanya jalur di aplikasi ini: "/orders/", bukan
// "//penyerang.test" atau "https://…" — open redirect sesudah login.
func localPath(p string) string {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.ContainsAny(p, "\\\r\n") {
		return ""
	}
	u, err := url.Parse(p)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return ""
	}
	return p
}

// originOf mengembalikan skema dan host sebuah alamat.
func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// Halaman gagal bawaan
// ---------------------------------------------------------------------------

type failure struct {
	status  int
	title   string
	message string
	switchs bool
}

var failures = map[Reason]failure{
	ReasonNotGranted: {http.StatusForbidden, "Akun ini belum diberi akses",
		"Anda berhasil masuk, tetapi akun ini belum diberi akses ke aplikasi ini. Minta admin memberi akses, atau masuk dengan akun lain.", true},
	ReasonExpired: {http.StatusBadRequest, "Waktu masuk habis",
		"Percobaan masuk ini sudah tidak berlaku. Silakan masuk lagi.", false},
	ReasonUnreachable: {http.StatusServiceUnavailable, "GONSU sedang tidak dapat dihubungi",
		"Masuk belum dapat dilakukan sekarang. Coba lagi sebentar lagi.", false},
	ReasonNotConfigured: {http.StatusServiceUnavailable, "Login belum siap",
		"Login untuk aplikasi ini belum disiapkan. Coba lagi sebentar lagi, atau hubungi admin.", false},
	ReasonRejected: {http.StatusBadRequest, "Masuk gagal",
		"Masuk tidak dapat diselesaikan. Silakan coba lagi.", false},
}

var failureTemplate = template.Must(template.New("gagal").Parse(`<!doctype html>
<html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}}</title>
<style>body{font-family:system-ui,sans-serif;max-width:32rem;margin:15vh auto;padding:0 1rem;line-height:1.5}a{margin-right:1rem}</style>
</head><body>
<h1>{{.Title}}</h1>
<p>{{.Message}}</p>
<p><a href="{{.Login}}">Masuk lagi</a>{{if .Switch}}<a href="{{.SwitchURL}}">Masuk dengan akun lain</a>{{end}}</p>
</body></html>`))

func writeFailurePage(w http.ResponseWriter, reason Reason) {
	f, ok := failures[reason]
	if !ok {
		f = failures[ReasonRejected]
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(f.status)
	_ = failureTemplate.Execute(w, map[string]any{
		"Title": f.title, "Message": f.message, "Login": LoginPath,
		"Switch": f.switchs, "SwitchURL": SwitchAccountPath,
	})
}
