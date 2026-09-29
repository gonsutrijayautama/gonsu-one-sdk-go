package web_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gonsutrijayautama/gonsu-one-sdk-go/auth"
	"github.com/gonsutrijayautama/gonsu-one-sdk-go/web"
)

const (
	clientID = "app_uji_web"
	kid      = "kunci-uji"
)

// provider adalah penyedia identitas tiruan: discovery, JWKS, token, dan
// end_session. Token yang diterbitkannya membawa nonce yang diminta produk,
// seperti penyedia sungguhan.
type provider struct {
	t      *testing.T
	key    *ecdsa.PrivateKey
	server *httptest.Server

	mu      sync.Mutex
	nonce   string
	subject string
}

func newProvider(t *testing.T) *provider {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := &provider{t: t, key: key, subject: "usr_andi"}
	mux := http.NewServeMux()
	mux.HandleFunc("/oidc/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                p.issuer(),
			"authorization_endpoint":                p.server.URL + "/oidc/auth",
			"token_endpoint":                        p.server.URL + "/oidc/token",
			"jwks_uri":                              p.server.URL + "/oidc/jwks",
			"end_session_endpoint":                  p.server.URL + "/oidc/session/end",
			"id_token_signing_alg_values_supported": []string{"ES384"},
			"code_challenge_methods_supported":      []string{"S256"},
		})
	})
	mux.HandleFunc("/oidc/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kty": "EC", "use": "sig", "kid": kid, "alg": "ES384", "crv": "P-384",
			"x": base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 48))),
			"y": base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 48))),
		}}})
	})
	mux.HandleFunc("/oidc/token", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"id_token": p.idToken()})
	})
	p.server = httptest.NewServer(mux)
	t.Cleanup(p.server.Close)
	return p
}

func (p *provider) issuer() string { return p.server.URL + "/oidc" }

func (p *provider) idToken() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	head, _ := json.Marshal(map[string]any{"alg": "ES384", "kid": kid, "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{
		"iss": p.issuer(), "sub": p.subject, "aud": clientID, "nonce": p.nonce,
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		"email": "andi@konveksiku.test", "name": "Andi",
	})
	signing := base64.RawURLEncoding.EncodeToString(head) + "." + base64.RawURLEncoding.EncodeToString(claims)
	sum := sha512.Sum384([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, p.key, sum[:])
	if err != nil {
		p.t.Fatal(err)
	}
	sig := append(r.FillBytes(make([]byte, 48)), s.FillBytes(make([]byte, 48))...)
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// app adalah produk tiruan yang memasang kit.
type app struct {
	t        *testing.T
	kit      *web.Kit
	server   *httptest.Server
	client   *http.Client
	provider *provider

	mu        sync.Mutex
	granted   map[string]bool
	users     int
	sessions  []session
	bootstrap int
}

type session struct {
	subject string
	next    string
}

type appOptions struct {
	owner string
}

func newApp(t *testing.T, p *provider, opts appOptions) *app {
	t.Helper()
	a := &app{t: t, provider: p, granted: map[string]bool{}}
	a.server = httptest.NewUnstartedServer(nil)
	a.server.Start()
	t.Cleanup(a.server.Close)

	env := map[string]string{
		"GONSU_OIDC_ISSUER":       p.issuer(),
		"GONSU_OIDC_CLIENT_ID":    clientID,
		"GONSU_OIDC_REDIRECT_URI": a.server.URL + web.CallbackPath,
		"GONSU_OWNER_SUBJECT":     opts.owner,
	}
	kit, err := web.New(web.Options{
		ProductCode: "garment",
		Getenv:      func(name string) string { return env[name] },
		Hooks: web.Hooks{
			Granted: func(_ context.Context, subject string) (bool, error) {
				a.mu.Lock()
				defer a.mu.Unlock()
				return a.granted[subject], nil
			},
			BootstrapOwner: func(_ context.Context, claims auth.Claims) (bool, error) {
				a.mu.Lock()
				defer a.mu.Unlock()
				a.bootstrap++
				if a.users > 0 {
					return false, nil
				}
				a.granted[claims.Subject], a.users = true, 1
				return true, nil
			},
			StartSession: func(w http.ResponseWriter, r *http.Request, login auth.Login, next string) error {
				a.mu.Lock()
				a.sessions = append(a.sessions, session{subject: login.Claims.Subject, next: next})
				a.mu.Unlock()
				if next == "" {
					next = "/dashboard/"
				}
				http.Redirect(w, r, next, http.StatusSeeOther)
				return nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	a.kit = kit
	a.server.Config.Handler = kit.Handler()

	jar, _ := cookiejar.New(nil)
	a.client = &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	return a
}

// login menjalankan alur sampai balikan, dan mengembalikan jawaban callback.
func (a *app) login(next string) *http.Response {
	a.t.Helper()
	start := a.server.URL + web.LoginPath
	if next != "" {
		start += "?next=" + url.QueryEscape(next)
	}
	resp := a.get(start)
	if resp.StatusCode != http.StatusSeeOther {
		a.t.Fatalf("mulai login: status %d", resp.StatusCode)
	}
	authorize, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || !strings.HasPrefix(authorize.String(), a.provider.server.URL+"/oidc/auth") {
		a.t.Fatalf("login tidak diarahkan ke penyedia identitas: %q", resp.Header.Get("Location"))
	}
	a.provider.mu.Lock()
	a.provider.nonce = authorize.Query().Get("nonce")
	a.provider.mu.Unlock()
	return a.get(a.server.URL + web.CallbackPath + "?code=kode-uji&state=" + url.QueryEscape(authorize.Query().Get("state")))
}

func (a *app) get(address string) *http.Response {
	a.t.Helper()
	resp, err := a.client.Get(address)
	if err != nil {
		a.t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp
}

func TestLogin_OrangYangDiberiAksesMendapatSesi(t *testing.T) {
	a := newApp(t, newProvider(t), appOptions{})
	a.granted["usr_andi"] = true

	resp := a.login("/orders/42?tab=1")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/orders/42?tab=1" {
		t.Fatalf("callback: %d → %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if len(a.sessions) != 1 || a.sessions[0] != (session{"usr_andi", "/orders/42?tab=1"}) {
		t.Errorf("sesi = %+v", a.sessions)
	}
}

func TestLogin_TerbuktiLoginBukanBerartiBerhakMasuk(t *testing.T) {
	a := newApp(t, newProvider(t), appOptions{})

	resp := a.login("")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d, mau 403", resp.StatusCode)
	}
	if len(a.sessions) != 0 {
		t.Errorf("sesi terbit untuk orang yang tidak diberi akses: %+v", a.sessions)
	}
}

// Admin pertama hanya bagi pemilik menurut GONSU, dan hanya selama tabel
// pengguna produk masih kosong.
func TestLogin_PemilikMenjadiAdminPertama(t *testing.T) {
	a := newApp(t, newProvider(t), appOptions{owner: "usr_andi"})

	if resp := a.login(""); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("pemilik pertama: status %d", resp.StatusCode)
	}
	if a.bootstrap != 1 || len(a.sessions) != 1 {
		t.Fatalf("bootstrap=%d sesi=%d", a.bootstrap, len(a.sessions))
	}

	// Pemilik lain, sesudah tabel berisi: produk menolak, kit tidak memberi
	// sesi.
	a.provider.subject = "usr_budi"
	b := newApp(t, a.provider, appOptions{owner: "usr_budi"})
	b.users = 1
	if resp := b.login(""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("pemilik baru ke pemasangan berisi: status %d, mau 403", resp.StatusCode)
	}
}

func TestLogin_BukanPemilikTidakMemanggilBootstrap(t *testing.T) {
	a := newApp(t, newProvider(t), appOptions{owner: "usr_andi_lain"})
	if resp := a.login(""); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d, mau 403", resp.StatusCode)
	}
	if a.bootstrap != 0 {
		t.Errorf("BootstrapOwner dipanggil untuk sub yang bukan pemilik")
	}
}

// `next` yang menunjuk ke luar aplikasi diabaikan: open redirect sesudah login.
func TestLogin_NextKeLuarDiabaikan(t *testing.T) {
	a := newApp(t, newProvider(t), appOptions{})
	a.granted["usr_andi"] = true
	for _, next := range []string{"//penyerang.test/x", "https://penyerang.test/", "/\\penyerang.test", "orders"} {
		a.sessions = nil
		if resp := a.login(next); resp.Header.Get("Location") != "/dashboard/" {
			t.Errorf("next %q diikuti: %q", next, resp.Header.Get("Location"))
		}
	}
}

func TestCallback_TanpaCookieKedaluwarsa(t *testing.T) {
	a := newApp(t, newProvider(t), appOptions{})
	resp := a.get(a.server.URL + web.CallbackPath + "?code=x&state=y")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, mau 400", resp.StatusCode)
	}
}

// Percobaan login hanya dapat diselesaikan sekali.
func TestCallback_TidakDapatDiulang(t *testing.T) {
	a := newApp(t, newProvider(t), appOptions{})
	a.granted["usr_andi"] = true
	start := a.get(a.server.URL + web.LoginPath)
	authorize, _ := url.Parse(start.Header.Get("Location"))
	a.provider.nonce = authorize.Query().Get("nonce")
	callback := a.server.URL + web.CallbackPath + "?code=k&state=" + url.QueryEscape(authorize.Query().Get("state"))
	cookie := a.client.Jar.Cookies(mustURL(t, a.server.URL+"/auth/gonsu/"))

	if resp := a.get(callback); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("pertama: %d", resp.StatusCode)
	}
	a.client.Jar.SetCookies(mustURL(t, a.server.URL+"/auth/gonsu/"), cookie)
	if resp := a.get(callback); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("ulangan: %d, mau 400", resp.StatusCode)
	}
}

func TestCallback_AccessDeniedBerartiBelumDiberiAkses(t *testing.T) {
	a := newApp(t, newProvider(t), appOptions{})
	resp := a.get(a.server.URL + web.CallbackPath + "?error=access_denied&state=x")
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status %d, mau 403", resp.StatusCode)
	}
}

// Sesudah keluar, GONSU mengembalikan pengguna ke alamat balikan tanpa code.
func TestCallback_BalikanSesudahKeluarKeHalamanMuka(t *testing.T) {
	a := newApp(t, newProvider(t), appOptions{})
	resp := a.get(a.server.URL + web.CallbackPath)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Errorf("%d → %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestAccount_KembaliKeJalurDiAplikasiIni(t *testing.T) {
	p := newProvider(t)
	a := newApp(t, p, appOptions{})
	resp := a.get(a.server.URL + web.AccountPath + "?return=" + url.QueryEscape("/settings/users"))
	want := p.server.URL + "/account?redirect=" + url.QueryEscape(a.server.URL+"/settings/users")
	if resp.Header.Get("Location") != want {
		t.Errorf("Location = %q\nmau %q", resp.Header.Get("Location"), want)
	}
	// Alamat kembali ke luar aplikasi diganti halaman muka.
	resp = a.get(a.server.URL + web.AccountPath + "?return=" + url.QueryEscape("https://penyerang.test/"))
	want = p.server.URL + "/account?redirect=" + url.QueryEscape(a.server.URL+"/")
	if resp.Header.Get("Location") != want {
		t.Errorf("Location = %q\nmau %q", resp.Header.Get("Location"), want)
	}
}

func TestLogin_BelumDikonfigurasi(t *testing.T) {
	kit, err := web.New(web.Options{ProductCode: "garment", Getenv: func(string) string { return "" },
		Hooks: web.Hooks{
			Granted:      func(context.Context, string) (bool, error) { return true, nil },
			StartSession: func(http.ResponseWriter, *http.Request, auth.Login, string) error { return nil },
		}})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	kit.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, web.LoginPath, nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status %d, mau 503", rec.Code)
	}
	if _, err := kit.LogoutURL(context.Background(), ""); !errors.Is(err, web.ErrLoginNotConfigured) {
		t.Errorf("LogoutURL tanpa login: %v", err)
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
