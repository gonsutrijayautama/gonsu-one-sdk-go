package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gonsutrijayautama/gonsu-one-sdk-go/auth"
)

// Jalur login milik GONSU. GONSU mendaftarkan redirect_uri pemasangan ke
// CallbackPath, dan tombol "Buka aplikasi" di Portal menunjuk LoginPath.
// Keduanya di bawah /auth/gonsu/ supaya tidak bertabrakan dengan jalur produk.
const (
	LoginPath          = "/auth/gonsu/login"
	CallbackPath       = "/auth/gonsu/callback"
	AccountPath        = "/auth/gonsu/account"
	ForgotPasswordPath = "/auth/gonsu/forgot-password" //nolint:gosec // jalur halaman, bukan kredensial
	SwitchAccountPath  = "/auth/gonsu/switch-account"
)

// ErrLoginNotConfigured berarti GONSU belum menerbitkan login untuk pemasangan
// ini: Secret tidak membawa GONSU_OIDC_*, atau agent belum dapat menjawab
// /v1/oidc. Keadaan sah — pemasangan yang baru dibuat melewatinya.
var ErrLoginNotConfigured = errors.New("login GONSU belum dikonfigurasi untuk pemasangan ini")

// agentOIDC adalah jawaban agent GET /v1/oidc — tanpa client_secret, dan memang
// tidak pernah ada: self-host memakai client publik dengan PKCE.
type agentOIDC struct {
	Issuer      string `json:"issuer"`
	ClientID    string `json:"client_id"`
	RedirectURI string `json:"redirect_uri"`
}

// agentOIDCRefresh: konfigurasi login jarang berubah, tetapi perubahannya —
// rotasi client — harus sampai tanpa restart.
const agentOIDCRefresh = 10 * time.Minute

// oidcSource menyiapkan client auth dari environment (cloud) atau agent
// (self-host). Tidak menghubungi siapa pun sampai login pertama.
type oidcSource struct {
	env    environment
	http   *http.Client
	logger *slog.Logger

	mu        sync.Mutex
	client    *auth.Client
	redirect  string
	current   agentOIDC
	fetchedAt time.Time
}

func newOIDCSource(env environment, httpClient *http.Client, logger *slog.Logger) (*oidcSource, error) {
	o := &oidcSource{env: env, http: httpClient, logger: logger}
	if env.issuer != "" {
		client, err := o.build(agentOIDC{Issuer: env.issuer, ClientID: env.clientID, RedirectURI: env.redirectURI})
		if err != nil {
			return nil, err
		}
		o.client, o.redirect = client, env.redirectURI
		o.warnCallbackPath(env.redirectURI)
	}
	return o, nil
}

func (o *oidcSource) build(c agentOIDC) (*auth.Client, error) {
	return auth.New(auth.Options{
		Issuer:          c.Issuer,
		ClientID:        c.ClientID,
		ClientSecret:    o.env.clientSecret,
		RedirectURI:     c.RedirectURI,
		RecheckInterval: o.env.recheck,
		OfflineGrace:    o.env.offlineGrace,
		HTTPClient:      o.http,
	})
}

// warnCallbackPath: redirect uri yang tidak menunjuk CallbackPath membuat
// balikan login mendarat di halaman yang tidak ada — penyedia identitas tidak
// akan menyebutkannya.
func (o *oidcSource) warnCallbackPath(redirect string) {
	if u, err := url.Parse(redirect); err == nil && u.Path != CallbackPath {
		o.logger.Warn("redirect_uri dari GONSU tidak menunjuk jalur balikan kit",
			slog.String("redirect_uri", redirect), slog.String("seharusnya_path", CallbackPath))
	}
}

// Client mengembalikan client auth beserta redirect uri-nya.
func (o *oidcSource) Client(ctx context.Context) (*auth.Client, string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.env.mode == ModeCloud {
		if o.client == nil {
			return nil, "", ErrLoginNotConfigured
		}
		return o.client, o.redirect, nil
	}
	if o.client != nil && time.Since(o.fetchedAt) < agentOIDCRefresh {
		return o.client, o.redirect, nil
	}

	c, err := o.fetchAgent(ctx)
	if err != nil {
		if o.client != nil {
			// Agent sesaat tidak menjawab; konfigurasi terakhir tetap sah.
			return o.client, o.redirect, nil
		}
		return nil, "", err
	}
	o.fetchedAt = time.Now()
	if o.client != nil && c == o.current {
		return o.client, o.redirect, nil
	}
	client, err := o.build(c)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrLoginNotConfigured, err)
	}
	o.client, o.redirect, o.current = client, c.RedirectURI, c
	o.warnCallbackPath(c.RedirectURI)
	return client, c.RedirectURI, nil
}

func (o *oidcSource) fetchAgent(ctx context.Context) (agentOIDC, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.env.agentOIDCURL, nil)
	if err != nil {
		return agentOIDC{}, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := o.http.Do(req)
	if err != nil {
		return agentOIDC{}, fmt.Errorf("%w: agent tidak terjangkau: %w", ErrLoginNotConfigured, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return agentOIDC{}, err
	}
	if resp.StatusCode != http.StatusOK {
		// 503: GONSU belum menerbitkan login, atau agent belum sempat menyapa
		// GONSU sejak start. Keduanya sembuh sendiri.
		return agentOIDC{}, fmt.Errorf("%w: agent menjawab %d", ErrLoginNotConfigured, resp.StatusCode)
	}
	var c agentOIDC
	if err := json.Unmarshal(body, &c); err != nil {
		return agentOIDC{}, fmt.Errorf("jawaban /v1/oidc agent tidak dapat dibaca: %w", err)
	}
	return c, nil
}

// offlineGrace adalah masa tenggang sesi saat GONSU tak terjangkau.
func (o *oidcSource) offlineGrace() time.Duration {
	if o.env.offlineGrace > 0 {
		return o.env.offlineGrace
	}
	return auth.DefaultOfflineGrace
}

// Verify memutuskan apakah sesi GONSU boleh dilanjutkan.
//
// Bila client-nya sendiri tidak dapat disiapkan — login dicabut dari
// konfigurasi, atau agent tidak menjawab sejak start — keadaannya sama dengan
// GONSU tak terjangkau: sesi bertahan selama masa tenggang, lalu berakhir.
func (o *oidcSource) Verify(ctx context.Context, state auth.SessionState) (auth.SessionState, error) {
	client, _, err := o.Client(ctx)
	if err != nil {
		grace := o.offlineGrace()
		if time.Since(state.LastChecked) <= grace {
			return state, nil
		}
		return state, fmt.Errorf("%w: login GONSU tidak tersedia melewati masa tenggang %s",
			auth.ErrSessionExpired, grace)
	}
	return client.VerifySession(ctx, state)
}
