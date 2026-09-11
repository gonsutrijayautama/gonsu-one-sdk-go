package gonsu

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Jalur endpoint lisensi GONSU.
const (
	pathActivate  = "/license/v1/activate"
	pathHeartbeat = "/license/v1/heartbeat"
	// pathDeactivate dipanggil sekali, saat produk dicopot.
	pathDeactivate = "/license/v1/deactivate"
)

// maxResponseBody membatasi jawaban yang dibaca dari server.
//
// Klien ini berjalan di dalam produk pelanggan dan tidak boleh dapat dipaksa
// menghabiskan memori oleh apa pun yang menjawab di alamat itu — termasuk oleh
// sesuatu yang bukan GONSU.
const maxResponseBody = 1 << 20

// Person adalah orang yang disebut GONSU, biasanya pemilik organisasi.
//
// Yang disebut adalah ORANGNYA, bukan perannya: produk sendiri yang memutuskan
// orang ini menjadi apa di dalamnya.
type Person struct {
	Subject     string `json:"subject"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
}

// Response adalah jawaban aktivasi maupun heartbeat.
type Response struct {
	Installation struct {
		ID            string `json:"id"`
		ApplicationID string `json:"application_id"`
		Status        string `json:"status"`
	} `json:"installation"`
	OrganizationID string `json:"organization_id"`
	Application    struct {
		Slug        string `json:"slug"`
		ProductCode string `json:"product_code"`
	} `json:"application"`
	// Lease nil berarti platform belum memiliki penandatangan. Instalasi tetap
	// dilayani selama masih terhubung, tetapi tidak dapat bertahan saat
	// terputus — dan produk mengetahuinya dari ketiadaan field ini, bukan dari
	// lease yang tidak dapat diverifikasi.
	Lease *SignedLease `json:"lease"`
	Owner *Person      `json:"owner"`
	// OIDC nil berarti login produk belum diterbitkan untuk pemasangan ini.
	//
	// Tidak memuat `client_secret`, dan itu bukan kelalaian: pemasangan
	// self-host memakai client PUBLIK dengan PKCE. Rahasia yang ditaruh di
	// mesin yang administratornya pelanggan sendiri tidak melindungi apa pun
	// dari pemilik mesin itu, sedangkan PKCE menutup kasus yang tersisa.
	OIDC *OIDCConfig `json:"oidc"`
}

// OIDCConfig adalah nilai yang dibutuhkan produk untuk memulai login.
//
// Ketiganya BUKAN rahasia. `client_id` bahkan terlihat di address bar setiap
// kali orang login, dan `redirect_uri` adalah alamat produk itu sendiri.
type OIDCConfig struct {
	// Issuer adalah penerbit token. Produk WAJIB mencocokkannya dengan klaim
	// `iss` pada id_token — kalau tidak, token dari penerbit lain akan lolos.
	Issuer string `json:"issuer"`
	// ClientID dipakai menyusun URL authorize.
	ClientID string `json:"client_id"`
	// RedirectURI diserahkan supaya produk tidak menebaknya sendiri. Produk
	// yang menebak akan menebak berbeda dari yang terdaftar, dan penyedia
	// identitas menolaknya tanpa menyebut nilai mana yang ia harapkan.
	RedirectURI string `json:"redirect_uri"`
}

// APIError adalah penolakan dari GONSU beserta kodenya.
//
// Kode dipisahkan dari pesan karena hanya kode yang boleh dijadikan pegangan
// program; pesannya ditulis untuk manusia dan dapat berubah kapan saja.
type APIError struct {
	Status    int
	Code      string
	Message   string
	RequestID string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("GONSU menolak (%d %s): %s", e.Status, e.Code, e.Message)
}

// Client memanggil endpoint lisensi GONSU.
//
// Untuk pemakaian biasa di dalam produk, gunakan Open — yang membungkus client
// ini bersama cache di disk dan penghitungan status. Client dipakai langsung
// hanya ketika produk ingin mengatur sendiri kapan memanggil.
type Client struct {
	baseURL        string
	installationID string
	key            ed25519.PrivateKey
	http           *http.Client
}

// NewClient membuat client.
func NewClient(baseURL, installationID string, key ed25519.PrivateKey, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &Client{
		baseURL:        strings.TrimRight(baseURL, "/"),
		installationID: installationID,
		key:            key,
		http:           httpClient,
	}
}

// activateRequest adalah body aktivasi.
type activateRequest struct {
	InstallationID  string `json:"installation_id"`
	ActivationToken string `json:"activation_token"`
	PublicKey       string `json:"public_key"`
	Version         string `json:"version"`
	Platform        string `json:"platform"`
}

// Activate mendaftarkan kunci publik instalasi ini.
//
// TIDAK bertanda tangan — kuncinya memang baru didaftarkan di sini. Yang
// menggantikannya adalah token aktivasi sekali pakai berumur pendek, yang
// diambil operator dari Portal.
func (c *Client) Activate(ctx context.Context, token, version, platform string) (Response, error) {
	body, err := json.Marshal(activateRequest{
		InstallationID:  c.installationID,
		ActivationToken: token,
		PublicKey:       publicKeyOf(c.key),
		Version:         version,
		Platform:        platform,
	})
	if err != nil {
		return Response{}, fmt.Errorf("menyusun permintaan aktivasi: %w", err)
	}
	return c.do(ctx, pathActivate, body, false)
}

// heartbeatRequest adalah body heartbeat.
type heartbeatRequest struct {
	Version  string `json:"version"`
	Platform string `json:"platform"`
}

// Heartbeat melaporkan instalasi masih hidup dan mengambil lease terbaru.
func (c *Client) Heartbeat(ctx context.Context, version, platform string) (Response, error) {
	body, err := json.Marshal(heartbeatRequest{Version: version, Platform: platform})
	if err != nil {
		return Response{}, fmt.Errorf("menyusun heartbeat: %w", err)
	}
	return c.do(ctx, pathHeartbeat, body, true)
}

// Deactivate memberi tahu GONSU bahwa pemasangan ini dicopot.
//
// Bertanda tangan seperti heartbeat: hanya pemegang kunci privat pemasangan
// yang boleh mencopot dirinya sendiri.
//
// Kegagalannya TIDAK boleh menghentikan pencopotan. Pelanggan yang menjalankan
// uninstall sudah memutuskan, dan jaringan yang sedang putus bukan alasan untuk
// menolak keputusannya — yang tertinggal cuma satu baris di GONSU yang akan
// terlihat sebagai pemasangan yang berhenti menyapa, dan itu sudah ditangani
// .
func (c *Client) Deactivate(ctx context.Context) error {
	_, err := c.request(ctx, pathDeactivate, []byte("{}"), true)
	return err
}

// do mengirim satu request aktivasi/heartbeat dan mengurai jawabannya.
func (c *Client) do(ctx context.Context, path string, body []byte, sign bool) (Response, error) {
	payload, err := c.request(ctx, path, body, sign)
	if err != nil {
		return Response{}, err
	}

	var decoded Response
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return Response{}, fmt.Errorf("jawaban GONSU tidak dapat dibaca: %w", err)
	}
	return decoded, nil
}

// request mengirim satu request bertanda tangan dan mengembalikan body mentah.
//
// Dipisahkan dari `do` karena tidak setiap endpoint menjawab dengan bentuk yang
// sama. Yang sama di seluruh jalur ini adalah CARA membuktikan diri, dan itulah
// yang tidak boleh punya dua salinan.
func (c *Client) request(ctx context.Context, path string, body []byte, sign bool) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("menyiapkan request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")

	if sign {
		nonce, err := newNonce()
		if err != nil {
			return nil, err
		}
		// Waktu diambil dari jam lokal instalasi dan server menolak selisih yang
		// terlalu jauh. Instalasi dengan jam yang meleset jauh akan ditolak, dan
		// itu memang jawaban yang benar: tanpa waktu yang dapat dipercaya, tidak
		// ada perlindungan terhadap request lama yang diputar ulang.
		now := time.Now().UTC()
		request.Header.Set("X-GONSU-Installation", c.installationID)
		request.Header.Set("X-GONSU-Timestamp", strconv.FormatInt(now.Unix(), 10))
		request.Header.Set("X-GONSU-Nonce", nonce)
		request.Header.Set("X-GONSU-Signature", Sign(c.key, SignedRequest{
			InstallationID: c.installationID,
			Method:         http.MethodPost,
			Path:           path,
			Timestamp:      now,
			Nonce:          nonce,
			Body:           body,
		}))
	}

	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("menghubungi GONSU: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	payload, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBody))
	if err != nil {
		return nil, fmt.Errorf("membaca jawaban GONSU: %w", err)
	}

	// Seluruh 2xx diterima, bukan hanya 200.
	//
	// `deactivate` menjawab 204 tanpa badan — dan memperlakukannya sebagai
	// kegagalan berarti pencopotan SELALU dilaporkan gagal meskipun GONSU
	// sudah melepaskannya. Memeriksa satu kode persis membuat setiap endpoint
	// baru yang menjawab 201 atau 202 ikut patah, dan patahnya baru terlihat
	// dari sisi pelanggan.
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, apiErrorFrom(response.StatusCode, payload)
	}
	return payload, nil
}

// apiErrorFrom menerjemahkan envelope error GONSU.
func apiErrorFrom(status int, payload []byte) error {
	var envelope struct {
		Error struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	// Gagal diurai bukan alasan menyembunyikan kegagalannya: yang menjawab di
	// alamat itu mungkin bukan GONSU melainkan proxy perusahaan, dan status
	// HTTP-nya tetap informasi yang berguna.
	_ = json.Unmarshal(payload, &envelope)

	return &APIError{
		Status:    status,
		Code:      envelope.Error.Code,
		Message:   envelope.Error.Message,
		RequestID: envelope.Error.RequestID,
	}
}

// IsUnauthorized melaporkan apakah error berasal dari penolakan autentikasi.
//
// Berguna untuk membedakan "jaringan sedang bermasalah" — yang harus dilewati
// dengan lease dari cache — dari "instalasi ini sudah dicabut", yang tidak akan
// membaik dengan mencoba lagi.
func IsUnauthorized(err error) bool {
	var apiError *APIError
	return errors.As(err, &apiError) &&
		(apiError.Status == http.StatusUnauthorized || apiError.Status == http.StatusForbidden)
}

// pathUpdate adalah jalur pemeriksaan pembaruan.
const pathUpdate = "/license/v1/update"

// ReleaseOffer adalah rilis yang ditawarkan GONSU.
type ReleaseOffer struct {
	Version string `json:"version"`
	Channel string `json:"channel"`
	Image   struct {
		Repository string `json:"repository"`
		Digest     string `json:"digest"`
	} `json:"image"`
	// Mandatory menandai rilis yang tidak boleh dilewati — misalnya perbaikan
	// keamanan. GONSU tidak dapat memaksakannya pada server pelanggan; yang
	// dapat dilakukannya adalah mengatakannya dengan jelas.
	Mandatory   bool   `json:"mandatory"`
	Changelog   string `json:"changelog"`
	PublishedAt string `json:"published_at"`
}

// UpdateOffer adalah jawaban pemeriksaan pembaruan.
type UpdateOffer struct {
	CurrentVersion string        `json:"current_version"`
	UpToDate       bool          `json:"up_to_date"`
	Latest         *ReleaseOffer `json:"latest"`
}

// CheckUpdate menanyakan rilis mana yang boleh dipasang instalasi ini.
//
// Bertanda tangan seperti heartbeat: jawabannya bergantung pada langganan
// organization yang memiliki instalasi ini, dan itu bukan sesuatu yang boleh
// dijawab kepada siapa pun yang menebak idnya.
func (c *Client) CheckUpdate(ctx context.Context, version string) (UpdateOffer, error) {
	body, err := json.Marshal(map[string]string{"version": version})
	if err != nil {
		return UpdateOffer{}, fmt.Errorf("menyusun permintaan pembaruan: %w", err)
	}

	response, err := c.request(ctx, pathUpdate, body, true)
	if err != nil {
		return UpdateOffer{}, err
	}

	var offer UpdateOffer
	if err := json.Unmarshal(response, &offer); err != nil {
		return UpdateOffer{}, fmt.Errorf("jawaban pembaruan tidak dapat dibaca: %w", err)
	}
	return offer, nil
}

// pathRegistryCredential adalah jalur kredensial registry.
const pathRegistryCredential = "/license/v1/registry-credential" //nolint:gosec // jalur URL, bukan credential

// RegistryCredential adalah kredensial `docker login` berumur pendek.
type RegistryCredential struct {
	Registry string `json:"registry"`
	Username string `json:"username"`
	// Password RAHASIA dan berumur pendek. Ia tidak pernah dicatat ke log oleh
	// SDK ini, dan tidak boleh dicatat oleh yang memakainya.
	Password  string `json:"password"`
	ExpiresAt string `json:"expires_at"`
}

// RegistryCredential meminta kredensial untuk menarik image produk.
//
// Kredensialnya berumur pendek, tetapi bukan itu yang membuat pencabutan
// berlaku: setiap penukaran token di registry memeriksa ULANG apakah instalasi
// ini masih aktif dan masih berhak. Kredensial yang sudah terlanjur dipegang
// menjadi tidak berguna dalam hitungan menit setelah dicabut.
func (c *Client) RegistryCredential(ctx context.Context) (RegistryCredential, error) {
	payload, err := c.request(ctx, pathRegistryCredential, []byte(`{}`), true)
	if err != nil {
		return RegistryCredential{}, err
	}

	var credential RegistryCredential
	if err := json.Unmarshal(payload, &credential); err != nil {
		return RegistryCredential{}, fmt.Errorf("jawaban kredensial tidak dapat dibaca: %w", err)
	}
	return credential, nil
}

// ErrInsecureBaseURL berarti alamat GONSU memakai http polos ke host yang bukan
// dirinya sendiri.
var ErrInsecureBaseURL = errors.New("BaseURL wajib https kecuali ke localhost")

// requireTransportSecurity menolak http polos ke host mana pun selain loopback.
//
// TLS wajib di production. SDK tidak punya — dan tidak boleh
// punya — gagasan tentang "production": ia hanya tahu alamat yang diberikan
// produk. Yang dapat diputuskannya sendiri adalah aturan yang tidak butuh
// konfigurasi: teks polos hanya boleh menuju diri sendiri.
//
// Aturan itu tidak dapat lupa dinyalakan. Flag `AllowInsecure` yang harus
// diingat seseorang adalah flag yang menyala di production justru karena ia
// menyala di laptop lebih dulu, lalu ikut tersalin.
//
// Yang dijaga bukan kerahasiaan lease — ia bertanda tangan dan sudah tahan
// diubah. Yang dijaga adalah token aktivasi yang melintas di badan request,
// dan kredensial registry yang dikembalikan GONSU.
func requireTransportSecurity(baseURL string) error {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("BaseURL tidak dapat dibaca: %w", err)
	}
	switch parsed.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopback(parsed.Hostname()) {
			return nil
		}
		return fmt.Errorf("%w: %s", ErrInsecureBaseURL, baseURL)
	default:
		return fmt.Errorf("%w: skema %q tidak dikenal", ErrInsecureBaseURL, parsed.Scheme)
	}
}

// isLoopback melaporkan apakah host menunjuk mesin ini sendiri.
//
// Nama `localhost` ikut diterima meskipun resolusinya ditentukan sistem: yang
// dijaga aturan ini adalah kekeliruan yang tidak disengaja, bukan operator yang
// sengaja mengarahkan localhost ke tempat lain di mesin yang ia kuasai sendiri.
func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
