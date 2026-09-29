package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	gonsu "github.com/gonsutrijayautama/gonsu-one-sdk-go"
)

// Phase adalah keadaan lisensi yang dilihat pengguna.
type Phase string

// Fase lisensi.
const (
	// PhaseNormal: lisensi berlaku.
	PhaseNormal Phase = "NORMAL"
	// PhaseGrace: lease kedaluwarsa tetapi masih dalam masa tenggang — operasi
	// normal, peringatan menonjol.
	PhaseGrace Phase = "GRACE"
	// PhaseRestricted: tidak diizinkan. Produk menolak transaksi baru, tetapi
	// data tetap dapat dibaca dan diekspor.
	PhaseRestricted Phase = "RESTRICTED"
	// PhaseNotActivated: pemasangan belum pernah diaktivasi, atau kehilangan
	// state-nya.
	PhaseNotActivated Phase = "NOT_ACTIVATED"
	// PhaseUnreachable: agent belum pernah terjawab sejak aplikasi start.
	// Gagal-terbuka: pabrik tidak berhenti karena satu request gagal.
	PhaseUnreachable Phase = "UNREACHABLE"
	// PhaseUnlicensed: cloud tanpa nilai lisensi dari GONSU. Semua diizinkan
	// dan tidak ada pembeda paket, sampai GONSU menyerahkannya.
	PhaseUnlicensed Phase = "UNLICENSED"
)

// Status adalah keadaan lisensi untuk ditampilkan, misalnya pada banner.
type Status struct {
	Mode       Mode       `json:"mode"`
	Phase      Phase      `json:"phase"`
	Allowed    bool       `json:"allowed"`
	State      string     `json:"state,omitempty"`
	PlanName   string     `json:"plan_name,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	GraceUntil *time.Time `json:"grace_until,omitempty"`
	CheckedAt  *time.Time `json:"checked_at,omitempty"`
}

// License menjawab hak pakai pemasangan ini. Murah dipanggil dari request
// handler mana pun; tidak pernah menunggu jaringan lebih dari beberapa detik,
// dan hanya pada pertanyaan pertama di self-host.
type License struct {
	mode  Mode
	agent *agentLicense
	lease *leaseLicense
}

// Allowed menjawab apakah pemasangan ini boleh menjalankan transaksi baru.
//
// Di cloud selalu true: langganan yang berhenti dijawab GONSU dengan
// menangguhkan aplikasinya.
func (l *License) Allowed(ctx context.Context) bool {
	if l.agent != nil {
		return l.agent.Allowed(ctx)
	}
	return true
}

// Feature menjawab apakah fitur boolean `key` menyala.
//
// Key yang tidak dibawa lisensi berarti TIDAK menyala, dan dicatat sekali di
// log: key yang salah ketik atau belum didaftarkan di katalog mematikan fiturnya
// tanpa galat apa pun. Di cloud tanpa nilai lisensi, semua menyala.
func (l *License) Feature(ctx context.Context, key string) bool {
	switch {
	case l.agent != nil:
		return l.agent.Feature(ctx, key)
	case l.lease != nil:
		return l.lease.Feature(key)
	default:
		return true
	}
}

// Limit mengembalikan batas numerik `key`, dan apakah tanpa batas.
//
// Key yang tidak dibawa lisensi berarti batas nol — tidak boleh sama sekali.
// Di cloud tanpa nilai lisensi, tanpa batas.
func (l *License) Limit(ctx context.Context, key string) (value int64, unlimited bool) {
	switch {
	case l.agent != nil:
		return l.agent.Limit(ctx, key)
	case l.lease != nil:
		return l.lease.Limit(key)
	default:
		return 0, true
	}
}

// Status menjelaskan keadaan lisensi.
func (l *License) Status(ctx context.Context) Status {
	switch {
	case l.agent != nil:
		return l.agent.Status(ctx)
	case l.lease != nil:
		return l.lease.Status()
	default:
		return Status{Mode: ModeCloud, Phase: PhaseUnlicensed, Allowed: true}
	}
}

// ---------------------------------------------------------------------------
// Self-host: agent
// ---------------------------------------------------------------------------

// agentLicense membaca kesimpulan lisensi dari agent GONSU. Agent yang
// memverifikasi tanda tangan lease; produk hanya membaca hasilnya.
//
//   - agent tidak ditanya pada setiap request — jawabannya di-cache singkat;
//   - request pengguna tidak menunggu agent yang macet — ada timeout, dan
//     jawaban basi disegarkan di latar;
//   - agent yang sesaat tidak terjangkau tidak menghentikan pabrik: jawaban
//     terakhir tetap dipakai, tetapi dinilai ulang terhadap waktunya sendiri —
//     lease yang melewati masa tenggangnya tetap berakhir walau agent mati;
//   - agent yang belum pernah terjawab sejak start: gagal-terbuka.
type agentLicense struct {
	url    string
	client *http.Client
	logger *slog.Logger
	ttl    time.Duration
	now    func() time.Time

	// first menyatukan pertanyaan pertama dari request yang datang bersamaan.
	first sync.Mutex

	mu          sync.Mutex
	last        *agentAnswer
	fetchedAt   time.Time
	attemptedAt time.Time
	refreshing  bool
	failing     bool
	missing     map[string]bool
}

// Lease berumur hari; 30 detik cukup segar tanpa membuat agent ditanya ribuan
// kali per menit.
const (
	agentCacheTTL = 30 * time.Second
	agentTimeout  = 2 * time.Second
)

// Keadaan lease menurut agent.
const (
	stateActive  = "active"
	stateGrace   = "grace"
	stateExpired = "expired"
	stateUnknown = "unknown"
)

// agentAnswer adalah bagian jawaban GET /v1/license yang dipakai kit.
type agentAnswer struct {
	Allowed        bool      `json:"allowed"`
	State          string    `json:"state"`
	PlanName       string    `json:"plan_name"`
	ExpiresAt      time.Time `json:"expires_at"`
	GraceUntil     time.Time `json:"grace_until"`
	OrganizationID string    `json:"organization_id"`
	Owner          *struct {
		Subject string `json:"subject"`
	} `json:"owner"`

	// Nilai hak pakai dipisah menurut tipenya saat dibaca, lihat decodeAgent.
	numbers map[string]json.Number
	flags   map[string]bool
	nulls   map[string]bool
}

func newAgentLicense(url string, client *http.Client, logger *slog.Logger) *agentLicense {
	return &agentLicense{
		url:     url,
		client:  client,
		logger:  logger,
		ttl:     agentCacheTTL,
		now:     time.Now,
		missing: map[string]bool{},
	}
}

func (a *agentLicense) Allowed(ctx context.Context) bool {
	l := a.answer(ctx)
	return l == nil || l.Allowed
}

func (a *agentLicense) Feature(ctx context.Context, key string) bool {
	l := a.answer(ctx)
	if l == nil {
		return true
	}
	on, ok := l.flags[key]
	if !ok {
		a.warnMissing(key)
	}
	return on
}

func (a *agentLicense) Limit(ctx context.Context, key string) (int64, bool) {
	l := a.answer(ctx)
	if l == nil {
		return 0, true
	}
	if l.nulls[key] {
		// null, bukan nol: tanpa batas. Nol berarti tidak boleh sama sekali.
		return 0, true
	}
	n, ok := l.numbers[key]
	if !ok {
		a.warnMissing(key)
		return 0, false
	}
	v, err := n.Int64()
	if err != nil {
		a.warnMissing(key)
		return 0, false
	}
	return v, false
}

func (a *agentLicense) Status(ctx context.Context) Status {
	l := a.answer(ctx)
	if l == nil {
		return Status{Mode: ModeSelfHost, Phase: PhaseUnreachable, Allowed: true}
	}
	a.mu.Lock()
	checked := a.fetchedAt
	a.mu.Unlock()
	s := Status{
		Mode: ModeSelfHost, Phase: l.phase(), Allowed: l.Allowed, State: l.State,
		PlanName: l.PlanName, CheckedAt: &checked,
	}
	if !l.ExpiresAt.IsZero() {
		s.ExpiresAt, s.GraceUntil = &l.ExpiresAt, &l.GraceUntil
	}
	return s
}

// installation mengembalikan organization dan `sub` pemilik menurut agent.
func (a *agentLicense) installation(ctx context.Context) (organizationID, ownerSubject string) {
	l := a.answer(ctx)
	if l == nil {
		return "", ""
	}
	if l.Owner != nil {
		ownerSubject = l.Owner.Subject
	}
	return l.OrganizationID, ownerSubject
}

// answer mengembalikan jawaban agent yang berlaku sekarang, atau nil bila agent
// belum pernah terjawab (gagal-terbuka).
func (a *agentLicense) answer(ctx context.Context) *agentAnswer {
	a.mu.Lock()
	last, fetchedAt := a.last, a.fetchedAt
	now := a.now()
	if last != nil {
		if now.Sub(fetchedAt) >= a.ttl && !a.refreshing && now.Sub(a.attemptedAt) >= a.ttl {
			a.refreshing = true
			go a.refresh(context.WithoutCancel(ctx))
		}
		a.mu.Unlock()
		l := last.at(now)
		return &l
	}
	a.mu.Unlock()

	a.first.Lock()
	defer a.first.Unlock()
	a.mu.Lock()
	due := a.last == nil && a.now().Sub(a.attemptedAt) >= a.ttl
	a.mu.Unlock()
	if due {
		a.fetch(ctx)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.last == nil {
		return nil
	}
	l := a.last.at(a.now())
	return &l
}

func (a *agentLicense) refresh(ctx context.Context) {
	a.fetch(ctx)
	a.mu.Lock()
	a.refreshing = false
	a.mu.Unlock()
}

// fetch bertanya ke agent dan menyimpan jawabannya. Kegagalan hanya dicatat:
// jawaban terakhir tetap berlaku.
func (a *agentLicense) fetch(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, agentTimeout)
	defer cancel()
	l, err := a.get(ctx)

	a.mu.Lock()
	defer a.mu.Unlock()
	a.attemptedAt = a.now()
	if err != nil {
		if !a.failing {
			a.failing = true
			if a.last == nil {
				a.logger.Warn("agent lisensi belum terjawab; aplikasi tetap melayani (gagal-terbuka)",
					slog.String("url", a.url), slog.String("error", err.Error()))
			} else {
				a.logger.Warn("agent lisensi tidak terjangkau; memakai jawaban terakhir",
					slog.String("url", a.url), slog.String("error", err.Error()))
			}
		}
		return
	}
	if a.failing {
		a.logger.Info("agent lisensi terjawab kembali", slog.String("state", l.State))
	}
	a.failing = false
	a.last, a.fetchedAt = &l, a.attemptedAt
}

func (a *agentLicense) get(ctx context.Context) (agentAnswer, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.url, nil)
	if err != nil {
		return agentAnswer{}, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return agentAnswer{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return agentAnswer{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return agentAnswer{}, fmt.Errorf("agent menjawab %d", resp.StatusCode)
	}
	return decodeAgent(body)
}

// decodeAgent membaca jawaban agent. Nilai hak pakai bertipe boolean, angka,
// atau null (tanpa batas); ketiganya dipisah di sini supaya pembacanya tidak
// menebak tipe.
func decodeAgent(body []byte) (agentAnswer, error) {
	var raw struct {
		agentAnswer
		Entitlements map[string]json.RawMessage `json:"entitlements"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return agentAnswer{}, fmt.Errorf("jawaban agent tidak dapat dibaca: %w", err)
	}
	l := raw.agentAnswer
	l.numbers = map[string]json.Number{}
	l.flags = map[string]bool{}
	l.nulls = map[string]bool{}
	for k, v := range raw.Entitlements {
		var b bool
		var n json.Number
		switch {
		case string(v) == "null":
			l.nulls[k] = true
		case json.Unmarshal(v, &b) == nil:
			l.flags[k] = b
		case json.Unmarshal(v, &n) == nil:
			l.numbers[k] = n
		}
	}
	return l, nil
}

// at menilai ulang jawaban terhadap waktu sekarang. Hanya pernah menurunkan:
// jawaban lama yang melewati masa berlakunya tidak lagi mengizinkan, walau
// agent tidak dapat ditanya.
func (l agentAnswer) at(now time.Time) agentAnswer {
	if l.State == stateUnknown || l.ExpiresAt.IsZero() {
		return l
	}
	switch {
	case !l.GraceUntil.IsZero() && now.After(l.GraceUntil):
		l.State, l.Allowed = stateExpired, false
	case now.After(l.ExpiresAt) && l.State == stateActive:
		l.State = stateGrace
	}
	return l
}

func (l agentAnswer) phase() Phase {
	switch {
	case l.State == stateUnknown:
		return PhaseNotActivated
	case !l.Allowed:
		return PhaseRestricted
	case l.State == stateGrace:
		return PhaseGrace
	default:
		return PhaseNormal
	}
}

// warnMissing mencatat key yang tidak dibawa lisensi, sekali per key.
func (a *agentLicense) warnMissing(key string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.missing[key] {
		return
	}
	a.missing[key] = true
	a.logger.Warn("hak pakai tidak ada di lisensi pemasangan; kemampuannya ditolak",
		slog.String("key", key))
}

// ---------------------------------------------------------------------------
// Cloud: lease
// ---------------------------------------------------------------------------

// leaseLicense membaca hak pakai cloud dari lease bertanda tangan, lewat paket
// lisensi. Hanya NILAI hak pakai yang dipakai: berhenti-tidaknya aplikasi
// cloud urusan GONSU, jadi kedaluwarsanya lease tidak pernah menguncinya.
type leaseLicense struct {
	license         *gonsu.License
	activationToken string
	logger          *slog.Logger

	mu      sync.Mutex
	missing map[string]bool
}

// activationRetry adalah jeda awal dan terlama antar percobaan aktivasi yang
// gagal karena jaringan.
const (
	activationRetryFirst = time.Minute
	activationRetryMax   = 15 * time.Minute
)

// run mengaktivasi pemasangan bila perlu, lalu menjaga lease tetap segar
// sampai ctx selesai.
func (l *leaseLicense) run(ctx context.Context) {
	wait := activationRetryFirst
	for l.license.Status().State == gonsu.StateUnknown && l.activationToken != "" {
		err := l.license.Activate(ctx, l.activationToken)
		if err == nil {
			l.logger.Info("pemasangan diaktivasi")
			break
		}
		var rejected *gonsu.APIError
		if errors.As(err, &rejected) {
			// Token sudah dipakai atau dicabut. Pemasangan yang sudah
			// diaktivasi sebelum restart tetap berjalan lewat heartbeat.
			l.logger.Warn("aktivasi ditolak GONSU; melanjutkan dengan identitas yang sudah ada",
				slog.String("error", err.Error()))
			break
		}
		l.logger.Warn("aktivasi belum berhasil; dicoba lagi",
			slog.String("error", err.Error()), slog.Duration("dalam", wait))
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = min(wait*2, activationRetryMax)
	}
	l.license.Run(ctx)
}

func (l *leaseLicense) Feature(key string) bool {
	status := l.license.Status()
	if status.State == gonsu.StateUnknown {
		// Belum ada lease sama sekali: gagal-terbuka, sama seperti cloud tanpa
		// nilai lisensi. Pelanggan yang membayar tidak kehilangan fitur karena
		// aktivasi di sisi GONSU tertunda.
		return true
	}
	if _, ok := status.Entry(key); !ok {
		l.warnMissing(key)
	}
	return status.Feature(key)
}

func (l *leaseLicense) Limit(key string) (int64, bool) {
	status := l.license.Status()
	if status.State == gonsu.StateUnknown {
		return 0, true
	}
	if _, ok := status.Entry(key); !ok {
		l.warnMissing(key)
	}
	return status.Limit(key)
}

func (l *leaseLicense) Status() Status {
	status := l.license.Status()
	s := Status{Mode: ModeCloud, Allowed: true, State: string(status.State), PlanName: status.Lease.PlanName}
	switch status.State {
	case gonsu.StateUnknown:
		s.Phase = PhaseNotActivated
	case gonsu.StateGrace:
		s.Phase = PhaseGrace
	default:
		s.Phase = PhaseNormal
	}
	return s
}

func (l *leaseLicense) warnMissing(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.missing[key] {
		return
	}
	l.missing[key] = true
	l.logger.Warn("hak pakai tidak ada di lisensi pemasangan; kemampuannya ditolak",
		slog.String("key", key))
}
