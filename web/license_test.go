package web

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

var quiet = slog.New(slog.DiscardHandler)

// fakeAgent menyajikan GET /v1/license seperti agent GONSU.
type fakeAgent struct {
	srv    *httptest.Server
	hits   atomic.Int32
	body   atomic.Value // string
	status atomic.Int32
}

func newFakeAgent(t *testing.T, body string) *fakeAgent {
	t.Helper()
	f := &fakeAgent{}
	f.body.Store(body)
	f.status.Store(http.StatusOK)
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f.hits.Add(1)
		w.WriteHeader(int(f.status.Load()))
		_, _ = io.WriteString(w, f.body.Load().(string))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// clock adalah jam yang dimajukan test.
type clock struct{ t atomic.Int64 }

func (c *clock) now() time.Time          { return time.Unix(0, c.t.Load()) }
func (c *clock) advance(d time.Duration) { c.t.Add(int64(d)) }

func newTestAgent(url string, c *clock) *agentLicense {
	a := newAgentLicense(url, &http.Client{Timeout: agentTimeout}, quiet)
	a.now = c.now
	return a
}

func licenseBody(state string, allowed bool, expires, grace time.Time, ent map[string]any) string {
	b, _ := json.Marshal(map[string]any{
		"allowed": allowed, "state": state, "granted": true, "plan_name": "Business",
		"expires_at": expires, "grace_until": grace, "entitlements": ent,
		"organization_id": "org_1", "owner": map[string]any{"subject": "usr_pemilik"},
	})
	return string(b)
}

var ctx = context.Background()

func TestAgent_LisensiAktif(t *testing.T) {
	c := &clock{}
	c.t.Store(time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC).UnixNano())
	now := c.now()
	f := newFakeAgent(t, licenseBody("active", true, now.Add(72*time.Hour), now.Add(144*time.Hour),
		map[string]any{"garment.core": true, "garment.pattern_studio": false, "users.max": 25, "warehouses.max": nil}))
	a := newTestAgent(f.srv.URL, c)

	if !a.Allowed(ctx) || !a.Feature(ctx, "garment.core") || a.Feature(ctx, "garment.pattern_studio") {
		t.Error("jawaban aktif dibaca salah")
	}
	if v, unlimited := a.Limit(ctx, "users.max"); v != 25 || unlimited {
		t.Errorf("users.max = %d, unlimited=%v", v, unlimited)
	}
	if _, unlimited := a.Limit(ctx, "warehouses.max"); !unlimited {
		t.Error("null harus berarti tanpa batas")
	}
	// Key yang tidak dibawa lisensi: ditolak, bukan dianggap boleh.
	if a.Feature(ctx, "garment.tidak_ada") {
		t.Error("key yang tidak ada diizinkan")
	}
	if v, unlimited := a.Limit(ctx, "sites.max"); v != 0 || unlimited {
		t.Errorf("limit yang tidak ada = %d, %v; mau 0, false", v, unlimited)
	}
	s := a.Status(ctx)
	if s.Mode != ModeSelfHost || s.Phase != PhaseNormal || s.PlanName != "Business" || s.ExpiresAt == nil {
		t.Errorf("status = %+v", s)
	}
	if org, owner := a.installation(ctx); org != "org_1" || owner != "usr_pemilik" {
		t.Errorf("pemasangan = %q, %q", org, owner)
	}
	// Cache: pertanyaan berikutnya dalam TTL tidak menyentuh agent.
	if n := f.hits.Load(); n != 1 {
		t.Errorf("agent ditanya %d kali, mau 1", n)
	}
}

func TestAgent_Fase(t *testing.T) {
	now := time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		body    string
		allowed bool
		phase   Phase
	}{
		{"grace tetap diizinkan", licenseBody("grace", true, now.Add(-time.Hour), now.Add(48*time.Hour), nil), true, PhaseGrace},
		{"expired", licenseBody("expired", false, now.Add(-96*time.Hour), now.Add(-time.Hour), nil), false, PhaseRestricted},
		{"belum aktivasi", licenseBody("unknown", false, time.Time{}, time.Time{}, nil), false, PhaseNotActivated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &clock{}
			c.t.Store(now.UnixNano())
			a := newTestAgent(newFakeAgent(t, tt.body).srv.URL, c)
			if got := a.Allowed(ctx); got != tt.allowed {
				t.Errorf("Allowed = %v, mau %v", got, tt.allowed)
			}
			if got := a.Status(ctx).Phase; got != tt.phase {
				t.Errorf("Phase = %s, mau %s", got, tt.phase)
			}
		})
	}
}

// Agent yang belum pernah terjawab: gagal-terbuka, dan tidak ditanya ulang pada
// setiap request selama masih mati.
func TestAgent_TakTerjangkauGagalTerbuka(t *testing.T) {
	c := &clock{}
	f := newFakeAgent(t, "")
	url := f.srv.URL
	f.srv.Close()
	a := newTestAgent(url, c)

	if !a.Allowed(ctx) || !a.Feature(ctx, "garment.core") {
		t.Error("agent mati harus gagal-terbuka")
	}
	if _, unlimited := a.Limit(ctx, "users.max"); !unlimited {
		t.Error("limit saat agent mati harus tanpa batas")
	}
	if s := a.Status(ctx); s.Phase != PhaseUnreachable || !s.Allowed {
		t.Errorf("status = %+v", s)
	}
	a.mu.Lock()
	attempted := a.attemptedAt
	a.mu.Unlock()
	_ = a.Allowed(ctx)
	a.mu.Lock()
	again := a.attemptedAt
	a.mu.Unlock()
	if !again.Equal(attempted) {
		t.Error("agent mati ditanya ulang sebelum TTL")
	}
}

// Agent mati setelah pernah menjawab: jawaban terakhir dipakai, tetapi lease
// yang melewati masa tenggangnya tetap berakhir — mematikan agent bukan jalan
// memperpanjang lisensi.
func TestAgent_JawabanBasiTetapBerakhir(t *testing.T) {
	c := &clock{}
	start := time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)
	c.t.Store(start.UnixNano())
	f := newFakeAgent(t, licenseBody("active", true, start.Add(24*time.Hour), start.Add(96*time.Hour),
		map[string]any{"garment.core": true}))
	a := newTestAgent(f.srv.URL, c)
	if !a.Allowed(ctx) {
		t.Fatal("awal harus diizinkan")
	}
	f.status.Store(http.StatusServiceUnavailable)

	c.advance(48 * time.Hour)
	a.fetch(ctx)
	if !a.Allowed(ctx) || a.Status(ctx).Phase != PhaseGrace {
		t.Errorf("lewat expires_at, dalam grace: allowed=%v phase=%s", a.Allowed(ctx), a.Status(ctx).Phase)
	}
	c.advance(72 * time.Hour)
	a.fetch(ctx)
	if a.Allowed(ctx) || a.Status(ctx).Phase != PhaseRestricted {
		t.Errorf("lewat grace_until tanpa agent: allowed=%v phase=%s", a.Allowed(ctx), a.Status(ctx).Phase)
	}
}

func TestAgent_DisegarkanSesudahTTL(t *testing.T) {
	c := &clock{}
	now := time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)
	c.t.Store(now.UnixNano())
	f := newFakeAgent(t, licenseBody("active", true, now.Add(72*time.Hour), now.Add(144*time.Hour), nil))
	a := newTestAgent(f.srv.URL, c)
	_ = a.Allowed(ctx)

	f.body.Store(licenseBody("expired", false, now.Add(-96*time.Hour), now.Add(-time.Hour), nil))
	c.advance(agentCacheTTL + time.Second)
	// Jawaban basi dijawab seketika; penyegaran berjalan di latar.
	_ = a.Allowed(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for a.Allowed(ctx) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if a.Allowed(ctx) {
		t.Error("jawaban baru dari agent tidak pernah dipakai")
	}
}

// Cloud tanpa nilai lisensi: semua diizinkan, tanpa pembeda paket, dan
// dinyatakan terus terang pada statusnya.
func TestLicense_CloudTanpaLisensi(t *testing.T) {
	l := &License{mode: ModeCloud}
	if !l.Allowed(ctx) || !l.Feature(ctx, "garment.apa_saja") {
		t.Error("cloud tanpa lisensi harus mengizinkan")
	}
	if _, unlimited := l.Limit(ctx, "users.max"); !unlimited {
		t.Error("cloud tanpa lisensi harus tanpa batas")
	}
	if s := l.Status(ctx); s.Phase != PhaseUnlicensed || s.Mode != ModeCloud {
		t.Errorf("status = %+v", s)
	}
}
