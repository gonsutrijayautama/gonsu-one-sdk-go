package web

import (
	"context"
	"net/http"
	"net/url"
)

// Jalur yang mengantar pengguna ke Portal GONSU, untuk bisnis dan produk
// pemasangan ini. Produk menautkannya seperti tautan biasa — "Kelola
// langganan", "Bayar tagihan", "Lihat paket" — tanpa pernah mengetahui alamat
// Portal maupun bentuk halamannya.
//
// Portal sendiri yang memeriksa siapa yang membukanya: orang yang login ke
// aplikasi belum tentu anggota bisnisnya di Portal, apalagi berhak melihat
// tagihan. Produk memutuskan siapa yang melihat tautannya; menjaga jalur ini
// dengan izinnya sendiri dianjurkan.
const (
	PortalSubscriptionPath = "/auth/gonsu/portal/subscription"
	PortalInvoicesPath     = "/auth/gonsu/portal/invoices"
	PortalPlansPath        = "/auth/gonsu/portal/plans"
)

// PortalPage adalah halaman Portal yang dituju.
type PortalPage string

const (
	// PortalSubscription: langganan bisnis ini.
	PortalSubscription PortalPage = "subscription"
	// PortalInvoices: tagihan bisnis ini.
	PortalInvoices PortalPage = "invoices"
	// PortalPlans: paket produk ini — untuk upgrade saat sebuah fitur belum
	// termasuk paket, atau kuota sudah penuh.
	PortalPlans PortalPage = "plans"
)

// PortalConfigured melaporkan apakah GONSU menyerahkan alamat Portal
// (GONSU_PORTAL_URL). Tanpa itu jalur Portal menjawab 404, dan produk
// sebaiknya tidak menampilkan tautannya.
func (k *Kit) PortalConfigured() bool { return k.env.portalURL != "" }

// PortalURL adalah alamat halaman Portal untuk pemasangan ini. ok false bila
// alamat Portal tidak diserahkan.
//
// Bila organization pemasangan belum diketahui — agent self-host belum
// menjawab — yang dituju halaman muka Portal, yang mengantar orangnya ke
// bisnisnya sendiri.
func (k *Kit) PortalURL(ctx context.Context, page PortalPage) (string, bool) {
	if k.env.portalURL == "" {
		return "", false
	}
	organization, _ := k.Installation(ctx)
	if organization == "" {
		return k.env.portalURL + "/", true
	}
	base := k.env.portalURL + "/organizations/" + url.PathEscape(organization)
	switch page {
	case PortalInvoices:
		return base + "/invoices", true
	case PortalPlans:
		return base + "/catalog/" + url.PathEscape(k.productCode), true
	default:
		return base + "/subscriptions", true
	}
}

func (k *Kit) portal(page PortalPage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		target, ok := k.PortalURL(r.Context(), page)
		if !ok {
			http.Error(w, "Alamat Portal GONSU belum diserahkan ke aplikasi ini.", http.StatusNotFound)
			return
		}
		// Tujuannya disusun dari alamat Portal milik GONSU dan organization
		// pemasangan, tidak dari apa pun yang dikirim peramban.
		http.Redirect(w, r, target, http.StatusSeeOther) //nolint:gosec // lihat komentar di atas
	}
}
