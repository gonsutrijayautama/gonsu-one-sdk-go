package auth

import (
	"context"
	"net/url"
	"strings"
)

// LogoutURL menyusun alamat keluar di penyedia identitas (RP-initiated logout).
//
// Sesi produk dimatikan produk SENDIRI; ini hanya mengakhiri sesi di penyedia
// identitas, supaya login berikutnya benar-benar meminta sandi lagi. Keduanya
// terpisah dengan sengaja: sesi produk tidak boleh bergantung
// pada penyedia identitas yang dapat sesaat tidak terjangkau.
//
// `redirectAfter` kosong berarti pengguna tertinggal di halaman penyedia
// identitas. Alamat yang diisi WAJIB sudah terdaftar — GONSU mendaftarkan
// `redirect_uri` pemasangan sebagai alamat pasca-logout juga.
func (c *Client) LogoutURL(ctx context.Context, idTokenHint, redirectAfter string) (string, error) {
	meta, err := c.metadata(ctx)
	if err != nil {
		return "", err
	}
	if meta.EndSessionEndpoint == "" {
		// Penyedia identitas tanpa endpoint keluar. Produk tetap dapat
		// mematikan sesinya sendiri; yang tidak dapat dilakukan hanyalah
		// mengakhiri sesi di sisi penyedia.
		return "", nil
	}

	query := url.Values{}
	if idTokenHint != "" {
		query.Set("id_token_hint", idTokenHint)
	}
	if redirectAfter != "" {
		query.Set("post_logout_redirect_uri", redirectAfter)
	}
	if len(query) == 0 {
		return meta.EndSessionEndpoint, nil
	}

	pemisah := "?"
	if strings.Contains(meta.EndSessionEndpoint, "?") {
		pemisah = "&"
	}
	return meta.EndSessionEndpoint + pemisah + query.Encode(), nil
}

// ForgotPasswordURL dan ChangePasswordURL mengembalikan TAUTAN, bukan formulir.
//
// Sandi berada di penyedia identitas, dan layar sandi di dalam produk MELATIH
// pengguna mengetik sandi GONSU-nya di domain produk. Satu-satunya hal yang
// membuat SSO bernilai adalah pengguna dapat melihat bahwa yang meminta
// sandinya benar-benar alamat GONSU; begitu kebiasaan itu hilang, memalsukan
// layar login tinggal menyalin tampilannya.
func (c *Client) ForgotPasswordURL() string {
	return strings.TrimSuffix(c.options.Issuer, "/oidc") + "/forgot-password"
}

// ChangePasswordURL menunjuk halaman ganti sandi milik penyedia identitas.
//
// Sama dengan AccountURL tanpa alamat kembali: sandi diganti di Account Center
// GONSU, bersama profil, verifikasi dua langkah, dan passkey.
func (c *Client) ChangePasswordURL() string {
	return c.AccountURL("")
}

// AccountURL menunjuk Account Center GONSU — halaman "Akun saya" — dengan
// tombol "Kembali ke aplikasi" yang menuju `returnTo`.
//
// Account Center hanya mengikuti `returnTo` yang origin-nya terdaftar di GONSU:
// Portal, Console, dan alamat aplikasi di domain aplikasi GONSU. Alamat lain
// diabaikan dan tombolnya kembali ke Portal, jadi mengisi alamat yang salah
// tidak membuka pengalihan ke mana pun. Kosong berarti tanpa alamat kembali.
func (c *Client) AccountURL(returnTo string) string {
	account := strings.TrimSuffix(c.options.Issuer, "/oidc") + "/account"
	if returnTo == "" {
		return account
	}
	return account + "?" + url.Values{"redirect": {returnTo}}.Encode()
}
