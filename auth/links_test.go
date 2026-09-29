package auth_test

import (
	"testing"

	"github.com/gonsutrijayautama/gonsu-one-sdk-go/auth"
)

// Tautan akun dan sandi menunjuk penyedia identitas, bukan produk. Yang diuji
// di sini bentuk alamatnya: Account Center membaca `redirect`, bukan nama lain.
func TestAccountURL(t *testing.T) {
	client, err := auth.New(auth.Options{
		Issuer:      "https://accounts.gonsu.example/oidc",
		ClientID:    clientID,
		RedirectURI: redirect,
	})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct{ name, got, want string }{
		{"tanpa alamat kembali", client.AccountURL(""), "https://accounts.gonsu.example/account"},
		{
			"dengan alamat kembali",
			client.AccountURL("https://konveksiku.app.example/dashboard/?tab=1"),
			"https://accounts.gonsu.example/account?redirect=https%3A%2F%2Fkonveksiku.app.example%2Fdashboard%2F%3Ftab%3D1",
		},
		{"ganti sandi sama dengan akun", client.ChangePasswordURL(), "https://accounts.gonsu.example/account"},
		{"lupa sandi", client.ForgotPasswordURL(), "https://accounts.gonsu.example/forgot-password"},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s: %q, mau %q", tc.name, tc.got, tc.want)
		}
	}
}
