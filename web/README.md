# GONSU One — kit web (Go)

**Untuk tim yang membangun produk web Go untuk dijual di GONSU One.**

Paket lisensi dan paket `auth` adalah inti: mereka mengurus protokol. Kit ini
mengurus sambungan di atasnya — bagian yang dulu ditulis setiap produk sendiri,
dan yang salahnya tidak terlihat. Pasang satu kit, serahkan beberapa pengait,
dan produk Anda tidak pernah bercabang menurut cloud atau self-host.

```
go get github.com/gonsutrijayautama/gonsu-one-sdk-go
```

```go
import "github.com/gonsutrijayautama/gonsu-one-sdk-go/web"
```

Nol dependency di luar standard library. Hanya `net/http`.

## Yang dikerjakan kit, dan yang tetap milik Anda

| kit | produk Anda |
|---|---|
| membaca nilai GONSU dari environment, memutuskan cloud atau self-host | tabel pengguna dan perannya |
| `/auth/gonsu/login`, `/callback`, `/account`, `/forgot-password`, `/switch-account` | sesi dan cookie Anda sendiri |
| menyimpan state login di server, menolak open redirect | halaman awal `/` — landing page Anda |
| memastikan orang yang terbukti login memang diberi akses | layar "beri akses login" |
| admin pertama dari pemilik bisnis | arti "admin" di produk Anda |
| hak pakai: `Allowed`, `Feature`, `Limit` | di mana hak pakai ditegakkan |
| meminta akun GONSU untuk orang baru | kuota kursi sebelum memintanya |

## Memasang

```go
kit, err := web.New(web.Options{
    ProductCode: "garment", // kode produk Anda di katalog GONSU
    Version:     version,
    Logger:      logger,
    Hooks: web.Hooks{
        // Apakah orang ini diberi akses? Cari di tabel pengguna ANDA.
        Granted: func(ctx context.Context, sub string) (bool, error) {
            return db.ActiveUserExists(ctx, sub)
        },
        // Opsional: pemilik bisnis menjadi admin pertama, hanya selama tabel
        // pengguna Anda masih kosong — periksa di dalam transaksi yang sama.
        BootstrapOwner: func(ctx context.Context, c auth.Claims) (bool, error) {
            return db.CreateFirstAdminIfEmpty(ctx, c.Subject, c.Email, c.Name)
        },
        // Terbitkan sesi Anda sendiri, lalu arahkan ke `next`.
        StartSession: func(w http.ResponseWriter, r *http.Request, login auth.Login, next string) error {
            if err := sessions.Issue(w, r, login.Claims.Subject, login.Session, login.IDToken); err != nil {
                return err
            }
            if next == "" {
                next = "/dashboard/"
            }
            http.Redirect(w, r, next, http.StatusSeeOther)
            return nil
        },
    },
})
if err != nil {
    return err
}
go kit.Run(ctx) // lisensi cloud: aktivasi pertama, lalu heartbeat

mux.Handle("/auth/gonsu/", kit.Handler())
```

Dengan chi, daftarkan tanpa memotong awalan jalurnya:

```go
r.Handle("/auth/gonsu/*", kit.Handler())
```

`New` tidak menghubungi GONSU maupun agent. Aplikasi tetap start walau keduanya
belum siap.

**Jangan pernah membuat pengguna di `Granted`.** Pengguna lahir dari layar
"beri akses login" Anda, bukan dari login pertama. Membuatnya dari `sub` yang
tidak dikenal berarti orang dari pemasangan lain dibuatkan akun alih-alih
ditolak.

## Tautan di halaman Anda

| tautan | ke mana |
|---|---|
| **Masuk** | `/auth/gonsu/login?next=/jalur/tujuan` |
| **Akun saya** | `/auth/gonsu/account?return=/jalur/saat/ini` — profil, sandi, verifikasi dua langkah, passkey di GONSU, dengan tombol kembali ke aplikasi Anda |
| **Lupa sandi** | `/auth/gonsu/forgot-password` |
| **Masuk dengan akun lain** | `/auth/gonsu/switch-account` |

`/` sengaja tidak dipakai kit. Halaman muka milik Anda dan pelanggan Anda.
Tombol **Buka aplikasi** di Portal GONSU menuju `/auth/gonsu/login`.

Tidak ada layar sandi di produk. Layar sandi di domain produk melatih pengguna
mengetik sandi GONSU-nya di tempat yang bukan GONSU.

## Keluar

Matikan sesi Anda lebih dulu, lalu akhiri sesi di GONSU:

```go
sessions.Revoke(w, r)
if u, err := kit.LogoutURL(ctx, idToken); err == nil {
    http.Redirect(w, r, u, http.StatusSeeOther)
    return
}
http.Redirect(w, r, "/", http.StatusSeeOther)
```

GONSU mengembalikan pengguna ke halaman muka aplikasi Anda.

## Orang yang dicabut harus berhenti

Panggil `VerifySession` pada request yang masuk. Ia hanya menyentuh jaringan
ketika sudah waktunya memeriksa ulang.

```go
state, err := kit.VerifySession(ctx, session.GonsuState)
if errors.Is(err, auth.ErrSessionExpired) {
    // matikan sesi, arahkan ke /auth/gonsu/login
}
session.GonsuState = state // SIMPAN: refresh token dapat dirotasi
```

GONSU yang menolak mematikan sesi seketika. GONSU yang tak terjangkau tidak:
sesi bertahan selama masa tenggang, bawaannya satu shift kerja.

## Hak pakai

```go
license := kit.License()

if !license.Allowed(ctx) {
    // tolak transaksi baru; biarkan data dibaca dan diekspor
}
if license.Feature(ctx, "garment.pattern_studio") { /* ... */ }
if max, unlimited := license.Limit(ctx, "users.max"); !unlimited && activeUsers >= max {
    // kuota habis
}
status := license.Status(ctx) // untuk banner: Phase, PlanName, ExpiresAt
```

Kunci yang tidak dibawa lisensi berarti **tidak** — fitur mati, batas nol — dan
dicatat sekali di log. Kunci yang salah ketik atau belum didaftarkan di katalog
GONSU mematikan fiturnya tanpa galat apa pun, jadi periksa lognya.

Paket, harga, dan add-on tidak pernah sampai ke produk. Yang sampai hanya kunci
dan nilainya; mengubah katalog di GONSU tidak menuntut rilis produk.

| | cloud | self-host |
|---|---|---|
| sumber | lease bertanda tangan, di volume lisensi | agent di jaringan lokal |
| `Allowed` | **selalu true** — GONSU menangguhkan aplikasi yang langganannya berhenti | mengikuti lease dan masa tenggangnya |
| GONSU tak terjangkau | nilai terakhir tetap dipakai | nilai terakhir, dinilai ulang terhadap masa berlakunya |
| belum ada nilai sama sekali | semua diizinkan, `Phase` = `UNLICENSED` atau `NOT_ACTIVATED` | semua diizinkan sampai agent terjawab, `Phase` = `UNREACHABLE` |

## Memberi akses login

```go
max, unlimited := kit.License().Limit(ctx, "users.max")
if !unlimited && activeUsers >= max {
    return errKuotaHabis
}
id, err := kit.Identities().Provision(ctx, email, name)
var rejected *web.IdentityError
if errors.As(err, &rejected) {
    // rejected.Kind: unavailable, rate_limited, invalid_email, revoked, ...
    // rejected.Message aman ditampilkan
}
db.CreateUser(ctx, id.Subject, email, role)
// id.TemporaryPassword: tampilkan SEKALI kepada admin, jangan simpan.
```

## Beberapa replica

State login disimpan di memori, cukup untuk satu replica. Isi `Options.Pending`
dengan penyimpanan di database Anda bila aplikasi berjalan di beberapa replica.

## Environment

Diisi GONSU. Produk tidak menulis satu pun di antaranya.

| | cloud | self-host |
|---|---|---|
| login | `GONSU_OIDC_ISSUER`, `GONSU_OIDC_CLIENT_ID`, `GONSU_OIDC_CLIENT_SECRET`, `GONSU_OIDC_REDIRECT_URI` | `GONSU_AGENT_URL` |
| lisensi | `GONSU_BASE_URL`, `GONSU_INSTALLATION_ID`, `GONSU_STATE_DIR`, `GONSU_ACTIVATION_TOKEN`, `GONSU_LICENSE_PUBLIC_KEYS` | `GONSU_AGENT_URL` |
| beri akses | `GONSU_IDENTITY_TOKEN` | `GONSU_AGENT_URL` |
| pemilik | `GONSU_ORGANIZATION_ID`, `GONSU_OWNER_SUBJECT` | `GONSU_AGENT_URL` |

Paket self-host lama yang hanya mengisi `GONSU_LICENSE_URL` dan
`GONSU_OIDC_URL` tetap dikenali.
