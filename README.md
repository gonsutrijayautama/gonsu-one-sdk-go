# GONSU One — SDK Go

**Untuk tim yang membangun produk untuk dijual di GONSU One.**

Satu module, beberapa paket:

| paket | untuk |
|---|---|
| `github.com/gonsutrijayautama/gonsu-one-sdk-go` | lisensi — halaman ini |
| `github.com/gonsutrijayautama/gonsu-one-sdk-go/auth` | login pengguna produk — [auth/README.md](auth/README.md) |

Paket yang tidak Anda impor tidak ikut dikompilasi ke binary Anda.

## Lisensi

Paket lisensi ditanam **di dalam** produk Anda. Ia menjawab satu pertanyaan: apa
yang boleh dijalankan pemasangan ini, dan sampai kapan.

Yang TIDAK perlu Anda kerjakan sendiri: menerbitkan pemasangan, menyerahkan
token aktivasi, atau menerapkan lisensi ketika ada yang berlangganan. Platform
yang mengurusnya — produk Anda cukup membaca `Status()`.

```
go get github.com/gonsutrijayautama/gonsu-one-sdk-go
```

Nol dependency di luar standard library, dan module tersendiri — produk Anda
tidak ikut menarik dependency platform GONSU.

## Cara kerja

GONSU menerbitkan **lease**: pernyataan bertanda tangan Ed25519 yang membawa
salinan hak pakai beserta masa berlakunya. SDK menyimpannya ke disk dan
memverifikasinya terhadap kunci publik GONSU yang ditanam di dalam binary Anda.

Akibatnya, instalasi yang tidak dapat menghubungi GONSU **tetap tahu** apa yang
boleh dijalankannya — dan tetap dapat menolak lease yang diubah orang.

Dua sumbu keputusan, sengaja tidak digabung:

| | arti |
|---|---|
| `Status.Lease.Granted` | langganan sedang memberi hak pakai |
| `Status.State` | kesegaran lease: `active`, `grace`, `expired`, `unknown` |

`Status.Allowed()` menggabungkan keduanya untuk produk yang hanya ingin satu
jawaban. Masa tenggang termasuk diizinkan: mematikan pelanggan pada detik lease
kedaluwarsa adalah reaksi yang tidak dapat dibatalkan terhadap sesuatu yang
paling sering hanyalah gangguan jaringan.

## Pemakaian

```go
// Kunci publik GONSU DITANAM saat build, bukan dibaca dari konfigurasi —
// kunci yang dapat diganti pelanggan membuat seluruh tanda tangan tidak ada
// gunanya. JAMAK, dipisah koma; lihat bagian "Rotasi kunci".
//
//	go build -ldflags "-X main.vendorKeys=$(cat kunci-publik.txt)"
var vendorKeys string

license, err := gonsu.Open(gonsu.Options{
	BaseURL: "https://api.gonsu.cloud",
	// Di cloud, GONSU mengisinya sendiri lewat Secret aplikasi — tidak ada
	// yang menempelkannya dengan tangan. Di paket self-host, SDK ini
	// dijalankan agent, bukan produk; lihat "Dari mana nilainya datang".
	InstallationID: os.Getenv("GONSU_INSTALLATION_ID"),
	// Kode produk Anda di katalog GONSU. Tulis di sini, jangan dari
	// konfigurasi; lihat "Mengikat lease pada produk Anda".
	ProductCode: "garment",
	StateDir: "/var/lib/produk-anda/lisensi", // wajib bertahan antar restart
	VendorKeys: gonsu.MustVendorKeys(strings.Split(vendorKeys, ",")...),
	Version: version,
	Platform: runtime.GOOS + "/" + runtime.GOARCH,
	Logger: logger,
})
if err != nil {
	return err
}

// Sekali seumur instalasi, dengan token aktivasi dari Portal.
if err := license.Activate(ctx, token); err != nil {
	return err
}

// Menjaga lease tetap segar. Kegagalan heartbeat TIDAK membatalkan lease yang
// sudah dipegang.
go license.Run(ctx)

// Saat produk DICOPOT. Tanpa ini, pemasangan yang sudah tidak ada tetap
// terhitung aktif — dan pada produk yang dijual per pemasangan, pelanggan
// membayar sesuatu yang sudah ia hapus.
defer license.Deactivate(context.WithoutCancel(ctx))

// Di dalam handler mana pun — murah, tidak menyentuh jaringan.
status := license.Status()
if !status.Allowed() {
	return errStatusLisensi(status)
}
if status.Feature("backup.enabled") { /*... */ }
if batas, tanpaBatas := status.Limit("users.max"); !tanpaBatas && jumlah >= batas {
	return errKuotaHabis
}
```

`Open` **tidak menyentuh jaringan**. Produk yang dimulai saat GONSU tidak dapat
dihubungi tetap dapat berjalan dari lease di disk — itulah seluruh gunanya lease
disimpan.

## Mengikat lease pada produk Anda

Seluruh produk GONSU diverifikasi dengan **kunci yang sama**. Tanda tangan
membuktikan lease berasal dari GONSU, tetapi tidak membuktikan lease itu untuk
produk **Anda**: tanpa pemeriksaan tambahan, lease sah milik produk lain dari
pelanggan yang sama — id pemasangan dan direktori state-nya disalin — diterima
begitu saja.

`Options.ProductCode` menutupnya. Terisi berarti lease yang `product_code`-nya
berbeda **ditolak**:

| Saat | Akibat |
|---|---|
| `Open` memuat lease dari disk | lease diabaikan (tidak dihapus), status `unknown` |
| `Activate` / `Refresh` menerima lease | lease tidak dipakai dan tidak disimpan; yang sudah dipegang tetap |
| `InstallOffline` | galat `ErrLeaseProdukLain`, berkas tidak disimpan |

Penolakan dicatat di `Logger` sebagai galat. `ProductCode` yang salah ketik
karena itu terlihat sebagai produk yang tidak pernah aktif — periksa lognya.

> **`ProductCode` kosong berarti `product_code` tidak diperiksa sama sekali.**
> Itu perilaku SDK sebelum opsi ini ada, dipertahankan supaya produk yang sudah
> terpasang tidak berhenti hanya karena SDK-nya diperbarui. Jangan mengandalkan
> keadaan itu: isi `ProductCode` pada rilis produk Anda berikutnya.

Tulis kodenya di dalam kode produk, bukan di environment — alasannya sama dengan
kunci publik GONSU: nilai yang dapat diganti pemilik server tidak menjaga apa
pun dari pemilik server.

## Dari mana kunci publik GONSU didapat

`VendorKeys` ditanam saat build, diambil dari OpenBao — sumber yang sama dengan
pipeline GONSU sendiri:

```sh
curl -sS -H "X-Vault-Token: $GONSU_ONE_OPENBAO_TOKEN" \
  "$GONSU_ONE_OPENBAO_ADDRESS/v1/transit/keys/license-signing-v1" | python3 -c '
import json, sys
data = json.load(sys.stdin)["data"]
minimum = int(data.get("min_decryption_version") or 1)
versi = sorted((int(v) for v in data["keys"] if int(v) >= minimum), reverse=True)
print(",".join(data["keys"][str(v)]["public_key"] for v in versi))'
```

**Ambil SELURUH versi, dipisah koma — bukan yang terbaru saja.** Alasannya di
bagian berikut; mengabaikannya berarti produk Anda berhenti memverifikasi pada
hari GONSU berpindah kunci.

Perintah yang sama sudah ada di `scripts/selfhost-package.sh` pada repository
platform, dan pipeline build produk Anda dapat menyalinnya.

## TLS wajib, kecuali ke diri sendiri

`Open` **menolak** `http://` ke host mana pun selain loopback:

```
https://api.gonsu.cloud     ✓
http://localhost:8091       ✓   pengembangan
http://127.0.0.1:8091       ✓
http://api.gonsu.cloud      ✗   ErrInsecureBaseURL
```

SDK tidak punya — dan tidak boleh punya — gagasan tentang "production"; ia
hanya tahu alamat yang Anda berikan. Yang dapat diputuskannya sendiri adalah
aturan yang tidak butuh konfigurasi: **teks polos hanya boleh menuju diri
sendiri.**

Tidak ada flag `AllowInsecure`, dan itu disengaja. Flag yang harus diingat
seseorang adalah flag yang menyala di production justru karena ia menyala di
laptop lebih dulu, lalu ikut tersalin.

Yang dijaga bukan kerahasiaan lease — ia bertanda tangan dan sudah tahan
diubah. Yang dijaga adalah **token aktivasi** yang melintas di badan request.
Jaringan di dalam cluster pun bukan alasan mengirimkannya sebagai teks polos.

## Rotasi kunci — baca ini sebelum rilis pertama

`VendorKeys` **jamak**, dan itu bukan kelebihan melainkan keharusan.

Kunci penandatangan GONSU akan dirotasi suatu hari — terjadwal atau karena
insiden. Produk yang hanya memegang satu kunci **berhenti memverifikasi apa pun
pada detik rotasi**, dan sebagian pemasangan berada di server pelanggan yang
tidak dapat diperbarui hari itu juga.

Urutan rotasi yang benar, dan urutannya menentukan:

1. GONSU menerbitkan kunci baru, **masih menandatangani dengan yang lama**;
2. produk dibangun ulang menanam kunci baru **bersama** yang lama;
3. seluruh pemasangan menerima versi itu;
4. **baru** GONSU mulai menandatangani dengan kunci baru;
5. kunci lama dicabut paling akhir.

Sebuah lease diterima bila **salah satu** kunci yang Anda tanam memverifikasinya.
Seluruhnya kunci GONSU, jadi tidak ada yang melemah — yang membuktikan tetap
tanda tangannya.

`scripts/selfhost-package.sh` sudah menanam seluruh versi yang masih dipercaya,
dipisah koma. Kalau Anda membangun produk sendiri, ambil daftarnya dari GONSU
dan jangan pernah menanam hanya yang terbaru.

## Jam yang meleset

`Options.ClockSkew` (bawaan 5 menit) memberi kelonggaran saat menilai
kedaluwarsa. Arahnya **hanya memperpanjang**, tidak pernah memperpendek.

Sengaja begitu: kesalahan karena longgar berarti produk melayani beberapa menit
lebih lama; kesalahan karena ketat berarti pelanggan yang membayar mendadak
berhenti dilayani karena jam servernya maju. Di server yang tidak pernah
menyentuh NTP — dan yang air-gapped memang tidak — jam melenceng tanpa ada yang
menyadari.

## Versi skema lease

`Lease.SchemaVersion` menyatakan bentuk lease. Kontraknya mengikat **GONSU**,
bukan Anda: naiknya versi skema wajib tetap dapat dibaca pembaca lama. GONSU
boleh menambah field; ia tidak boleh mengubah arti field yang sudah ada, dan
tidak boleh menambahkan pembatasan yang hanya dipahami pembaca baru.

Karena itu SDK yang menemukan versi lebih tinggi **tidak berhenti melayani** —
ia menandainya lewat `Status.SchemaAhead`. Catat itu sekali di log Anda sebagai
pertanda SDK layak diperbarui; **jangan** tunjukkan kepada pengguna akhir, dan
jangan jadikan alasan berhenti.

## Server tanpa internet (enterprise offline)

Untuk pemasangan yang tidak pernah dapat menghubungi GONSU sama sekali:

```go
// 1. Di server pelanggan — kunci privat lahir di sini dan tidak pernah keluar.
fmt.Println(license.PublicKey()) // kirim ini ke GONSU lewat jalur apa pun

// 2. GONSU menerbitkan lisensi yang terikat pada kunci itu.

// 3. Kembali di server pelanggan, tanpa jaringan sama sekali:
var signed gonsu.SignedLease
json.Unmarshal(berkasLisensi, &signed)
if err := license.InstallOffline(signed); err != nil {
	return err // ditolak = berkasnya berubah, atau untuk mesin lain
}
```

Lisensi offline **terikat pada satu mesin** dan **tidak dapat dicabut** — hanya
masa berlakunya yang menghentikannya. Rinciannya di dokumentasi enterprise offline GONSU.

## Menguji produk Anda tanpa GONSU

`StatusAt` diekspor justru untuk ini: susun `Lease` apa pun, lalu nilai
statusnya pada waktu apa pun.

```go
lease := gonsu.Lease{
	Granted: true, PlanCode: "pro",
	Entries: []gonsu.GrantEntry{{Key: "users.max", ValueType: "integer", Integer: 25}},
	ExpiresAt: waktuUji.Add(time.Hour), GraceUntil: waktuUji.Add(72 * time.Hour),
}
status := gonsu.StatusAt(lease, waktuUji, gonsu.DefaultClockSkew)
```

Saran yang menghemat banyak waktu kemudian: **jangan bergantung pada
`*gonsu.License` di dalam kode bisnis Anda.** Definisikan interface sempit milik
Anda sendiri — biasanya cukup satu method — dan biarkan `*gonsu.License`
memenuhinya:

```go
type Lisensi interface{ Status() gonsu.Status }
```

Dengan begitu seluruh kode Anda dapat diuji tanpa berkas, tanpa kunci, dan tanpa
GONSU.

## Dari mana nilainya datang

Produk Anda selalu membaca environment, tetapi isinya BERBEDA per mode. Di cloud
produk sendiri yang memakai SDK ini. Di paket self-host (`deploy/selfhost`) yang
memakainya adalah **agent** di sebelah produk: installation ID, token aktivasi,
dan kunci pemasangan berhenti di agent, dan produk hanya menerima alamat agent.

| | Cloud (GONSU yang memasang) | Self-host (paket `gonsu-selfhost`) |
|---|---|---|
| `GONSU_INSTALLATION_ID` | Secret aplikasi, dibuat GONSU saat deploy | dipegang agent, tidak sampai ke produk |
| `GONSU_BASE_URL` | Secret aplikasi, alamat DALAM cluster | dipegang agent |
| `GONSU_ACTIVATION_TOKEN` | Secret aplikasi, hanya saat memang dibutuhkan | dipakai `install.sh` untuk agent, lalu dibuang |
| `GONSU_STATE_DIR` | volume yang bertahan, disiapkan GONSU | volume milik agent |
| `GONSU_ORGANIZATION_ID`, `GONSU_OWNER_SUBJECT`, `GONSU_OWNER_EMAIL` | Secret aplikasi — pemilik pemasangan, untuk admin pertama | tidak ada; field `organization_id` dan `owner` pada jawaban agent |
| `GONSU_IDENTITY_TOKEN` | Secret aplikasi — bearer SEMPIT untuk `POST $GONSU_BASE_URL/license/v1/identities` | tidak ada; produk memanggil `POST http://agent:8099/v1/identities` |
| `GONSU_LICENSE_URL` | tidak ada | `http://agent:8099/v1/license` — hak pakai yang sudah diverifikasi agent |
| `GONSU_OIDC_URL` | tidak ada; login memakai `GONSU_OIDC_*` (lihat SDK login) | `http://agent:8099/v1/oidc` |
| kunci publik GONSU | **ditanam saat build**, tidak pernah disuntikkan | ditanam di agent |

Keempat variabel pemilik dan identitas dapat TIDAK ADA — bukan kosong. Pemilik
yang belum tercatat tidak ditulis ke Secret sama sekali, dan token identitas
yang gagal diterbitkan saat deployment ikut hilang sampai deployment
berikutnya. Periksa ada-tidaknya variabel, bukan isinya.

Produk yang dijual untuk kedua mode karena itu punya dua jalur baca hak pakai:
SDK ini di cloud, `GONSU_LICENSE_URL` di self-host. Bedakan keduanya dari
ada-tidaknya `GONSU_LICENSE_URL`: ada berarti self-host (baca hak pakai dan
daftarkan karyawan lewat agent), tidak ada berarti cloud (pakai SDK ini).

Di jalur self-host, **bandingkan sendiri `product_code`** pada jawaban agent
dengan kode produk Anda, dan perlakukan yang berbeda sebagai tidak berlisensi —
padanan `ProductCode` di atas. Agent satu image untuk semua produk; ia hanya
memeriksa produk bila `GONSU_PRODUCT_CODE` diisi di `.env` server, dan nilai itu
dikuasai administrator server.

## Yang perlu diketahui operator

- `StateDir` berisi kunci privat instalasi (`installation.key`, 0600) dan cache
 lease. Ia **harus bertahan antar restart**; kalau tidak, instalasi kehilangan
 identitasnya setiap kali produk dimulai ulang.
- Jangan menyalin `StateDir` ke mesin lain. Lease terikat pada satu
 `installation_id` dan SDK menolak lease milik instalasi lain — dan, bila
 `ProductCode` diisi, lease untuk produk lain.
- Pencabutan lisensi berlaku ketika lease habis, bukan seketika. Dengan angka
 bawaan GONSU, jaraknya sampai 4 hari (masa berlaku 24 jam + tenggang 3 hari).
- `Deactivate` melepaskan pemasangan di GONSU dan membuang lease lokalnya. Lease
 lokal dibuang **meskipun** GONSU tidak dapat dihubungi: yang diputuskan
 pelanggan adalah mencopot, dan jaringan yang putus tidak membatalkannya.

## Contoh lengkap

`example/selfhost` adalah produk contoh terkecil yang mungkin — ia tidak
melakukan apa pun selain melaporkan apa yang boleh dijalankannya:

```bash
export GONSU_BASE_URL=https://api.gonsu.cloud
export GONSU_INSTALLATION_ID=ins_...
export GONSU_PRODUCT_CODE=garment   # contoh membacanya dari sini; produk sungguhan menulisnya di kode
export GONSU_ACTIVATION_TOKEN=...
export GONSU_VENDOR_KEY=...

go run ./example/selfhost activate
go run ./example/selfhost run # matikan API GONSU: ia tetap berjalan
go run ./example/selfhost status # sekali baca, tanpa jaringan
```

## Peran pengguna tidak ada di sini

GONSU tidak pernah mengetahui peran di dalam produk Anda, dan SDK ini tidak
menyediakan tempat untuk menyimpannya. Yang GONSU sebut adalah ORANGNYA —
`Response.Owner`, untuk menetapkan administrator pertama — bukan perannya.
Produk Anda yang memutuskan orang itu menjadi apa di dalamnya.

## Lisensi

**Bukan perangkat lunak sumber terbuka.** Kode sumbernya dipublikasikan agar
dapat diperiksa dan diambil dengan perkakas Go yang lazim — bukan agar dapat
dipakai bebas.

Perkakas internal untuk tim yang membangun produk bagi platform GONSU One.
Pembeli produk tersebut menerima bentuk terkompilasinya dan tidak membutuhkan
lisensi tersendiri. Selengkapnya di [LICENSE](LICENSE).

Hak Cipta (c) 2026 PT Gonsu Trijaya Utama.
