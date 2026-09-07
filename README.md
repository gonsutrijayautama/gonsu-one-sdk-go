# GONSU One — SDK Lisensi (Go)

SDK yang ditanam **di dalam** produk yang dijual GONSU. Ia menjawab satu
pertanyaan: apa yang boleh dijalankan instalasi ini, dan sampai kapan.

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
	// yang menempelkannya dengan tangan. Di self-host, installer
	// yang menuliskannya ke.env dari token yang diberikan Portal.
	//
	// Dari sudut pandang produk, keduanya sama: baca environment.
	InstallationID: os.Getenv("GONSU_INSTALLATION_ID"),
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

Produk Anda selalu membaca environment. Yang berbeda hanyalah siapa yang
mengisinya, dan itu bukan urusan produk:

| | Cloud (GONSU yang memasang) | Self-host |
|---|---|---|
| `GONSU_INSTALLATION_ID` | Secret aplikasi, dibuat GONSU saat deploy | installer menulis ke `.env` |
| `GONSU_BASE_URL` | Secret aplikasi, alamat DALAM cluster | `.env` |
| `GONSU_ACTIVATION_TOKEN` | Secret aplikasi, hanya saat memang dibutuhkan | dari Portal, sekali pakai |
| `GONSU_STATE_DIR` | volume yang bertahan, disiapkan GONSU | direktori di host |
| kunci publik GONSU | **ditanam saat build**, tidak pernah disuntikkan | sama |

Karena itu satu binary berjalan di kedua mode tanpa jalur kode yang berbeda —
dan itu memang tujuannya: jalur yang hanya dipakai satu mode adalah jalur yang
tidak pernah teruji.

## Yang perlu diketahui operator

- `StateDir` berisi kunci privat instalasi (`installation.key`, 0600) dan cache
 lease. Ia **harus bertahan antar restart**; kalau tidak, instalasi kehilangan
 identitasnya setiap kali produk dimulai ulang.
- Jangan menyalin `StateDir` ke mesin lain. Lease terikat pada satu
 `installation_id` dan SDK menolak lease milik instalasi lain.
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
export GONSU_ACTIVATION_TOKEN=...
export GONSU_VENDOR_KEY=...

go run./example/selfhost activate
go run./example/selfhost run # matikan API GONSU: ia tetap berjalan
go run./example/selfhost status # sekali baca, tanpa jaringan
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

Pelanggan dengan perjanjian berlangganan GONSU One yang masih berlaku boleh
memakai, mengubah, dan menautkannya ke dalam produknya, semata-mata untuk
berinteraksi dengan layanan GONSU One. Selengkapnya di [LICENSE](LICENSE).

Hak Cipta (c) 2026 PT Gonsu Trijaya Utama.
