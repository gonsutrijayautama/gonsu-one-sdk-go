// Package auth adalah SDK login untuk produk yang dijual GONSU One.
//
// Ia mengurus satu hal, dan hanya satu: membuktikan SIAPA orang yang sedang
// masuk. Produk yang memutuskan orang itu menjadi apa di dalamnya, dan produk
// yang menghitung kuotanya sendiri.
//
// # Kenapa ini ada
//
// Alur OIDC terlihat sederhana dan salahnya TIDAK TERLIHAT. Lupa membandingkan
// `state`, lupa `nonce`, lupa memverifikasi `aud`, lupa memeriksa tenant —
// login tetap berhasil, pengguna tetap masuk, dan tidak ada yang gagal sampai
// ada yang memanfaatkannya. Kode dengan sifat seperti itu tidak boleh ditulis
// ulang di setiap produk.
//
// # Satu module dengan SDK lisensi, paket yang terpisah
//
// Keduanya berlawanan di dua hal, dan karena itu tidak berbagi kode:
//
//   - saat GONSU tak terjangkau: lisensi WAJIB tetap bekerja, login baru
//     mustahil;
//   - yang dibuktikan: lisensi membuktikan sebuah lease, auth membuktikan sesi
//     seseorang.
//
// Sebelum v1.1.0 package ini module tersendiri (gonsu-one-sdk-go-auth).
// Keduanya kini satu module supaya produk cukup satu `go get` dan satu tag;
// produk yang tidak mengimpor package ini tidak ikut mengompilasinya.
//
// Package ini NOL DEPENDENCY di luar standard library, sama seperti paket
// lisensi: verifikasi JWT ditulis di sini, bukan ditarik. Yang dibutuhkannya
// hanya ECDSA dan SHA-2, dan keduanya ada di standard library.
//
// # Yang TIDAK ada di sini
//
// Reset dan lupa sandi. Sandi berada di penyedia identitas, dan layar sandi di
// dalam produk MELATIH pengguna mengetik sandi GONSU-nya di domain produk —
// begitu kebiasaan itu ada, memalsukan layar login tinggal menyalin
// tampilannya. Yang disediakan hanyalah tautan.
package auth
