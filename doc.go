// Package gonsu adalah SDK yang ditanam DI DALAM produk yang dijual GONSU.
//
// Ia berjalan di jaringan pelanggan — untuk self-host, di jaringan yang sama
// sekali tidak dikuasai GONSU. Seluruh bentuk package ini mengikuti satu fakta
// itu:
//
// - Nol dependency di luar standard library, dan module tersendiri. Produk
// pelanggan tidak boleh terpaksa menarik pgx, chi, atau NATS hanya untuk
// menanyakan apa yang boleh dijalankannya.
//
// - Lease disimpan ke disk dan diverifikasi terhadap kunci publik GONSU yang
// ditanam di dalam binary. Instalasi yang tidak dapat menghubungi platform
// tetap tahu apa yang boleh dijalankannya, dan tetap dapat menolak lease
// yang diubah orang.
//
// - Yang menentukan boleh-tidaknya sebuah instalasi berjalan adalah UMUR
// lease, bukan keberhasilan heartbeat terakhir. Heartbeat yang gagal adalah
// peristiwa jaringan; lease yang kedaluwarsa adalah keputusan bisnis.
//
// Alur pemakaian di dalam produk:
//
//	license, err := gonsu.Open(gonsu.Options{
//		BaseURL: "https://api.gonsu.cloud",
//		StateDir: "/var/lib/produk/lisensi",
//		VendorKeys: gonsu.MustVendorKeys(kunciSaatIni, kunciSebelumnya),
//	})
//	...
//	if !license.Status().Allowed() { /* produk memutuskan sendiri apa artinya */ }
//
// Yang TIDAK ada di sini, dan itu disengaja: peran pengguna. GONSU tidak pernah
// mengetahui peran di dalam produk, dan SDK ini tidak menyediakan tempat untuk
// menyimpannya.
package gonsu
