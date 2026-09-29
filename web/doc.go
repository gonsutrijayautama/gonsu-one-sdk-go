// Package web adalah kit untuk produk web Go yang dijual di GONSU One.
//
// Paket lisensi (akar module) dan paket auth adalah INTI: mereka mengurus
// protokol. Kit ini mengurus perekat di atasnya — hal-hal yang dulu ditulis
// setiap produk sendiri, dan yang salahnya tidak terlihat:
//
//   - membaca nilai GONSU dari environment dan memutuskan mode cloud atau
//     self-host, sehingga produk tidak pernah bercabang menurut mode;
//   - jalur login milik GONSU di bawah /auth/gonsu/, termasuk penyimpanan
//     state login di server, pencegahan open redirect, dan pemeriksaan bahwa
//     orang yang terbukti login memang diberi akses di pemasangan ini;
//   - admin pertama dari pemilik bisnis, hanya selama belum ada seorang pun;
//   - hak pakai: Allowed, Feature, Limit — dari agent di self-host, dari lease
//     di cloud;
//   - "beri akses login": meminta akun GONSU untuk seseorang;
//   - "Akun saya", lupa sandi, ganti akun, dan keluar.
//
// Yang TETAP milik produk: tabel pengguna dan perannya, sesi dan cookie-nya
// sendiri, layar "beri akses login", dan di mana hak pakai ditegakkan. Kit
// meminta produk menyerahkan pengait (Hooks), bukan konfigurasi.
//
// # Mode
//
// GONSU_AGENT_URL terisi berarti self-host: lisensi, login, dan pemberian akses
// dibaca dari agent di jaringan lokal. GONSU_LICENSE_URL dan GONSU_OIDC_URL
// dari paket self-host lama juga dikenali. Selain itu cloud: nilainya datang
// dari Secret aplikasi.
//
// # Di cloud, berhenti-tidaknya aplikasi urusan GONSU
//
// Langganan yang berhenti dijawab GONSU dengan menangguhkan workload. Karena
// itu di cloud License.Allowed selalu true, dan lease hanya membawa NILAI hak
// pakai. Gangguan jaringan ke GONSU tidak pernah mengunci pelanggan cloud.
package web
