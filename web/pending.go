package web

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/gonsutrijayautama/gonsu-one-sdk-go/auth"
)

// PendingLogin adalah login yang sudah dimulai dan belum kembali.
type PendingLogin struct {
	// Auth adalah state, nonce, dan verifier PKCE — ketiganya wajib disimpan di
	// sisi server, bukan di tempat yang dapat dibaca atau ditulis pengunjung.
	Auth auth.Pending
	// Next adalah jalur di aplikasi ini yang dituju sesudah login. Sudah
	// diperiksa kit: hanya jalur lokal, bukan alamat lain.
	Next string
	// ExpiresAt adalah batas login ini boleh diselesaikan.
	ExpiresAt time.Time
}

// PendingStore menyimpan login yang sedang berjalan, dengan kunci acak yang
// dibawa cookie pengunjung.
//
// Bawaannya di memori, dan itu cukup untuk satu replica — bentuk aplikasi
// cloud GONSU. Produk yang berjalan di beberapa replica, atau yang ingin login
// bertahan melewati restart, mengisi Options.Pending dengan penyimpanan di
// databasenya sendiri.
type PendingStore interface {
	// Put menyimpan login. key sudah berupa hash; nilai mentahnya hanya ada di
	// cookie pengunjung.
	Put(ctx context.Context, key string, login PendingLogin) error
	// Take mengambil sekaligus MENGHAPUS login. Login yang sama tidak boleh
	// dapat diselesaikan dua kali. Tidak ada atau kedaluwarsa berarti found
	// false tanpa galat.
	Take(ctx context.Context, key string) (login PendingLogin, found bool, err error)
}

// memoryPendingLimit membatasi login yang tersimpan sekaligus. Tanpa batas,
// siapa pun dapat mengisi memori aplikasi dengan membuka /auth/gonsu/login
// berulang-ulang.
const memoryPendingLimit = 10_000

// errPendingFull berarti penyimpanan bawaan penuh oleh login yang belum
// kedaluwarsa.
var errPendingFull = errors.New("terlalu banyak login yang sedang berjalan")

type memoryPending struct {
	now func() time.Time

	mu    sync.Mutex
	items map[string]PendingLogin
}

func newMemoryPending() *memoryPending {
	return &memoryPending{now: time.Now, items: map[string]PendingLogin{}}
}

func (m *memoryPending) Put(_ context.Context, key string, login PendingLogin) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.items) >= memoryPendingLimit {
		now := m.now()
		for k, item := range m.items {
			if !now.Before(item.ExpiresAt) {
				delete(m.items, k)
			}
		}
		if len(m.items) >= memoryPendingLimit {
			return errPendingFull
		}
	}
	m.items[key] = login
	return nil
}

func (m *memoryPending) Take(_ context.Context, key string) (PendingLogin, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	login, ok := m.items[key]
	if !ok {
		return PendingLogin{}, false, nil
	}
	delete(m.items, key)
	if !m.now().Before(login.ExpiresAt) {
		return PendingLogin{}, false, nil
	}
	return login, true, nil
}
