package certcache

import (
	"context"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/chacha20poly1305"
)

type EncryptedCache struct {
	aead cipher.AEAD
	next autocert.Cache
}

func NewEncryptedCache(key []byte, next autocert.Cache) (*EncryptedCache, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return &EncryptedCache{
		aead: aead,
		next: next,
	}, nil
}

func (c *EncryptedCache) Get(ctx context.Context, key string) ([]byte, error) {
	encryptedData, err := c.next.Get(ctx, key)
	if err != nil {
		return nil, err
	}

	if len(encryptedData) < c.aead.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	// Split nonce and ciphertext.
	nonce, ciphertext := encryptedData[:c.aead.NonceSize()], encryptedData[c.aead.NonceSize():]

	// Decrypt the data and check it wasn't tampered with.
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, []byte(key))
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func (c *EncryptedCache) Put(ctx context.Context, key string, data []byte) error {
	// Select a random nonce, and leave capacity for the ciphertext.
	nonce := make([]byte, c.aead.NonceSize(), c.aead.NonceSize()+len(data)+c.aead.Overhead())
	if _, err := cryptorand.Read(nonce); err != nil {
		return err
	}

	// Encrypt the message and append the ciphertext to the nonce.
	encryptedData := c.aead.Seal(nonce, nonce, data, []byte(key))

	return c.next.Put(ctx, key, encryptedData)
}

func (c *EncryptedCache) Delete(ctx context.Context, key string) error {
	return c.next.Delete(ctx, key)
}

func (c *EncryptedCache) Close() error {
	if cacheCloser, ok := c.next.(io.Closer); ok {
		return cacheCloser.Close()
	}
	return nil
}
