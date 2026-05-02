package securestorage

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestStorage(t *testing.T) *FileStorage {
	t.Helper()
	dir := t.TempDir()
	return NewFileStorage(dir)
}

func TestStoreAndRetrieve(t *testing.T) {
	fs := newTestStorage(t)
	require.NoError(t, fs.Store("key1", "value1"))
	val, err := fs.Retrieve("key1")
	require.NoError(t, err)
	assert.Equal(t, "value1", val)
}

func TestRetrieveNonExistent(t *testing.T) {
	fs := newTestStorage(t)
	val, err := fs.Retrieve("missing")
	require.NoError(t, err)
	assert.Equal(t, "", val)
}

func TestUpdateValue(t *testing.T) {
	fs := newTestStorage(t)
	require.NoError(t, fs.Store("key", "initial"))
	require.NoError(t, fs.Store("key", "updated"))
	val, err := fs.Retrieve("key")
	require.NoError(t, err)
	assert.Equal(t, "updated", val)
}

func TestDelete(t *testing.T) {
	fs := newTestStorage(t)
	require.NoError(t, fs.Store("key", "value"))
	require.NoError(t, fs.Delete("key"))
	val, err := fs.Retrieve("key")
	require.NoError(t, err)
	assert.Equal(t, "", val)
}

func TestDeleteNonExistent(t *testing.T) {
	fs := newTestStorage(t)
	assert.NoError(t, fs.Delete("missing"))
}

func TestContains(t *testing.T) {
	fs := newTestStorage(t)
	require.NoError(t, fs.Store("key", "value"))
	exists, err := fs.Contains("key")
	require.NoError(t, err)
	assert.True(t, exists)
	exists, err = fs.Contains("missing")
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestListKeys(t *testing.T) {
	fs := newTestStorage(t)
	require.NoError(t, fs.Store("a", "1"))
	require.NoError(t, fs.Store("b", "2"))
	require.NoError(t, fs.Store("c", "3"))
	keys, err := fs.ListKeys()
	require.NoError(t, err)
	assert.Len(t, keys, 3)
	assert.ElementsMatch(t, []string{"a", "b", "c"}, keys)
}

func TestClear(t *testing.T) {
	fs := newTestStorage(t)
	require.NoError(t, fs.Store("a", "1"))
	require.NoError(t, fs.Store("b", "2"))
	require.NoError(t, fs.Clear())
	keys, err := fs.ListKeys()
	require.NoError(t, err)
	assert.Empty(t, keys)
}

func TestIsSecure(t *testing.T) {
	fs := newTestStorage(t)
	secure, err := fs.IsSecure()
	require.NoError(t, err)
	assert.True(t, secure)
}

func TestStoreCredentials(t *testing.T) {
	fs := newTestStorage(t)
	require.NoError(t, fs.StoreCredentials("webdav", "user", "pass"))
	u, p, err := fs.RetrieveCredentials("webdav")
	require.NoError(t, err)
	assert.Equal(t, "user", u)
	assert.Equal(t, "pass", p)
}

func TestCredentialsWithColons(t *testing.T) {
	fs := newTestStorage(t)
	require.NoError(t, fs.StoreCredentials("webdav", "domain:user", "pass:word:with:colons"))
	u, p, err := fs.RetrieveCredentials("webdav")
	require.NoError(t, err)
	assert.Equal(t, "domain:user", u)
	assert.Equal(t, "pass:word:with:colons", p)
}

func TestStoreToken(t *testing.T) {
	fs := newTestStorage(t)
	require.NoError(t, fs.StoreToken("dropbox", "sl.test_token_abc"))
	tok, err := fs.RetrieveToken("dropbox")
	require.NoError(t, err)
	assert.Equal(t, "sl.test_token_abc", tok)
}

func TestStorePrivateKey(t *testing.T) {
	fs := newTestStorage(t)
	pk := "-----BEGIN RSA PRIVATE KEY-----\ntest_key_data\n-----END RSA PRIVATE KEY-----"
	require.NoError(t, fs.StorePrivateKey("sftp", pk))
	retrieved, err := fs.RetrievePrivateKey("sftp")
	require.NoError(t, err)
	assert.Equal(t, pk, retrieved)
}

func TestEncryptionProducesUniqueOutput(t *testing.T) {
	fs := newTestStorage(t)
	require.NoError(t, fs.Store("key", "same_value"))
	data1, _ := os.ReadFile(fs.dataFile)
	require.NoError(t, fs.Store("key", "same_value"))
	data2, _ := os.ReadFile(fs.dataFile)
	assert.NotEqual(t, data1, data2)
}

func TestPersistenceAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	fs1 := NewFileStorage(dir)
	require.NoError(t, fs1.Store("key", "value"))
	fs2 := NewFileStorage(dir)
	val, err := fs2.Retrieve("key")
	require.NoError(t, err)
	assert.Equal(t, "value", val)
}

func TestCorruptedKeyFile(t *testing.T) {
	fs := newTestStorage(t)
	require.NoError(t, fs.Store("key", "value"))
	os.WriteFile(fs.keyFile, []byte{0, 1, 2, 3, 4, 5}, 0600)
	fs2 := NewFileStorage(fs.storageDir)
	_, err := fs2.Retrieve("key")
	assert.Error(t, err)
}

func TestCorruptedDataFile(t *testing.T) {
	fs := newTestStorage(t)
	require.NoError(t, fs.Store("key", "value"))
	os.WriteFile(fs.dataFile, []byte("corrupted_data"), 0600)
	fs.cache = nil
	val, err := fs.Retrieve("key")
	assert.NoError(t, err)
	assert.Equal(t, "", val)
}

func TestDirectoryCreation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "deep", "nested", "path")
	fs := NewFileStorage(dir)
	require.NoError(t, fs.Store("key", "value"))
	_, err := os.Stat(dir)
	assert.NoError(t, err)
}

func TestEmptyKey(t *testing.T) {
	fs := newTestStorage(t)
	require.NoError(t, fs.Store("", "value"))
	val, err := fs.Retrieve("")
	require.NoError(t, err)
	assert.Equal(t, "value", val)
}

func TestEmptyValue(t *testing.T) {
	fs := newTestStorage(t)
	require.NoError(t, fs.Store("key", ""))
	val, err := fs.Retrieve("key")
	require.NoError(t, err)
	assert.Equal(t, "", val)
}

func TestSpecialCharactersInKeys(t *testing.T) {
	fs := newTestStorage(t)
	keys := []string{"key-dashes", "key_underscores", "key.dots", "key with spaces"}
	for _, k := range keys {
		require.NoError(t, fs.Store(k, "value"))
		val, err := fs.Retrieve(k)
		require.NoError(t, err)
		assert.Equal(t, "value", val, "key: %s", k)
	}
}

func TestStorageInterface(t *testing.T) {
	fs := newTestStorage(t)
	var _ Storage = fs
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := "Hello, secure world!"
	encrypted, err := encrypt(plaintext, key)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, encrypted)
	decrypted, err := decrypt(encrypted, key)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}
