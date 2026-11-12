package azure_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/uvamai/meiscope-collector/internal/adapter/azure"
	"github.com/uvamai/meiscope-collector/internal/redirect"
)

// TestAzureDoesNotFollowRedirects: a 307 from the API to another host is not
// followed, so the bearer token is not replayed there (the fake fails the
// test on any request to an unexpected host).
func TestAzureDoesNotFollowRedirects(t *testing.T) {
	f := newFake(t, "keyvault")
	f.override["/certificates"] = func(r *http.Request) *http.Response {
		resp := jsonResponse(r, http.StatusTemporaryRedirect, `{}`)
		resp.Header.Set("Location", "https://collector-test.example.test/certificates?api-version=7.4")
		return resp
	}
	h := newHarness(f, allOn)
	_, err := h.sync(t, config("kv", azure.NameKeyVault, map[string]string{"vaults": "kv-contoso-prod"}), "")
	if !errors.Is(err, redirect.ErrRefused) {
		t.Fatalf("err %v, want redirect.ErrRefused", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, host := range f.hosts {
		if host == "collector-test.example.test" {
			t.Fatal("the redirect was followed")
		}
	}
}
