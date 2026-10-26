package conjur

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/cyberark/conjur-api-go/conjurapi/response"
	"github.com/cyberark/conjur-authn-k8s-client/pkg/access_token"
	"github.com/cyberark/conjur-authn-k8s-client/pkg/access_token/memory"
	"github.com/cyberark/conjur-authn-k8s-client/pkg/authenticator"
	"github.com/stretchr/testify/assert"
)

// fakeAuthenticator writes "token-1", "token-2", ... on each authentication
type fakeAuthenticator struct {
	accessToken *memory.AccessToken
	authCount   atomic.Int32
}

func (a *fakeAuthenticator) Authenticate() error {
	return a.AuthenticateWithContext(context.Background())
}

func (a *fakeAuthenticator) AuthenticateWithContext(ctx context.Context) error {
	// widen the window between authenticating and reading the token
	time.Sleep(time.Millisecond)
	n := a.authCount.Add(1)
	return a.accessToken.Write([]byte(fmt.Sprintf("token-%d", n)))
}

func (a *fakeAuthenticator) GetAccessToken() access_token.AccessToken {
	return a.accessToken
}

func (a *fakeAuthenticator) GetHttpClient() *http.Client {
	return &http.Client{}
}

func newFakeRetriever(auth string) (secretRetriever, *fakeAuthenticator) {
	accessToken, _ := memory.NewAccessToken()
	authn := &fakeAuthenticator{accessToken: accessToken}
	// drop token state left by a previous test run
	lock.Lock()
	delete(authnLocks, auth)
	lock.Unlock()
	return secretRetriever{
		authnMap: map[string]authenticator.Authenticator{auth: authn},
	}, authn
}

func TestRetrieveConcurrentSameAuthn(t *testing.T) {
	retriever, authn := newFakeRetriever("CONCURRENT")

	var wg sync.WaitGroup
	errs := make(chan error, 50)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err, _ := retriever.Retrieve("concurrent", []string{}, context.Background())
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		assert.NoError(t, err)
	}
	assert.Equal(t, int32(1), authn.authCount.Load(), "token should be authenticated once and reused")
}

func TestRetrieveReauthenticatesAfterTokenTTL(t *testing.T) {
	retriever, authn := newFakeRetriever("TTL")
	origTTL := tokenTTL
	tokenTTL = 0
	t.Cleanup(func() { tokenTTL = origTTL })

	for i := 0; i < 2; i++ {
		_, err, _ := retriever.Retrieve("ttl", []string{}, context.Background())
		assert.NoError(t, err)
	}
	assert.Equal(t, int32(2), authn.authCount.Load())
}

// unauthorizedConjurClient rejects every request with 401
type unauthorizedConjurClient struct{}

func (c *unauthorizedConjurClient) RetrieveBatchSecretsSafe(variableIDs []string) (map[string][]byte, error) {
	return nil, &response.ConjurError{Code: http.StatusUnauthorized, Message: "Unauthorized"}
}

func (c *unauthorizedConjurClient) Resources(filter *conjurapi.ResourceFilter) ([]map[string]interface{}, error) {
	return nil, nil
}

func (c *unauthorizedConjurClient) GetHttpClient() *http.Client {
	return &http.Client{}
}

func TestRetrieveReauthenticatesAfterUnauthorized(t *testing.T) {
	retriever, authn := newFakeRetriever("UNAUTHORIZED")

	_, err, _ := retriever.Retrieve("unauthorized", []string{}, context.Background())
	assert.NoError(t, err)
	assert.Equal(t, int32(1), authn.authCount.Load())

	_, err, variableErrors := retrieveConjurSecrets("unauthorized", []byte("token-1"), []string{"var1"}, &unauthorizedConjurClient{})
	assert.NoError(t, err)
	assert.Contains(t, variableErrors["general"], "Unauthorized")

	_, err, _ = retriever.Retrieve("unauthorized", []string{}, context.Background())
	assert.NoError(t, err)
	assert.Equal(t, int32(2), authn.authCount.Load(), "rejected token should be replaced by a new one")
}
