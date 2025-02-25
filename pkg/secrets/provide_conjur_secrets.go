package secrets

import (
	"context"
	"fmt"
	k8swebhooks "github.com/cyberark/secrets-provider-for-k8s/pkg/secrets/k8s_webhooks"
	"math/rand"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/cyberark/conjur-authn-k8s-client/pkg/log"

	"github.com/cyberark/secrets-provider-for-k8s/pkg/log/messages"
	"github.com/cyberark/secrets-provider-for-k8s/pkg/secrets/clients/conjur"
	"github.com/cyberark/secrets-provider-for-k8s/pkg/secrets/config"
	secretsConfigProvider "github.com/cyberark/secrets-provider-for-k8s/pkg/secrets/config"
	k8sSecretsStorage "github.com/cyberark/secrets-provider-for-k8s/pkg/secrets/k8s_secrets_storage"
	"github.com/cyberark/secrets-provider-for-k8s/pkg/secrets/pushtofile"
	"github.com/cyberark/secrets-provider-for-k8s/pkg/utils"
)

const (
	secretProviderGracePeriod = time.Duration(10 * time.Millisecond)
)

// CommonProviderConfig provides config that is common to all providers
type CommonProviderConfig struct {
	StoreType       string
	SanitizeEnabled bool
}

// ProviderConfig provides the configuration necessary to create a secrets
// Provider.
type ProviderConfig struct {
	CommonProviderConfig
	k8sSecretsStorage.K8sProviderConfig
	pushtofile.P2FProviderConfig
}

// ProviderFunc describes a function type responsible for providing secrets to
// an unspecified target. It returns either an error, or a flag that indicates
// whether any target secret files or Kubernetes Secrets have been updated.
type ProviderFunc func(secrets ...string) (updated bool, err error)

// RepeatableProviderFunc describes a function type that is capable of looping
// indefinitely while providing secrets to unspecified targets.
type RepeatableProviderFunc func() error

// ProviderFactory defines a function type for creating a ProviderFunc given a
// RetrieveSecretsFunc and ProviderConfig.
type ProviderFactory func(traceContent context.Context, secretsRetrieverFunc conjur.RetrieveSecretsFunc, providerConfig ProviderConfig) (ProviderFunc, []error)

// RandomTicker defines custom ticker with random element
type RandomTicker struct {
	C     chan time.Time
	stopc chan struct{}
	min   int64
	max   int64
}

// NewProviderForType returns a ProviderFunc responsible for providing secrets in a given mode.
func NewProviderForType(
	traceContext context.Context,
	secretsRetrieverFunc conjur.RetrieveSecretsFunc,
	providerConfig ProviderConfig,
) (ProviderFunc, []error) {
	switch providerConfig.StoreType {
	case config.K8s:
		provider := k8sSecretsStorage.NewProvider(
			traceContext,
			secretsRetrieverFunc,
			providerConfig.CommonProviderConfig.SanitizeEnabled,
			providerConfig.K8sProviderConfig,
		)
		k8swebhooks.StartWebhookServer(provider)
		return provider.Provide, nil
	case config.File:
		provider, err := pushtofile.NewProvider(
			secretsRetrieverFunc,
			providerConfig.CommonProviderConfig.SanitizeEnabled,
			providerConfig.P2FProviderConfig,
		)
		if err != nil {
			return nil, err
		}
		provider.SetTraceContext(traceContext)
		return provider.Provide, nil
	default:
		return nil, []error{fmt.Errorf(
			messages.CSPFK054E,
			providerConfig.StoreType,
		)}
	}
}

// RetryableSecretProvider returns a new ProviderFunc, which wraps the provided ProviderFunc
// in a limitedBackOff-restricted Retry call.
func RetryableSecretProvider(
	retryInterval time.Duration,
	retryCountLimit int,
	provideSecrets ProviderFunc,
) ProviderFunc {
	limitedBackOff := utils.NewLimitedBackOff(
		retryInterval,
		retryCountLimit,
	)

	return func(secrets ...string) (bool, error) {
		var updated bool
		var retErr error

		err := backoff.Retry(func() error {
			if limitedBackOff.RetryCount() > 0 {
				log.Info(fmt.Sprintf(messages.CSPFK010I, limitedBackOff.RetryCount(), limitedBackOff.RetryLimit))
			}
			updated, retErr = provideSecrets(secrets...)
			return retErr
		}, limitedBackOff)

		if err != nil {
			log.Error(messages.CSPFK038E, err)
		}
		return updated, err
	}
}

// ProviderRefreshConfig specifies the secret refresh configuration
// for a repeatable secret provider.
type ProviderRefreshConfig struct {
	Mode                  string
	SecretRefreshInterval time.Duration
	ProviderQuit          chan struct{}
}

// RunSecretsProvider takes a retryable ProviderFunc, and runs it in one of three modes:
//   - Run once and return (for init or application container modes)
//   - Run once and sleep forever (for sidecar mode without periodic refresh)
//   - Run periodically (for sidecar mode with periodic refresh)
func RunSecretsProvider(
	config ProviderRefreshConfig,
	provideSecrets ProviderFunc,
	status StatusUpdater,
	providerConfig *secretsConfigProvider.Config,
) error {

	var periodicQuit = make(chan struct{})
	var periodicError = make(chan error)
	var ticker *time.Ticker
	var err error

	if err = status.CopyScripts(); err != nil {
		return err
	}
	rand.New(rand.NewSource(time.Now().UnixNano()))
	n := rand.Intn(5000) // n will be between 0 and 5000ms(5s)
	log.Info("Waiting randomly %d ms...", n)
	time.Sleep(time.Duration(n) * time.Millisecond)
	if _, err = provideSecrets(providerConfig.RequiredK8sSecrets...); err != nil && (config.Mode != "sidecar" && config.Mode != "application") {
		return err
	}
	if err == nil {
		err = status.SetSecretsProvided()
		// In sidecar or application mode provider should keep running
		if err != nil && (config.Mode != "sidecar" && config.Mode != "application") {
			return err
		}
	}
	switch {
	case config.Mode != "sidecar" && config.Mode != "application":
		// Run once and return if not in sidecar mode
		return nil
	case config.Mode == "application":
		log.Info(fmt.Sprintf(messages.CSPFK025I, config.SecretRefreshInterval) + ". Actual refresh interval will be randomized by +-10% of configured time.")
		// Run periodically if in sidecar mode with periodic refresh
		config := periodicConfig{
			ticker: newRandomTicker(
				time.Duration(0.9*(float64(config.SecretRefreshInterval.Nanoseconds()))),
				time.Duration(1.1*(float64(config.SecretRefreshInterval.Nanoseconds())))),
			periodicQuit:  periodicQuit,
			periodicError: periodicError,
		}
		go periodicSecretProvider(provideSecrets, config, status, providerConfig.RequiredK8sSecrets...)
	default:
		// Run once and sleep forever if in sidecar mode without
		// periodic refresh (fall through)
	}

	// Wait here for a signal to quit providing secrets or an error
	// from the periodicSecretProvider() function
	select {
	case <-config.ProviderQuit:
		break
	case err = <-periodicError:
		//periodic provider in standalone mode should keep working event there is provision errors.
		//errors should be appropriately logged so user can see what went wrong.
		if config.Mode != "application" {
			break
		}
	}

	// Allow the periodicSecretProvider goroutine to gracefully shut down
	if config.SecretRefreshInterval > 0 {
		// Kill the ticker
		ticker.Stop()
		periodicQuit <- struct{}{}
		// Let the go routine exit
		time.Sleep(secretProviderGracePeriod)
	}
	return err
}

type periodicConfig struct {
	ticker        *RandomTicker
	periodicQuit  <-chan struct{}
	periodicError chan<- error
}

func periodicSecretProvider(
	provideSecrets ProviderFunc,
	config periodicConfig,
	status StatusUpdater,
	requiredK8sSecrets ...string,
) {
	for {
		select {
		case <-config.periodicQuit:
			return
		case <-config.ticker.C:
			log.Info(messages.CSPFK024I)
			updated, err := provideSecrets(requiredK8sSecrets...)
			if err == nil && updated {
				log.Info("Periodic provider run finished")
				err = status.SetSecretsUpdated()
			}
			/*if err != nil {
				config.periodicError <- err
			}*/
		}
	}
}

// defines the RandomTicker behaviour
func (rt *RandomTicker) loop() {
	t := time.NewTimer(rt.nextInterval())
	for {
		select {
		case <-rt.stopc:
			t.Stop()
			return
		case <-t.C:
			select {
			case rt.C <- time.Now():
				t.Stop()
				t = time.NewTimer(rt.nextInterval())
			default:
				// skip if there is no receiver
			}
		}
	}
}

// define next  interval for RandomTicker loop
func (rt *RandomTicker) nextInterval() time.Duration {
	interval := rand.Int63n(rt.max-rt.min) + rt.min
	timeInterval := time.Duration(interval) * time.Nanosecond
	return timeInterval
}

// NewRandomTicker returns a pointer to an initialized instance of the
// RandomTicker. Min and max are durations of the shortest and longest
// allowed ticks. Ticker will run in a goroutine until explicitly stopped.
func newRandomTicker(min, max time.Duration) *RandomTicker {
	rt := &RandomTicker{
		C:     make(chan time.Time),
		stopc: make(chan struct{}),
		min:   min.Nanoseconds(),
		max:   max.Nanoseconds(),
	}
	go rt.loop()
	return rt
}

// Stop terminates the ticker goroutine and closes the C channel.
func (rt *RandomTicker) Stop() {
	close(rt.stopc)
	close(rt.C)
}
