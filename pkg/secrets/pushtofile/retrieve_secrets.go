package pushtofile

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"github.com/cyberark/conjur-authn-k8s-client/pkg/log"
	"github.com/cyberark/secrets-provider-for-k8s/pkg/log/messages"
	"github.com/cyberark/secrets-provider-for-k8s/pkg/secrets/clients/conjur"
)

// Secret describes how Conjur secrets are represented in the Push-to-File context.
type Secret struct {
	Alias string
	Value string
}

// FetchSecretsForGroups fetches the secrets for all the groups and returns
// map of [group name] to [a slice of secrets for the group]. Callers of this
// function should decorate any errors with messages.CSPFK052E
func FetchSecretsForGroups(
	depRetrieveSecrets conjur.RetrieveSecretsFunc,
	secretGroups []*SecretGroup,
	traceContext context.Context,
) (map[string][]*Secret, error, map[string]string) {
	var err error
	secretsByGroup := map[string][]*Secret{}

	secretPaths := getAllPaths(secretGroups)
	secretValueById, err, variableErrors := depRetrieveSecrets("", secretPaths, traceContext)
	if err != nil {
		return nil, err, nil
	}

	for _, group := range secretGroups {
		for _, spec := range group.SecretSpecs {
			sValue, ok := secretValueById[spec.Path]
			if !ok {
				err = fmt.Errorf(
					"secret with alias %q not present in fetched secrets",
					spec.Alias,
				)
				return nil, err, variableErrors
			}
			if spec.ContentType == "base64" {
				decodedSecretValue := make([]byte, base64.StdEncoding.DecodedLen(len(sValue)))
				_, err := base64.StdEncoding.Decode(decodedSecretValue, sValue)
				decodedSecretValue = bytes.Trim(decodedSecretValue, "\x00")
				if err != nil {
					// Log the error as a warning but still provide the original secret value
					log.Warn(messages.CSPFK064E, spec.Alias, spec.ContentType, err.Error())
				} else {
					sValue = decodedSecretValue
				}
				decodedSecretValue = []byte{}
			}
			secretsByGroup[group.Name] = append(
				secretsByGroup[group.Name],
				&Secret{
					Alias: spec.Alias,
					Value: string(sValue),
				},
			)
			sValue = []byte{}
		}
	}

	return secretsByGroup, err, variableErrors
}

func getSecretValueByID(secretValuesByID map[string][]byte, spec SecretSpec, path string) (*Secret, error) {
	alias := spec.Alias
	if alias == "" || alias == "*" {
		alias = path
	}

	// Get the secret value from the map
	sValue, ok := secretValuesByID[path]
	if !ok {
		err := fmt.Errorf(
			"secret with alias %q not present in fetched secrets",
			alias,
		)
		return nil, err
	}

	// Decode the secret value if it's base64 encoded
	sValue = decodeIfNeeded(spec, alias, sValue)

	secret := &Secret{
		Alias: alias,
		Value: string(sValue),
	}
	return secret, nil
}

// Decodes a secret from Base64 if the SecretSpec specifies that it is encoded.
// If the secret is not encoded, the original secret value is returned.
func decodeIfNeeded(spec SecretSpec, alias string, sValue []byte) []byte {
	if spec.ContentType != "base64" {
		return sValue
	}

	decodedSecretValue := make([]byte, base64.StdEncoding.DecodedLen(len(sValue)))
	_, err := base64.StdEncoding.Decode(decodedSecretValue, sValue)
	decodedSecretValue = bytes.Trim(decodedSecretValue, "\x00")
	if err != nil {
		// Log the error as a warning but still provide the original secret value
		log.Warn(messages.CSPFK064E, alias, spec.ContentType, err.Error())
	} else {
		return decodedSecretValue
	}

	return sValue
}

// secretPathSet is a mathematical set of secret paths. The values of the
// underlying map use an empty struct, since no data is required.
type secretPathSet map[string]struct{}

func (s secretPathSet) Add(path string) {
	s[path] = struct{}{}
}

func getAllPaths(secretGroups []*SecretGroup) []string {
	// Create a mathematical set of all secret paths
	pathSet := secretPathSet{}
	for _, group := range secretGroups {
		for _, spec := range group.SecretSpecs {
			// If the path is "*", then we should fetch all secrets
			if spec.Path == "*" {
				return []string{"*"}
			}

			pathSet.Add(spec.Path)
		}
	}
	// Convert the set of secret paths to a slice of secret paths
	var paths []string
	for path := range pathSet {
		paths = append(paths, path)
	}
	return paths
}
