package phpcloud

import (
	"sync"

	"github.com/aws/aws-sdk-go/service/secretsmanager/secretsmanageriface"
)

// AWS implements a net/rpc service for interacting with AWS services.
type AWS struct {
	secrets secretsmanageriface.SecretsManagerAPI

	secretMu    sync.RWMutex
	secretCache map[SecretRequest]*SecretResponse
}

// NewAWS returns a new AWS service.
func NewAWS(secrets secretsmanageriface.SecretsManagerAPI) *AWS {
	return &AWS{
		secrets:     secrets,
		secretCache: make(map[SecretRequest]*SecretResponse),
	}
}
