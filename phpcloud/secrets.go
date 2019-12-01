package phpcloud

import (
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go/service/secretsmanager"
)

// SecretRequest is the request argument for AWS.Secret.
type SecretRequest struct {
	ID string
}

// SecretResponse is the response argument for AWS.Secret.
type SecretResponse struct {
	String    string
	Binary    []byte
	VersionID string
}

// Secret is a helper for secretsmanager::GetSecretValue(). The secret is
// indefinitely cached in memory.
//
// A threat model in which an adversary has access to this binary's memory is
// such that we assume access to PHP memory too. The alternatives are (a)
// storing secrets in some other format; or (b) a new GetSecretValue() request
// on every call, which will become expensive for secrets such as database
// credentials that PHP needs on every request (even for persistent connections,
// in the case of MySQL).
func (a *AWS) Secret(req SecretRequest, resp *SecretResponse) error {
	a.secretMu.RLock()
	c, ok := a.secretCache[req]
	a.secretMu.RUnlock()
	if ok {
		*resp = *c
		return nil
	}

	sec, err := a.secrets.GetSecretValue(&secretsmanager.GetSecretValueInput{
		SecretId: &req.ID,
	})
	if err != nil {
		return fmt.Errorf("GetSecretValue(): %v", err)
	}

	if sec.VersionId == nil {
		return errors.New("nil version ID received from secretsmanager.GetSecretValue()")
	}
	resp.VersionID = *sec.VersionId

	if s := sec.SecretString; s != nil {
		resp.String = *s
	}
	resp.Binary = sec.SecretBinary

	a.secretMu.Lock()
	defer a.secretMu.Unlock()
	c = new(SecretResponse)
	*c = *resp
	a.secretCache[req] = c
	return nil
}
