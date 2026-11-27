// Package secret reads credentials hipr needs, such as an OAuth client
// secret, from where they are kept: HashiCorp Vault, an environment variable
// or a file.
package secret

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Source yields a secret. Implementations read it afresh on every call, so a
// caller that suspects the secret was rotated just calls again.
type Source interface {
	Secret(ctx context.Context) (string, error)
	// String says where the secret comes from. It never includes the secret.
	String() string
}

// Parse turns a flag value into a Source:
//
//	vault:<api path>#<field>   e.g. vault:secret/data/hipr/entra#client_secret
//	env:<NAME>
//	file:<path>
//
// For vault, the connection and Vault credentials come from the environment;
// see VaultFromEnv.
func Parse(spec string) (Source, error) {
	kind, rest, _ := strings.Cut(spec, ":")
	switch kind {
	case "vault":
		path, field, ok := strings.Cut(rest, "#")
		if !ok || path == "" || field == "" {
			return nil, fmt.Errorf("secret %q: want vault:<path>#<field>, e.g. vault:secret/data/hipr/entra#client_secret", spec)
		}
		return VaultFromEnv(strings.Trim(path, "/"), field)
	case "env":
		if rest == "" {
			return nil, errors.New("secret: env: needs a variable name")
		}
		return envSource(rest), nil
	case "file":
		if rest == "" {
			return nil, errors.New("secret: file: needs a path")
		}
		return fileSource(rest), nil
	}
	return nil, fmt.Errorf("secret %q: want vault:<path>#<field>, env:<NAME> or file:<path>", spec)
}

type envSource string

func (e envSource) String() string { return "environment variable " + string(e) }

func (e envSource) Secret(context.Context) (string, error) {
	v := os.Getenv(string(e))
	if v == "" {
		return "", fmt.Errorf("%s is not set", e)
	}
	return v, nil
}

type fileSource string

func (f fileSource) String() string { return "file " + string(f) }

func (f fileSource) Secret(context.Context) (string, error) {
	b, err := os.ReadFile(string(f))
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return "", fmt.Errorf("%s is empty", f)
	}
	return v, nil
}
