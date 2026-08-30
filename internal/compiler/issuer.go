package compiler

import (
	"fmt"
	"os"
)

type Env struct {
	PublicHost string
	HTTPSPort  string
}

func EnvFromOS() Env {
	return Env{
		PublicHost: os.Getenv("LAB_PUBLIC_HOST"),
		HTTPSPort:  os.Getenv("LABSSO_HTTPS_PORT"),
	}
}

func DeriveIssuer(env Env) (string, bool) {
	if env.PublicHost == "" {
		return "", false
	}
	port := env.HTTPSPort
	if port == "" || port == "443" {
		return "https://" + env.PublicHost, true
	}
	return "https://" + env.PublicHost + ":" + port, true
}

func ResolveIssuer(yamlIssuer string, env Env) (string, error) {
	derived, ok := DeriveIssuer(env)
	if !ok {
		if yamlIssuer == "" {
			return "", fmt.Errorf("spec.issuer is required when LAB_PUBLIC_HOST is unset")
		}
		return yamlIssuer, nil
	}
	if yamlIssuer != derived {
		return "", fmt.Errorf("spec.issuer %q does not match derived issuer %q (LAB_PUBLIC_HOST / LABSSO_HTTPS_PORT)", yamlIssuer, derived)
	}
	return derived, nil
}
