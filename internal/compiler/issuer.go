package compiler

import (
	"fmt"
	"github.com/hilather/go-lab-sso/internal/model"
	"net"
	"net/url"
	"os"
	"strings"
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
		host := strings.Trim(env.PublicHost, "[]")
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		return "https://" + host, true
	}
	return "https://" + net.JoinHostPort(strings.Trim(env.PublicHost, "[]"), port), true
}

func ResolveIssuer(yamlIssuer string, env Env) (string, error) {
	if env.PublicHost != "" && (!model.ValidHost(strings.Trim(env.PublicHost, "[]")) || (strings.ContainsAny(env.PublicHost, "[]") && (env.PublicHost != "["+strings.Trim(env.PublicHost, "[]")+"]" || net.ParseIP(strings.Trim(env.PublicHost, "[]")) == nil))) {
		return "", fmt.Errorf("invalid LAB_PUBLIC_HOST")
	}
	if env.HTTPSPort != "" && !model.ValidPort(env.HTTPSPort) {
		return "", fmt.Errorf("invalid LABSSO_HTTPS_PORT")
	}
	if err := model.ValidateURI(yamlIssuer, true); err != nil {
		return "", fmt.Errorf("issuer must be an absolute HTTPS origin: %w", err)
	}
	u, err := url.Parse(yamlIssuer)
	if err != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", fmt.Errorf("issuer must have no path, query, or fragment")
	}
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
