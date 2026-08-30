package model

import (
	"encoding/json"
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string (Go syntax such as 1h)")
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("duration must be a string (Go syntax such as 1h)")
	}
	switch n.Tag {
	case "!!int", "!!float":
		return fmt.Errorf("bare numbers rejected; use Go duration syntax")
	}
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", n.Value, err)
	}
	*d = Duration(v)
	return nil
}

func (d Duration) MarshalYAML() (any, error) {
	return time.Duration(d).String(), nil
}
