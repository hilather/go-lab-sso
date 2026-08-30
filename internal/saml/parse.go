package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

const maxSAMLBytes = 64 << 10

type authnRequest struct {
	XMLName                     xml.Name
	ID                          string `xml:"ID,attr"`
	AssertionConsumerServiceURL string `xml:"AssertionConsumerServiceURL,attr"`
	Destination                 string `xml:"Destination,attr"`
	Issuer                      string `xml:"Issuer"`
}

func decodeSAMLRequest(raw string, deflated bool) (*authnRequest, error) {
	if raw == "" {
		return nil, fmt.Errorf("SAMLRequest is required")
	}
	if len(raw) > maxSAMLBytes*2 {
		return nil, fmt.Errorf("SAMLRequest too large")
	}
	bin, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		bin, err = base64.URLEncoding.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("SAMLRequest is not base64")
		}
	}
	if len(bin) > maxSAMLBytes {
		return nil, fmt.Errorf("SAMLRequest too large")
	}
	body := bin
	if deflated {
		r := flate.NewReader(bytes.NewReader(bin))
		defer r.Close()
		body, err = io.ReadAll(io.LimitReader(r, maxSAMLBytes+1))
		if err != nil {
			return nil, fmt.Errorf("SAMLRequest deflate")
		}
		if len(body) > maxSAMLBytes {
			return nil, fmt.Errorf("SAMLRequest too large")
		}
	}
	if err := rejectHostileXML(body); err != nil {
		return nil, err
	}
	dec := xml.NewDecoder(bytes.NewReader(body))
	dec.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		return input, nil
	}
	var req authnRequest
	if err := dec.Decode(&req); err != nil {
		return nil, fmt.Errorf("SAMLRequest xml: %w", err)
	}
	req.Issuer = strings.TrimSpace(req.Issuer)
	if req.ID == "" || req.Issuer == "" {
		return nil, fmt.Errorf("SAMLRequest missing ID or Issuer")
	}
	return &req, nil
}

func ParseSPSSO(raw string) (entityID string, acs []string, err error) {
	if err := rejectHostileXML([]byte(raw)); err != nil {
		return "", nil, err
	}
	if len(raw) > maxSAMLBytes {
		return "", nil, fmt.Errorf("SAML metadata too large")
	}
	dec := xml.NewDecoder(bytes.NewReader([]byte(raw)))
	dec.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		return input, nil
	}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", nil, fmt.Errorf("SAML metadata xml: %w", err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "EntityDescriptor":
			for _, a := range se.Attr {
				if a.Name.Local == "entityID" {
					entityID = a.Value
				}
			}
		case "AssertionConsumerService":
			for _, a := range se.Attr {
				if a.Name.Local == "Location" && a.Value != "" {
					acs = append(acs, a.Value)
				}
			}
		}
	}
	return entityID, acs, nil
}

func rejectHostileXML(raw []byte) error {
	s := strings.ToUpper(string(raw))
	if strings.Contains(s, "<!DOCTYPE") || strings.Contains(s, "<!ENTITY") || strings.Contains(s, "SYSTEM \"") {
		return fmt.Errorf("SAMLRequest rejected: external entities / DTD")
	}
	return nil
}
