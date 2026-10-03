package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"github.com/hilather/go-lab-sso/internal/model"
	"io"
	"strings"
)

const maxSAMLBytes = 64 << 10

type authnRequest struct {
	XMLName                     xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
	Version                     string   `xml:"Version,attr"`
	ForceAuthn                  bool     `xml:"ForceAuthn,attr"`
	IsPassive                   bool     `xml:"IsPassive,attr"`
	ID                          string   `xml:"ID,attr"`
	AssertionConsumerServiceURL string   `xml:"AssertionConsumerServiceURL,attr"`
	Destination                 string   `xml:"Destination,attr"`
	Issuer                      string   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
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
		defer func() { _ = r.Close() }()
		body, err = io.ReadAll(io.LimitReader(r, maxSAMLBytes+1))
		if err != nil {
			return nil, fmt.Errorf("SAMLRequest deflate")
		}
		if len(body) > maxSAMLBytes {
			return nil, fmt.Errorf("SAMLRequest too large")
		}
	}
	if err := validateStructure(body, false); err != nil {
		return nil, err
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
	if err := oneDocument(dec); err != nil {
		return nil, err
	}
	if req.Version != "2.0" {
		return nil, fmt.Errorf("SAMLRequest requires Version 2.0")
	}
	req.Issuer = strings.TrimSpace(req.Issuer)
	if req.ID == "" || req.Issuer == "" {
		return nil, fmt.Errorf("SAMLRequest missing ID or Issuer")
	}
	return &req, nil
}

func ParseSPSSO(raw string) (entityID string, acs []string, err error) {
	if err := validateStructure([]byte(raw), true); err != nil {
		return "", nil, err
	}
	if err := rejectHostileXML([]byte(raw)); err != nil {
		return "", nil, err
	}
	if len(raw) > maxSAMLBytes {
		return "", nil, fmt.Errorf("SAML metadata too large")
	}
	dec := xml.NewDecoder(strings.NewReader(raw))
	var md struct {
		XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
		Entity  string   `xml:"entityID,attr"`
		SP      []struct {
			Protocol string `xml:"protocolSupportEnumeration,attr"`
			ACS      []struct {
				Binding  string `xml:"Binding,attr"`
				Location string `xml:"Location,attr"`
				Index    string `xml:"index,attr"`
			} `xml:"urn:oasis:names:tc:SAML:2.0:metadata AssertionConsumerService"`
		} `xml:"urn:oasis:names:tc:SAML:2.0:metadata SPSSODescriptor"`
	}
	if err := dec.Decode(&md); err != nil {
		return "", nil, fmt.Errorf("SAML metadata must be one EntityDescriptor: %w", err)
	}
	if err := oneDocument(dec); err != nil {
		return "", nil, err
	}
	if md.Entity == "" || len(md.SP) != 1 || !strings.Contains(" "+md.SP[0].Protocol+" ", " urn:oasis:names:tc:SAML:2.0:protocol ") {
		return "", nil, fmt.Errorf("SAML metadata requires exactly one SAML2 SP descriptor")
	}
	indices := map[string]bool{}
	locations := map[string]bool{}
	for _, endpoint := range md.SP[0].ACS {
		if endpoint.Index == "" || indices[endpoint.Index] {
			return "", nil, fmt.Errorf("SAML metadata requires unique ACS indices")
		}
		indices[endpoint.Index] = true
		if endpoint.Binding != "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" {
			continue
		}
		if model.ValidateURI(endpoint.Location, true) != nil || locations[endpoint.Location] {
			return "", nil, fmt.Errorf("invalid or duplicate POST ACS")
		}
		locations[endpoint.Location] = true
		acs = append(acs, endpoint.Location)
	}
	if len(acs) == 0 {
		return "", nil, fmt.Errorf("no HTTPS HTTP-POST ACS")
	}
	return md.Entity, acs, nil
}

func rejectHostileXML(raw []byte) error {
	s := strings.ToUpper(string(raw))
	if strings.Contains(s, "<!DOCTYPE") || strings.Contains(s, "<!ENTITY") || strings.Contains(s, "SYSTEM \"") {
		return fmt.Errorf("SAMLRequest rejected: external entities / DTD")
	}
	return nil
}

func oneDocument(dec *xml.Decoder) error {
	for {
		token, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch t := token.(type) {
		case xml.CharData:
			if strings.TrimSpace(string(t)) != "" {
				return fmt.Errorf("trailing XML data")
			}
		case xml.Comment:
		default:
			return fmt.Errorf("trailing XML document")
		}
	}
}

// Reject duplicate attributes and protocol elements hidden under unrelated descriptors.
func validateStructure(raw []byte, metadata bool) error {
	if len(raw) > maxSAMLBytes {
		return fmt.Errorf("SAML XML too large")
	}
	dec := xml.NewDecoder(bytes.NewReader(raw))
	var stack []xml.Name
	issuers := 0
	entities := 0
	for {
		token, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("invalid SAML XML: %w", err)
		}
		switch element := token.(type) {
		case xml.StartElement:
			attrs := map[xml.Name]bool{}
			for _, a := range element.Attr {
				if attrs[a.Name] {
					return fmt.Errorf("duplicate XML attribute")
				}
				attrs[a.Name] = true
			}
			if metadata {
				switch element.Name.Local {
				case "EntityDescriptor":
					entities++
					if len(stack) != 0 || entities != 1 || element.Name.Space != "urn:oasis:names:tc:SAML:2.0:metadata" {
						return fmt.Errorf("ambiguous EntityDescriptor")
					}
				case "SPSSODescriptor":
					if len(stack) != 1 || stack[0].Local != "EntityDescriptor" || element.Name.Space != "urn:oasis:names:tc:SAML:2.0:metadata" {
						return fmt.Errorf("invalid SP descriptor nesting")
					}
				case "AssertionConsumerService":
					if len(stack) != 2 || stack[1].Local != "SPSSODescriptor" || element.Name.Space != "urn:oasis:names:tc:SAML:2.0:metadata" {
						return fmt.Errorf("invalid ACS descriptor nesting")
					}
				}
			} else if element.Name.Local == "Issuer" {
				issuers++
				if issuers != 1 || len(stack) != 1 || element.Name.Space != "urn:oasis:names:tc:SAML:2.0:assertion" {
					return fmt.Errorf("invalid or duplicate request Issuer")
				}
			}
			stack = append(stack, element.Name)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}
	return nil
}
