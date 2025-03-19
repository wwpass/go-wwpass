// Server-side client for [WWPass] authorization service, to be used with [wwpass-frontend].
//
// This library only supports the minimum of SPFE API required for authentication.
// It can be extended for complete support if there is demand for it.
//
// [WWPass]: https://www.wwpass.com/
// [wwpass-frontend]: https://github.com/wwpass/wwpass-frontend
package wwpass

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// WWPass official CA certificate.
const wwpassCA = `
-----BEGIN CERTIFICATE-----
MIIGATCCA+mgAwIBAgIJAN7JZUlglGn4MA0GCSqGSIb3DQEBCwUAMFcxCzAJBgNV
BAYTAlVTMRswGQYDVQQKExJXV1Bhc3MgQ29ycG9yYXRpb24xKzApBgNVBAMTIldX
UGFzcyBDb3Jwb3JhdGlvbiBQcmltYXJ5IFJvb3QgQ0EwIhgPMjAxMjExMjgwOTAw
MDBaGA8yMDUyMTEyODA4NTk1OVowVzELMAkGA1UEBhMCVVMxGzAZBgNVBAoTEldX
UGFzcyBDb3Jwb3JhdGlvbjErMCkGA1UEAxMiV1dQYXNzIENvcnBvcmF0aW9uIFBy
aW1hcnkgUm9vdCBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMmF
pl1WX80osygWx4ZX8xGyYfHx8cpz29l5s/7mgQIYCrmUSLK9KtSryA0pmzrOFkyN
BuT0OU5ucCuv2WNgUriJZ78b8sekW1oXy2QXndZSs+CA+UoHFw0YqTEDO659/Tjk
NqlE5HMXdYvIb7jhcOAxC8gwAJFgAkQboaMIkuWsAnpOtKzrnkWHGz45qoyICjqz
feDcN0dh3ITMHXrYiwkVq5fGXHPbuJPbuBN+unnakbL3Ogk3yPnEcm6YV+HrxQ7S
Ky83q60Abdy8ft0RpSJeUkBjJVwiHu4y4j5iKC1tNgtV8qE9Zf2g5vAHzL3obqnu
IMr8JpmWp0MrrUa9jYOtKXk2LnZnfxurJ74NVk2RmuN5I/H0a/tUrHWtCE5pcVNk
b3vmoqeFsbTs2KDCMq/gzUhHU31l4Zrlz+9DfBUxlb5fNYB5lF4FnR+5/hKgo75+
OaNjiSfp9gTH6YfFCpS0OlHmKhsRJlR2aIKpTUEG9hjSg3Oh7XlpJHhWolQQ2BeL
++3UOyRMTDSTZ1bGa92oz5nS+UUsE5noUZSjLM+KbaJjZGCxzO9y2wiFBbRSbhL2
zXpUD2dMB1G30jZwytjn15VAMEOYizBoHEp2Nf9PNhsDGa32AcpJ2a0n89pbSOlu
yr/vEzYjJ2DZ/TWQQb7upi0G2kRX17UIZ5ZfhjmBAgMBAAGjgcswgcgwHQYDVR0O
BBYEFGu/H4b/gn8RzL7XKHBT6K4BQcl7MIGIBgNVHSMEgYAwfoAUa78fhv+CfxHM
vtcocFPorgFByXuhW6RZMFcxCzAJBgNVBAYTAlVTMRswGQYDVQQKExJXV1Bhc3Mg
Q29ycG9yYXRpb24xKzApBgNVBAMTIldXUGFzcyBDb3Jwb3JhdGlvbiBQcmltYXJ5
IFJvb3QgQ0GCCQDeyWVJYJRp+DAPBgNVHRMBAf8EBTADAQH/MAsGA1UdDwQEAwIB
BjANBgkqhkiG9w0BAQsFAAOCAgEAE46CMikI7378mkC3qZyKcVxkNfLRe3eD4h04
OO27rmfZj/cMrDDCt0Bn2t9LBUGBdXfZEn13gqn598F6lmLoObtN4QYqlyXrFcPz
FiwQarba+xq8togxjMkZ2y70MlV3/PbkKkwv4bBjOcLZQ1DsYehPdsr57C6Id4Ee
kEQs/aMtKcMzZaSipkTuXFxfxW4uBifkH++tUASD44OD2r7m1UlSQ5viiv3l0qvA
B89dPifVnIeAvPcd7+GY2RXTZCw36ZipnFiOWT9TkyTDpB/wjWQNFrgmmQvxQLeW
BWIUSaXJwlVzMztdtThnt/bNZNGPMRfaZ76OljYB9BKC7WUmss2f8toHiys+ERHz
0xfCTVhowlz8XtwWfb3A17jzJBm+KAlQsHPgeBEqtocxvBJcqhOiKDOpsKHHz+ng
exIO3elr1TCVutPTE+UczYTBRsL+jIdoIxm6aA9rrN3qDVwMnuHThSrsiwyqOXCz
zjCaCf4l5+KG5VNiYPytiGicv8PCBjwFkzIr+LRSyUiYzAZuiyRchpdT+yRAfL7q
qHBuIHYhG3E47a3GguwUwUGcXR+NjrSmteHRDONOUYUCH41hw6240Mo1lL4F+rpr
LEBB84k3+v+AtbXePEwvp+o1nu/+1sRkhqlNFHN67vakqC4xTxiuPxu6Pb/uDeNI
ip0+E9I=
-----END CERTIFICATE-----
`

const spfeUrl = "https://spfe.wwpass.com"

// Client object. Upon initializing one with [Client], you will be able to make requests to SPFE with it.
type WWPass struct {
	spfe string
	http *http.Client
}

// A set of flags describing optional components of authentication process, which gets encoded in the ticket.
// Operations on an existing ticket verify the supplied flags against the actual state of the ticket,
// and will return errors if they don't match.
//
// SessionKey flag is used by certain API endpoints not currently implemented in this library.
// ClientKey flag can be used on the frontend without the server being aware of the specifics.
// (see [wwpass-crypto.js] and the use of this feature in [passhub])
//
// [wwpass-crypto.js]: https://github.com/wwpass/wwpass-frontend/blob/master/src/wwpass.crypto.js
// [passhub]: https://github.com/wwpass/passhub/blob/master/src/js/crypto.js
type AuthFlags struct {
	Pin        bool // Request the user to input a PIN code or perform biometric verification during login.
	SessionKey bool // Generate a session key available to both parties.
	ClientKey  bool // Generate a cryptographic key that only the frontend will have access to.
}

// SPFE API is highly idiosyncratic for historical reasons.
// The response is a flat dictionary of variables which have different meanings depending
// on the request.
type spfeResponse struct {
	Success   bool   `json:"result"`
	ErrorCode string `json:"code"` // Error code is actually a string.
	Data      string `json:"data"`
	Ttl       int    `json:"ttl"`
	Encoding  string `json:"encoding"`
}

// Initialize a new WWPass client using your client certificate and key.
//
// The timeout value affects all requests made to SPFE.
//
// Passing empty values for ca and spfe will result in using defaults, which are the
// WWPass certificate authority and https://spfe.wwpass.com respectively.
// If you wish to override the CA, supply a PEM-encoded certificate.
func Client(cert []byte, key []byte, timeout time.Duration, ca []byte, spfe string) (WWPass, error) {
	var err error
	var client = WWPass{}

	caPool := x509.NewCertPool()
	if len(ca) == 0 {
		ca = []byte(wwpassCA)
	}
	caPem, _ := pem.Decode(ca)
	if caPem == nil {
		return client, fmt.Errorf("supplied CA data does not appear to contain a CA certificate")
	} else {
		caCert, err := x509.ParseCertificate(caPem.Bytes)
		if err != nil {
			return client, fmt.Errorf("failed to parse CA certificate: %w", err)
		}
		caPool.AddCert(caCert)
	}

	clientCert, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return client, fmt.Errorf("failed to parse keypair: %w", err)
	}

	client.http = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caPool,
				Certificates: []tls.Certificate{clientCert},
			},
		},
		Timeout: timeout,
	}

	client.spfe = spfeUrl
	if len(spfe) > 0 {
		client.spfe = spfe
	}

	return client, nil
}

func authFlagString(auth AuthFlags) string {

	s := ""
	if auth.Pin {
		s += "p"
	}
	if auth.SessionKey {
		s += "s"
	}
	if auth.ClientKey {
		s += "c"
	}
	return s
}

func (c *WWPass) makeRequest(method string, command string, auth AuthFlags, args url.Values) (spfeResponse, error) {

	var r spfeResponse

	targetUrl, err := url.Parse(c.spfe)
	if err != nil {
		return r, fmt.Errorf("issues with SPFE url: %w", err)
	}

	// We only work with json responses around here:
	targetUrl = targetUrl.JoinPath(command + ".json")

	flags := authFlagString(auth)
	if len(flags) > 0 {
		args.Set("auth_type", flags)
	}

	var res *http.Response
	switch method {
	case http.MethodGet:
		targetUrl.RawQuery = args.Encode()
		res, err = c.http.Get(targetUrl.String())
	case http.MethodPost:
		res, err = c.http.Post(targetUrl.String(),
			"application/x-www-form-urlencoded",
			strings.NewReader(args.Encode()))
	default:
		return r, errors.New("methods other than GET and POST not supported")
	}

	if err != nil {
		return r, fmt.Errorf("error making a request to SPFE: %w", err)
	}

	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return r, fmt.Errorf("error reading SPFE response: %w", err)
	}

	err = json.Unmarshal(body, &r)
	if err != nil {
		fmt.Print(string(body))
		return r, fmt.Errorf("error parsing SPFE response: %w", err)
	}

	if !r.Success {
		code := ""
		if r.ErrorCode != "" {
			code = r.ErrorCode + ": "
		}
		return r, fmt.Errorf("error from SPFE: %s%s", code, r.Data)
	}

	if r.Encoding == "base64" {
		binaryData, err := base64.StdEncoding.DecodeString(r.Data)
		if err != nil {
			return r, fmt.Errorf("error decoding base64 response from SPFE: %w", err)
		}
		r.Data = string(binaryData)
	}

	return r, nil
}

// Request a new ticket from SPFE for further authentication operations in the frontend.
//
// ttl sets the ticket's time to live in seconds. Giving a zero value results in SPFE
// picking the default.
//
// Returns the resulting ticket string, and the value of ttl that SPFE responded with.
func (c *WWPass) GetTicket(ttl int, auth AuthFlags) (string, int, error) {
	result, err := c.makeRequest(
		http.MethodGet, "get", auth,
		url.Values{"ttl": []string{strconv.Itoa(ttl)}},
	)
	if err != nil {
		return "", 0, err
	}

	return result.Data, result.Ttl, nil
}

// Get your provider name from SPFE by requesting a ticket and parsing the response.
func (c *WWPass) GetName() (string, error) {
	ticket, _, err := c.GetTicket(0, AuthFlags{})
	if err != nil {
		return "", err
	}
	chunks := strings.Split(ticket, ":")
	if len(chunks) == 1 {
		return "", errors.New("cannot extract service provider name from ticket")

	}
	return chunks[0], nil
}

// Given a ticket, retrieves the PUID from SPFE.
// Trying to get a PUID on a ticket that was not authenticated through the frontend
// results in an error.
//
// Setting finalize to true will result in the ticket being invalidated by this operation.
func (c *WWPass) GetPUID(ticket string, auth AuthFlags, finalize bool) (string, error) {
	args := url.Values{}

	args.Add("ticket", ticket)
	if finalize {
		args.Add("finalize", "1")
	}

	result, err := c.makeRequest(http.MethodGet, "puid", auth, args)
	if err != nil {
		return "", err
	}
	return result.Data, nil
}

// Request a new ticket given an existing ticket that was authenticated through the frontend.
// The new ticket will have the requested ttl, or default if ttl is zero.
//
// Setting finalize to true will result in the old ticket being invalidated by this operation.
func (c *WWPass) PutTicket(ticket string, ttl int, auth AuthFlags, finalize bool) (string, int, error) {

	args := url.Values{}
	args.Add("ttl", strconv.Itoa(ttl))
	args.Add("ticket", ticket)
	if finalize {
		args.Add("finalize", "1")
	}

	result, err := c.makeRequest(http.MethodGet, "put", auth, args)
	if err != nil {
		return "", 0, err
	}
	return result.Data, result.Ttl, nil
}
