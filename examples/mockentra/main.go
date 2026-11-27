// Command mockentra runs a stand-in for Microsoft Entra ID so the sample
// Service API can be tried without a tenant. Development use only.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"hipr/internal/entratest"
)

// Fixed IDs so the commands printed at startup work every time.
const (
	defaultTenant   = "11111111-1111-1111-1111-111111111111"
	apiClientID     = "22222222-2222-2222-2222-222222222222"
	apiAppIDURI     = "api://hipr-sample-api"
	testerClientID  = "33333333-3333-3333-3333-333333333333" // hipr / regression tests
	testerSecret    = "regression-secret"
	noRoleClientID  = "44444444-4444-4444-4444-444444444444" // registered, but never granted a role
	noRoleSecret    = "norole-secret"
	testerObjectID  = "aaaaaaaa-0000-0000-0000-000000000001"
	noRoleObjectID  = "aaaaaaaa-0000-0000-0000-000000000002"
	defaultAddr     = "127.0.0.1:29100"
	sampleAPIAddr   = "127.0.0.1:29010"
	defaultLifetime = time.Hour
)

func main() {
	addr := flag.String("addr", defaultAddr, "listen address")
	tenant := flag.String("tenant", defaultTenant, "tenant ID used in URLs and tokens")
	lifetime := flag.Duration("lifetime", defaultLifetime, "access token lifetime")
	flag.Parse()

	host, port, err := net.SplitHostPort(*addr)
	if err != nil {
		log.Fatal(err)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}

	s, err := entratest.New(*tenant, entratest.API{ClientID: apiClientID, AppIDURI: apiAppIDURI})
	if err != nil {
		log.Fatal(err)
	}
	s.BaseURL = "http://" + net.JoinHostPort(host, port)
	s.Lifetime = *lifetime
	s.Clients[testerClientID] = entratest.Client{Secret: testerSecret, ObjectID: testerObjectID, Roles: []string{"Items.ReadWrite.All"}}
	s.Clients[noRoleClientID] = entratest.Client{Secret: noRoleSecret, ObjectID: noRoleObjectID}

	fmt.Printf(`mockentra listening on %s  (NOT a real identity provider)

  tenant        %s
  authority     %s
  token URL     %s
  Service API   client ID %s, Application ID URI %s

  Confidential clients (client credentials):
    %s  secret %-18s roles: Items.ReadWrite.All
    %s  secret %-18s roles: (none)

Run the sample API against it:
  go run ./examples/serviceapi -authority %s -audience %s,%s

App-only token (what hipr will fetch):
  curl -s %s -d grant_type=client_credentials -d client_id=%s -d client_secret=%s -d scope=%s/.default

Delegated token (stands in for the PKCE sign-in):
  curl -s %s/%s/dev/user-token -d name=alice -d "scp=Items.Read Items.ReadWrite"

Then: curl -H "Authorization: Bearer <access_token>" http://%s/items
`, *addr, s.Tenant, s.Issuer(), s.TokenURL(), apiClientID, apiAppIDURI,
		testerClientID, testerSecret, noRoleClientID, noRoleSecret,
		s.Issuer(), apiClientID, apiAppIDURI,
		s.TokenURL(), testerClientID, testerSecret, apiAppIDURI,
		s.BaseURL, s.Tenant, sampleAPIAddr)

	srv := &http.Server{Addr: *addr, Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
