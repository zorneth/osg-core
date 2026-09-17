// Package defaults holds shared ports, guest paths, and image names used across osg modules.
package defaults

import (
	"fmt"
	"time"
)

// Well-known TCP ports.
const (
	ProxyPort    = 3128
	GatewayPort  = 7443
	NoVNCPort    = 6080
	GuestSSHPort = 2222
	HTTPSPort    = 443
	HTTPPort     = 80
)

// GatewayListen is the default osg-gateway bind address.
const GatewayListen = "127.0.0.1:7443"

// ProxyListenHost is used when binding the sidecar on all interfaces inside the netns.
const ProxyListenHost = "0.0.0.0"

// Guest filesystem layout inside sandboxes.
const (
	GuestRoot   = "/osg"
	GuestData   = "/osg/data"
	GuestHome   = "/osg/data/home"
	GuestBin    = "/osg/data/bin"
	GuestCADir  = "/osg/ca"
	GuestCAFile = "/osg/ca/ca.pem"
	GuestPolicy = "/osg/policy.yaml"
	GuestInit   = "/osg/osg-init"
	GuestPath   = "/osg/data/home/.local/bin:/osg/data/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

	// GuestEtcOSG is the reserved control tree for agent guidance (skills, payload).
	// Same role as OpenShell's /etc/openshell; osg naming, MIT-owned content.
	GuestEtcOSG       = "/etc/osg"
	GuestSkills       = "/etc/osg/skills"
	GuestAgentPayload = "/etc/osg/agent-payload"

	// GuestSandboxHome mirrors OpenShell harness HOME (/sandbox/home).
	// Symlinked to GuestHome on agent-config install so persist volume stays canonical.
	GuestSandboxRoot = "/sandbox"
	GuestSandboxHome = "/sandbox/home"
)

// NoProxyValue is the default NO_PROXY / no_proxy list for sandbox guests.
const NoProxyValue = "localhost,127.0.0.1,::1"

// Sandbox image tags (local dev) and GHCR catalog (OpenShell-style paths).
const (
	ImageDebian = "debian:bookworm"
	ImageLocal  = "osg-sandbox:local"
	ImageGUI    = "osg-sandbox:gui"
	ImageGPU    = "osg-sandbox:gpu"
	ImageCursor = "osg-sandbox:cursor"
	ImageClaude = "osg-sandbox:claude"
	ImageCodex  = "osg-sandbox:codex"

	// GHCR: separate image per flavor (like openshell-community/sandboxes/<name>).
	GHCROrg        = "ghcr.io/zorneth"
	GHCRGateway    = GHCROrg + "/osg/gateway"
	GHCRSandboxes  = GHCROrg + "/osg/sandboxes"
	ImageBaseRef   = GHCRSandboxes + "/base:latest"
	ImageGUIRef    = GHCRSandboxes + "/gui:latest"
	ImageGPURef    = GHCRSandboxes + "/gpu:latest"
	ImageCursorRef = GHCRSandboxes + "/cursor:latest"
	ImageClaudeRef = GHCRSandboxes + "/claude:latest"
	ImageCodexRef  = GHCRSandboxes + "/codex:latest"
)

// Guest SSH layout (osg-sshd).
const (
	GuestSSHDir            = "/osg/ssh"
	GuestSSHAuthorizedKeys = "/osg/ssh/authorized_keys"
	GuestSSHHostKey        = "/osg/ssh/host_ed25519"
)

// HeaderBinary is an optional HTTP header naming the egress client binary (tests / ops).
const HeaderBinary = "X-OSG-Binary"

// EnvTrustBinaryHeader enables trusting HeaderBinary when set to 1/true/yes.
const EnvTrustBinaryHeader = "OSG_TRUST_BINARY_HEADER"

// RelayClientTimeout is the CLI/SDK wait for a gateway relay exec round-trip.
const RelayClientTimeout = 70 * time.Second

// ProxyEnvKeys lists host proxy variables forwarded into the sidecar (not the guest agent).
var ProxyEnvKeys = []string{
	"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
	"http_proxy", "https_proxy", "all_proxy", "no_proxy",
}

// ProxyListenLocal returns 127.0.0.1:<ProxyPort>.
func ProxyListenLocal() string {
	return fmt.Sprintf("127.0.0.1:%d", ProxyPort)
}
