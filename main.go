package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	"github.com/pkg/errors"

	cmmetav1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func main() {
	groupName := os.Getenv("GROUP_NAME")
	if groupName == "" {
		klog.Fatal("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(groupName, &ispConfigSolver{})
}

// Config is a structure that is used to decode into when solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type Config struct {
	// Change the two fields below according to the format of the configuration
	// to be decoded.
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	APIUrl      string                     `json:"APIUrl"`
	APIUsername cmmetav1.SecretKeySelector `json:"APIUsername"`
	APIPassword cmmetav1.SecretKeySelector `json:"APIPassword"`
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (Config, error) {
	cfg := Config{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

func NewSolver() webhook.Solver {
	return &ispConfigSolver{}
}

type loginCredentials struct {
	Username string
	Password string
}

type DNSZone struct {
	Serial    string `json:"serial"`
	Id        string `json:"id"`
	ServerID  string `json:"server_id"`
	SysUserID string `json:"sys_userid"`
}

type DNSObject struct {
	Code    string    `json:"code"`
	Message string    `json:"message"`
	DNS     []DNSZone `json:"response"`
}

type ClientObject struct {
	Code     string `json:"code"`
	Message  string `json:"message"`
	ClientID int    `json:"response"`
}

// ispConfigSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/jetstack/cert-manager/pkg/acme/webhook.Solver`
// interface.
type ispConfigSolver struct {
	// If a Kubernetes 'clientset' is needed, you must:
	// 1. uncomment the additional `client` field in this structure below
	// 2. uncomment the "k8s.io/client-go/kubernetes" import at the top of the file
	// 3. uncomment the relevant code in the Initialize method below
	// 4. ensure your webhook's service account has the required RBAC role
	//    assigned to it for interacting with the Kubernetes APIs you need.
	client    *kubernetes.Clientset
	sessionID string
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *ispConfigSolver) Name() string {
	return "ISPConfig"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *ispConfigSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	fqdn := ch.ResolvedFQDN
	zone := ch.ResolvedZone
	txtvalue := ch.Key
	apiUrl := cfg.APIUrl

	klog.Infof("Running solver for domain '%s' in zone '%s'\n", fqdn, zone)

	cred, err := c.getCredential(&cfg, ch.ResourceNamespace)
	if err != nil {
		return err
	}

	klog.Infof("Obtaining session from '%s' with user '%s'", apiUrl, cred.Username)

	// Login and get sessionID
	sessionID, err := c.login(ch, cred.Username, cred.Password)
	if err != nil {
		return err
	}

	klog.Info("Session successfully created.\n")

	c.sessionID = sessionID

	var dnsZone DNSObject

	klog.Info("Searching for matching domain in ISPConfig\n")

	// try zones, removing one sub-domain each try, until we find the matching zone in ISPConfig
	for {
		params := map[string]interface{}{"session_id": sessionID, "primary_id": map[string]interface{}{"origin": zone}}

		klog.Infof("Checking zone '%s' (dns_zone_get)\n", zone)

		byts, err := c.callAPI(ch, "dns_zone_get", params, "POST")
		if err != nil {
			return err
		}

		var object DNSObject
		json.Unmarshal([]byte(byts), &object)

		if object.Code != "ok" || len(object.DNS) == 0 {
			if len(strings.Split(zone, ".")) == 3 {
				panic("Zone not found...")
				break
			}
			zone = fmt.Sprintf(strings.Join(strings.Split(zone, ".")[1:], "."))
			continue
		}

		dnsZone = object
		break

	}

	klog.Infof("Matching zone '%s' found\n", zone)

	// Get client_id
	paramsClientID := map[string]interface{}{"session_id": sessionID, "sys_userid": dnsZone.DNS[0].SysUserID}

	clientByts, err := c.callAPI(ch, "client_get_id", paramsClientID, "POST")
	if err != nil {
		return err
	}

	var clientObject ClientObject
	json.Unmarshal([]byte(clientByts), &clientObject)

	currentTime := time.Now()
	stamp := currentTime.Format("2006-01-02 15:04:05")
	clientID := strconv.Itoa(clientObject.ClientID)

	paramsAddTxt := map[string]interface{}{
		"session_id":    sessionID,
		"client_id":     clientID,
		"update_serial": true,
		"params": map[string]interface{}{
			"server_id": dnsZone.DNS[0].ServerID,
			"zone":      dnsZone.DNS[0].Id,
			"name":      fqdn,
			"type":      "txt",
			"data":      txtvalue,
			"aux":       "0",
			"ttl":       "300",
			"active":    "y",
			"stamp":     stamp,
		},
	}

	addTxtByts, err := c.callAPI(ch, "dns_txt_add", paramsAddTxt, "POST")
	if err != nil {
		return err
	}

	klog.V(2).Infof("Response TXT add: %s\n", addTxtByts)

	klog.Info("TXT Record successfully added, returning to caller")
	return nil
}

func (c *ispConfigSolver) login(ch *v1alpha1.ChallengeRequest, username string, password string) (string, error) {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return "", err
	}

	loginParams := map[string]interface{}{"username": username, "password": password, "client_login": false}
	byts, _ := json.Marshal(loginParams)

	req, err := http.NewRequest("POST", cfg.APIUrl+"?login", bytes.NewBuffer(byts))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}

	klog.V(2).Infof("login Response: %v\n", resp)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var result map[string]interface{}
	json.Unmarshal([]byte(body), &result)

	if result["code"] != "ok" {
		return "", fmt.Errorf("%s", result["message"])
	}

	klog.V(2).Infof("login sessionID: %v\n", result["response"])

	defer resp.Body.Close()

	return fmt.Sprintf("%v", result["response"]), nil
}

func (c *ispConfigSolver) callAPI(ch *v1alpha1.ChallengeRequest, function string, params map[string]interface{}, httpType string) ([]byte, error) {
	var data []byte
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return data, err
	}

	byts, _ := json.Marshal(params)
	klog.V(2).Infof("Calling API function %s with %s\n", function, string(byts))
	req, err := http.NewRequest(httpType, cfg.APIUrl+"?"+function, bytes.NewBuffer(byts))
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return data, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return data, err
	}

	var result map[string]interface{}
	json.Unmarshal([]byte(body), &result)

	if result["code"] != "ok" {
		return data, fmt.Errorf("%s", result["message"])
	}

	defer resp.Body.Close()

	return body, nil
}

func (c *ispConfigSolver) getCredential(cfg *Config, ns string) (loginCredentials, error) {
	username, err := c.getSecretData(cfg.APIUsername, ns)
	if err != nil {
		return loginCredentials{}, err
	}

	password, err := c.getSecretData(cfg.APIPassword, ns)
	if err != nil {
		return loginCredentials{}, err
	}

	return loginCredentials{Username: string(username), Password: string(password)}, nil
}

func (c *ispConfigSolver) getSecretData(selector cmmetav1.SecretKeySelector, ns string) ([]byte, error) {
	secret, err := c.client.CoreV1().Secrets(ns).Get(context.TODO(), selector.Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	if data, ok := secret.Data[selector.Key]; ok {
		return data, nil
	}

	return nil, errors.Errorf("no key %q in secret %q", selector.Key, ns+"/"+selector.Name)
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *ispConfigSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	// TODO: add code that deletes a record from the DNS provider's console
	fqdn := ch.ResolvedFQDN

	// Get TXT entry
	paramsGetTxt := map[string]interface{}{
		"session_id": c.sessionID,
		"primary_id": map[string]interface{}{
			"name": fqdn,
			"type": "TXT",
		},
	}

	klog.Infof("Getting TXT entry for '%s'.\n", fqdn)
	getTxtByts, err := c.callAPI(ch, "dns_txt_get", paramsGetTxt, "POST")
	if err != nil {
		return err
	}

	var dnsObject DNSObject
	json.Unmarshal([]byte(getTxtByts), &dnsObject)

	if len(dnsObject.DNS) == 0 {
		klog.Info("Nothing to delete")
		return nil
	}

	paramsDelTxt := map[string]interface{}{
		"session_id":    c.sessionID,
		"primary_id":    dnsObject.DNS[0].Id,
		"update_serial": true,
	}

	klog.Infof("Removing TXT entry for '%s'.\n", fqdn)
	delTxtByts, err := c.callAPI(ch, "dns_txt_delete", paramsDelTxt, "POST")
	if err != nil {
		return err
	}

	klog.V(2).Infof("Response client object: %s\n", delTxtByts)

	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *ispConfigSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = cl

	return nil
}
