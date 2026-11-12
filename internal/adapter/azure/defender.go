package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

const (
	// NameDefender is the registry name and evidence source of the Defender adapter.
	NameDefender = "defender_tvm"

	huntingPath = "/v1.0/security/runHuntingQuery"

	// StatSkippedBadRow counts hunting rows without a usable device or thumbprint.
	StatSkippedBadRow = "skipped_bad_row"
	// StatNotDue counts syncs skipped because min_interval has not passed.
	StatNotDue = "not_due"
)

func init() {
	adapter.Register(NameDefender, func(env adapter.Env) adapter.Adapter {
		return &Defender{base{env: env, desc: adapter.Description{
			Name:        NameDefender,
			Source:      NameDefender,
			Summary:     "Microsoft Defender Vulnerability Management certificate inventory (DeviceTvmCertificateInfo) via Advanced Hunting (read-only)",
			Settings:    []string{"auth", "tenant_id", "client_id", "page_size", "min_interval", "rate_per_second"},
			Credentials: []string{CredClientSecret},
		}}}
	})
}

// Defender reads the certificate inventory Defender Vulnerability
// Management keeps for onboarded devices (FR-DISC-030), with the Microsoft
// Graph Advanced Hunting API. Permission: Microsoft Graph application
// permission ThreatHunting.Read.All. Graph allows about 45 hunting calls a
// minute; the default rate is one call every two seconds.
type Defender struct{ base }

// Validate checks the configuration.
func (a *Defender) Validate(cfg adapter.Config) error {
	if err := validateAuth(cfg); err != nil {
		return err
	}
	if _, err := pageSize(cfg); err != nil {
		return err
	}
	_, err := minInterval(cfg)
	return err
}

func pageSize(cfg adapter.Config) (int, error) {
	n, err := strconv.Atoi(cfg.Setting("page_size", "10000"))
	if err != nil || n < 1 || n > 100000 {
		return 0, errors.New("page_size must be an integer in [1, 100000]")
	}
	return n, nil
}

func minInterval(cfg adapter.Config) (time.Duration, error) {
	d, err := time.ParseDuration(cfg.Setting("min_interval", "24h"))
	if err != nil || d < 0 {
		return 0, errors.New("min_interval must be a duration such as 24h")
	}
	return d, nil
}

// defenderCursor: DeviceTvmCertificateInfo is a snapshot table without a
// change time, so the delta is "a full inventory at most every
// min_interval". The core de-duplicates unchanged observations.
type defenderCursor struct {
	LastFull *time.Time `json:"last_full,omitempty"`
}

type huntingRow struct {
	Key                string          `json:"MeiscopeKey"`
	DeviceID           string          `json:"DeviceId"`
	DeviceName         string          `json:"DeviceName"`
	Thumbprint         string          `json:"Thumbprint"`
	Path               string          `json:"Path"`
	SerialNumber       string          `json:"SerialNumber"`
	IssuedTo           string          `json:"IssuedTo"`
	IssuedBy           string          `json:"IssuedBy"`
	IssueDate          string          `json:"IssueDate"`
	ExpirationDate     string          `json:"ExpirationDate"`
	KeySize            json.RawMessage `json:"KeySize"`
	SignatureAlgorithm string          `json:"SignatureAlgorithm"`
}

type huntingAnswer struct {
	Results []huntingRow `json:"results"`
}

// keysetPattern is the shape of MeiscopeKey: device ID, thumbprint and the
// SHA-256 of the path, joined by "|". Only a key of this shape is placed
// back into a query.
var keysetPattern = regexp.MustCompile(`^[0-9A-Za-z]{1,64}\|[0-9A-Fa-f]{40}\|[0-9a-f]{64}$`)

// huntingQuery is a keyset-paged read of the certificate inventory, newest
// device name joined from DeviceInfo.
func huntingQuery(after string, n int) string {
	return `DeviceTvmCertificateInfo
| extend MeiscopeKey = strcat(DeviceId, "|", Thumbprint, "|", hash_sha256(Path))
| where strcmp(MeiscopeKey, "` + after + `") > 0
| join kind=leftouter (DeviceInfo | summarize arg_max(Timestamp, DeviceName) by DeviceId) on DeviceId
| order by MeiscopeKey asc
| take ` + strconv.Itoa(n) + `
| project MeiscopeKey, DeviceId, DeviceName, Thumbprint, Path, SerialNumber, IssuedTo, IssuedBy, IssueDate, ExpirationDate, KeySize, SignatureAlgorithm`
}

// Sync reads the whole inventory when min_interval has passed.
func (a *Defender) Sync(ctx context.Context, cfg adapter.Config, since adapter.Cursor) (adapter.Result, error) {
	cur := defenderCursor{}
	if err := adapter.DecodeCursor(since, &cur); err != nil {
		return adapter.Result{}, err
	}
	n, err := pageSize(cfg)
	if err != nil {
		return adapter.Result{}, err
	}
	every, err := minInterval(cfg)
	if err != nil {
		return adapter.Result{}, err
	}
	now := a.now()
	st := map[string]int{}
	if cur.LastFull != nil && now.Sub(*cur.LastFull) < every {
		st[StatNotDue]++
		return a.finish(cfg, nil, st, since, since), nil
	}
	c := a.newClient(cfg, 0.5)
	rows, err := adapter.Paginate(ctx, 0, func(ctx context.Context, after string) (adapter.Page[huntingRow], error) {
		body, err := json.Marshal(map[string]string{"Query": huntingQuery(after, n)})
		if err != nil {
			return adapter.Page[huntingRow]{}, err
		}
		var ans huntingAnswer
		if err := c.do(ctx, http.MethodPost, "https://"+graphHost+huntingPath, scopeGraph, body, &ans); err != nil {
			return adapter.Page[huntingRow]{}, err
		}
		p := adapter.Page[huntingRow]{Items: ans.Results}
		if len(ans.Results) >= n {
			last := ans.Results[len(ans.Results)-1].Key
			if !keysetPattern.MatchString(last) {
				return adapter.Page[huntingRow]{}, errors.New("defender: unexpected MeiscopeKey in hunting results")
			}
			p.Next = last
		}
		return p, nil
	})
	if err != nil {
		return adapter.Result{}, fmt.Errorf("defender certificate inventory: %w", err)
	}
	var obs []submit.Observation
	for _, r := range rows {
		if o, ok := a.mapRow(r, now); ok {
			obs = append(obs, o)
		} else {
			st[StatSkippedBadRow]++
		}
	}
	mergeStats(st, c.stats)
	next, err := adapter.EncodeCursor(defenderCursor{LastFull: &now})
	if err != nil {
		return adapter.Result{}, err
	}
	return a.finish(cfg, obs, st, next, since), nil
}

var (
	// HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates\<store>\...
	hklmStore = regexp.MustCompile(`(?i)^(?:HKEY_LOCAL_MACHINE|HKLM)\\SOFTWARE\\(?:Policies\\)?Microsoft\\SystemCertificates\\([^\\]+)`)
	// HKEY_USERS\<sid>\SOFTWARE\Microsoft\SystemCertificates\<store>\...
	hkuStore = regexp.MustCompile(`(?i)^(?:HKEY_USERS|HKU)\\[^\\]+\\SOFTWARE\\(?:Policies\\)?Microsoft\\SystemCertificates\\([^\\]+)`)
	winAbs   = regexp.MustCompile(`^[A-Za-z]:\\`)
	hostOK   = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,252}$`)
)

// storeOf maps a Defender certificate path to the contract's store locator.
func storeOf(path string) string {
	if m := hklmStore.FindStringSubmatch(path); m != nil {
		return "windows/LocalMachine/" + m[1]
	}
	if m := hkuStore.FindStringSubmatch(path); m != nil {
		return "windows/CurrentUser/" + m[1]
	}
	return "windows/defender/other"
}

func (a *Defender) mapRow(r huntingRow, now time.Time) (submit.Observation, bool) {
	tp := normThumbprint(r.Thumbprint)
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r.DeviceName), "."))
	if host == "" {
		host = strings.ToLower(r.DeviceID)
	}
	if tp == "" || !hostOK.MatchString(host) {
		return submit.Observation{}, false
	}
	meta := &submit.CertificateMetadata{
		SHA1:             tp,
		Serial:           strings.ToLower(strings.TrimSpace(r.SerialNumber)),
		Subject:          r.IssuedTo,
		Issuer:           r.IssuedBy,
		CommonName:       r.IssuedTo,
		NotBefore:        parseTime(r.IssueDate),
		NotAfter:         parseTime(r.ExpirationDate),
		SigningAlgorithm: r.SignatureAlgorithm,
	}
	if ks := strings.Trim(string(r.KeySize), `"`); ks != "" && ks != "null" {
		if n, err := strconv.Atoi(ks); err == nil && n > 0 {
			meta.KeyStrength = strconv.Itoa(n)
		}
	}
	o := submit.Observation{
		Target:     submit.Target{Kind: submit.KindStore, Host: host, Store: storeOf(r.Path)},
		Method:     submit.MethodAdapter,
		ObservedAt: now,
		Outcome:    submit.OutcomeCertSeen,
		Adapter: &submit.AdapterEvidence{
			Source:      NameDefender,
			Certificate: meta,
			Custody:     &submit.Custody{KeyCustody: submit.KeyUnknown},
		},
	}
	if winAbs.MatchString(r.Path) && len(r.Path) <= 4096 {
		o.Target.Path = r.Path
	}
	return o, true
}
