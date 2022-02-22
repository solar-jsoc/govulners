package govulners

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
)

const (
	apiURL = "https://vulners.com"

	defaultLimit = 20
	maxLimit     = 10000

	resultError = "error"
)

var (
	defaultFields = []string{
		"id",
		"title",
		"description",
		"type",
		"bulletinFamily",
		"cvss",
		"published",
		"modified",
		"lastseen",
		"href",
		"sourceHref",
		"sourceData",
		"cvelist",
	}
)

type Package struct {
	Software string
	Version  string
}

type Vulenrs struct {
	apikey string
	debug  bool
	logger Logger
	http   HTTPClient
}

func New(apikey string, opts ...Option) *Vulenrs {
	options := Options{
		logger:     log.Default(),
		httpClient: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(&options)
	}

	return &Vulenrs{
		apikey: apikey,
		logger: options.logger,
		http:   options.httpClient,
	}
}

// SetDebug set debug flag
func (v *Vulenrs) SetDebug(debug bool) {
	v.debug = debug
}

func (v *Vulenrs) do(request *http.Request, dst interface{}) error {
	response, err := v.http.Do(request)
	if err != nil {
		return err
	}

	if response.Body != nil {
		defer response.Body.Close()
	}

	if response.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("HTTP status: %d", response.StatusCode)
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}
	if v.debug {
		v.logger.Println(string(body))
	}

	r := Response{}
	err = json.Unmarshal(body, &r)
	if err != nil {
		return err
	}
	if r.Result == resultError {
		return v.handleError(r)
	}

	if dst == nil {
		return nil
	}

	return json.Unmarshal(r.Data, dst)
}

func (v *Vulenrs) handleError(r Response) error {
	e := Error{}
	err := json.Unmarshal(r.Data, &e)
	if err != nil {
		return err
	}

	return e
}

func (v *Vulenrs) get(path string, values url.Values, dst interface{}) error {
	values.Add("apiKey", v.apikey)
	request, err := http.NewRequest(http.MethodGet, apiURL+path+"?"+values.Encode(), nil)
	if err != nil {
		return err
	}
	if v.debug {
		v.logger.Println(request.Method, request.URL.String())
	}

	return v.do(request, dst)
}

func (v *Vulenrs) post(path string, data map[string]interface{}, dst interface{}) error {
	data["apiKey"] = v.apikey
	body, err := json.Marshal(data)
	if err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodPost, apiURL+path, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	request.Header.Add("Content-Type", "application/json")

	if v.debug {
		v.logger.Println(request.Method, request.URL.String())
		v.logger.Println(string(body))
	}

	return v.do(request, dst)
}

func (v *Vulenrs) search(query string, skip, size int, fields []string, dst interface{}) error {
	return v.post("/api/v3/search/lucene/", map[string]interface{}{
		"query":  query,
		"skip":   skip,
		"size":   size,
		"fields": fields,
	}, dst)
}

// GetSoftwareVulnerabilities find software vulnerabilities using name and version.
func (v *Vulenrs) GetSoftwareVulnerabilities(name, version string) ([]CVE, error) {
	response := SearchResponse{}
	err := v.post("/api/v3/burp/software/", map[string]interface{}{
		"type":     "software",
		"software": name,
		"version":  version,
	}, &response)
	if err != nil {
		return nil, err
	}

	cves := make([]CVE, len(response.Search))
	for i := range response.Search {
		cves[i] = response.Search[i].Source
	}

	return cves, nil
}

// GetCPEVulnerabilities find software vulnerabilities using CPE string.
// See CPE references at https://cpe.mitre.org/specification/
func (v *Vulenrs) GetCPEVulnerabilities(cpe string) ([]CVE, error) {
	version, err := getCPEversion(cpe)
	if err != nil {
		return nil, err
	}

	response := SearchResponse{}
	err = v.post("/api/v3/burp/software/", map[string]interface{}{
		"type":     "cpe",
		"software": cpe,
		"version":  version,
	}, &response)
	if err != nil {
		return nil, err
	}

	cves := make([]CVE, len(response.Search))
	for i := range response.Search {
		cves[i] = response.Search[i].Source
	}

	return cves, nil
}

// GetMultipleBulletins fetch multiple bulletins by ids.
func (v *Vulenrs) GetMultipleBulletins(ids []string, fields []string) (map[string]CVE, error) {
	if len(fields) == 0 {
		fields = defaultFields
	}

	response := CVEsResponse{}
	err := v.post("/api/v3/search/id/", map[string]interface{}{
		"id":     ids,
		"fields": fields,
	}, &response)
	if err != nil {
		return nil, err
	}

	return response.Documents, nil
}

// GetBulletin fetch bulletin by id.
func (v *Vulenrs) GetBulletin(id string, fields []string) (*CVE, error) {
	cves, err := v.GetMultipleBulletins([]string{id}, fields)
	if err != nil {
		return nil, err
	}

	if cve, ok := cves[id]; ok {
		return &cve, nil
	}

	return nil, nil
}

func getCPEversion(cpe string) (string, error) {
	index := 4
	if strings.HasPrefix(cpe, "cpe:2.3") {
		index = 5
	}

	splits := strings.Split(cpe, ":")
	if len(splits) <= index {
		return "", fmt.Errorf("Malformed cpe: %s", cpe)
	}

	return splits[index], nil
}
