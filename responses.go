package govulners

import (
	"encoding/json"
)

type Response struct {
	Result string          `json:"result"`
	Data   json.RawMessage `json:"data"`
}

type CVEsResponse struct {
	Documents map[string]CVE `json:"documents"`
}

type SearchResponse struct {
	Search []struct {
		ID      string `json:"id"`
		DocType string `json:"doc_type"`
		Source  CVE    `json:"_source"`
	} `json:"search"`
}
