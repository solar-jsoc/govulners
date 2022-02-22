package govulners

type Node struct {
	Children []Node `json:"children"`
	CpeMatch []struct {
		Cpe23URI            string   `json:"cpe23Uri"`
		CpeName             []string `json:"cpe_name"`
		VersionEndIncluding string   `json:"versionEndIncluding"`
		Vulnerable          bool     `json:"vulnerable"`
	} `json:"cpe_match"`
	Operator string `json:"operator"`
}

type CVE struct {
	ID             string      `json:"id"`
	VendorID       interface{} `json:"vendorId"`
	Type           string      `json:"type"`
	BulletinFamily string      `json:"bulletinFamily"`
	Title          string      `json:"title"`
	Description    string      `json:"description"`
	Published      Time        `json:"published"`
	Modified       Time        `json:"modified"`
	Lastseen       Time        `json:"lastseen"`
	References     []string    `json:"references"`
	Cvss           struct {
		Score  float64 `json:"score"`
		Vector string  `json:"vector"`
	} `json:"cvss"`
	Cvss2 struct {
		CvssV2 struct {
			AccessComplexity      string  `json:"accessComplexity"`
			AccessVector          string  `json:"accessVector"`
			Authentication        string  `json:"authentication"`
			AvailabilityImpact    string  `json:"availabilityImpact"`
			BaseScore             float64 `json:"baseScore"`
			ConfidentialityImpact string  `json:"confidentialityImpact"`
			IntegrityImpact       string  `json:"integrityImpact"`
			VectorString          string  `json:"vectorString"`
			Version               string  `json:"version"`
		} `json:"cvssV2"`
		ExploitabilityScore     float64 `json:"exploitabilityScore"`
		ImpactScore             float64 `json:"impactScore"`
		ObtainAllPrivilege      bool    `json:"obtainAllPrivilege"`
		ObtainOtherPrivilege    bool    `json:"obtainOtherPrivilege"`
		ObtainUserPrivilege     bool    `json:"obtainUserPrivilege"`
		Severity                string  `json:"severity"`
		UserInteractionRequired bool    `json:"userInteractionRequired"`
	} `json:"cvss2"`
	Cvss3 struct {
		CvssV3 struct {
			Version               string  `json:"version"`
			VectorString          string  `json:"vectorString"`
			AttackVector          string  `json:"attackVector"`
			AttackComplexity      string  `json:"attackComplexity"`
			PrivilegesRequired    string  `json:"privilegesRequired"`
			UserInteraction       string  `json:"userInteraction"`
			Scope                 string  `json:"scope"`
			ConfidentialityImpact string  `json:"confidentialityImpact"`
			IntegrityImpact       string  `json:"integrityImpact"`
			AvailabilityImpact    string  `json:"availabilityImpact"`
			BaseScore             float64 `json:"baseScore"`
			BaseSeverity          string  `json:"baseSeverity"`
		} `json:"cvssV3"`
		ExploitabilityScore float64 `json:"exploitabilityScore"`
		ImpactScore         float64 `json:"impactScore"`
	} `json:"cvss3"`
	Href            string        `json:"href"`
	Reporter        string        `json:"reporter"`
	CVElist         []string      `json:"cvelist"`
	ImmutableFields []interface{} `json:"immutableFields"`
	ViewCount       int           `json:"viewCount"`
	Enchantments    struct {
		Dependencies struct {
			References []struct {
				Type   string   `json:"type"`
				IDList []string `json:"idList"`
			} `json:"references"`
			Rev int `json:"rev"`
		} `json:"dependencies"`
		Score struct {
			Value  float64 `json:"value"`
			Vector string  `json:"vector"`
		} `json:"score"`
		Backreferences struct {
			References []struct {
				Type   string   `json:"type"`
				IDList []string `json:"idList"`
			} `json:"references"`
		} `json:"backreferences"`
		Exploitation struct {
			WildExploitedSources []struct {
				Type   string   `json:"type"`
				IDList []string `json:"idList"`
			} `json:"wildExploitedSources"`
		} `json:"exploitation"`
		VulnersScore FloatString `json:"vulnersScore"`
	} `json:"enchantments"`
	Cpe              []string `json:"cpe"`
	Cpe23            []string `json:"cpe23"`
	Cwe              []string `json:"cwe"`
	AffectedSoftware []struct {
		CpeName  string `json:"cpeName"`
		Name     string `json:"name"`
		Operator string `json:"operator"`
		Version  string `json:"version"`
	} `json:"affectedSoftware"`
	AffectedConfiguration []struct {
		CpeName  string `json:"cpeName"`
		Name     string `json:"name"`
		Operator string `json:"operator"`
		Version  string `json:"version"`
	} `json:"affectedConfiguration"`
	CpeConfiguration struct {
		CVEDataVersion string `json:"CVE_data_version"`
		Nodes          []Node `json:"nodes"`
	} `json:"cpeConfiguration"`
	ExtraReferences []struct {
		Name      string   `json:"name"`
		Refsource string   `json:"refsource"`
		Tags      []string `json:"tags"`
		URL       string   `json:"url"`
	} `json:"extraReferences"`
	State struct {
		Dependencies int `json:"dependencies"`
	} `json:"_state"`
}
