package secret

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/h2non/filetype/types"
	"github.com/owenrumney/go-sarif/sarif"
	"gopkg.in/yaml.v2"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"
)

// Signatures holds a list of all signatures used during the session
var Signatures = make(map[string]Signature)
var FalsePositives []regexp.Regexp
var IgnoreList []regexp.Regexp

// loadSignatureSet will read in the defined signatures from an external source
func loadSignatureSet(content []byte) (SignatureConfig, error) {

	var c SignatureConfig
	err := yaml.Unmarshal(content, &c)
	if err != nil {
		return SignatureConfig{}, err
	}

	return c, nil
}

// get EntropyInt will calculate the entrophy based upon Shannon Entropy
func getEntropyInt(s string) float64 {
	//Shannon Entropy calculation
	m := map[rune]float64{}
	for _, r := range s {
		m[r]++
	}
	var hm float64
	for _, c := range m {
		hm += c * math.Log2(c)
	}
	l := float64(len(s))
	res := math.Log2(l) - hm/l
	return res
}

// Signature is an expression that we are looking for in a file
type Signature interface {
	Description() *string
	Enable() int
	ConfidenceLevel() int
	SignatureID() *string
	Check(path string, kind types.Type, contents []byte, showSecrets bool) []*sarif.Result
	SignaturePattern() *regexp.Regexp
}

// SignaturesMetaData is used by updateSignatures to determine if/how to update the signatures
type SignaturesMetaData struct {
	Date    string
	Time    int
	Version string
}

// PatternSignature holds the information about a pattern signature which is a regex used to match content within a file
type PatternSignature struct {
	comment         string
	description     string
	enable          int
	entropy         float64
	match           *regexp.Regexp
	confidenceLevel int
	path            *regexp.Regexp
	signatureid     string
}

// SignatureDef maps to a signature within the yaml file
type SignatureDef struct {
	Comment         string  `yaml:"comment"`
	Description     string  `yaml:"description"`
	Enable          int     `yaml:"enable"`
	Entropy         float64 `yaml:"entropy"`
	Match           string  `yaml:"match"`
	ConfidenceLevel int     `yaml:"confidence-level"`
	Severity        int     `yaml:"severity"`
	Path            string  `yaml:"path"`
	SignatureID     string  `yaml:"signatureid"`
}

// SignatureConfig holds the base file structure for the signatures file
type SignatureConfig struct {
	Meta   SignaturesMetaData `yaml:"Meta"`
	Ignore []string           `yaml:"Ignore"`
	//PatternSignatures      []SignatureDef     `yaml:"PatternSignatures"`
	Signatures    []SignatureDef `yaml:"Signatures"`
	FalsePositive []string       `yaml:"FalsePositive"`
}

// fetchLineNumber will read a file line by line and when the match is found, save the line number.
// It manages multiple matches in a file by way of the count and an index
func fetchLineNumber(input *[]string, thisMatch string, idx int) int {
	linesOfScannedFile := *input
	lineNumIndexMap := make(map[int]int)

	count := 0

	for i, line := range linesOfScannedFile {
		if strings.Contains(line, thisMatch) {

			// We need to add 1 here as the index starts at zero so every line number would be line -1 normally
			lineNumIndexMap[count] = i + 1
			count = count + 1
		}
	}
	return lineNumIndexMap[idx]
}

// Enable sets whether as signature is active or not
func (s PatternSignature) Enable() int {
	return s.enable
}

// ConfidenceLevel sets the confidence level of the pattern
func (s PatternSignature) ConfidenceLevel() int {
	return s.confidenceLevel
}

// Description sets the user comment of the signature
func (s PatternSignature) Description() *string {
	return &s.description
}

// SignatureID sets the id used to identify the signature. This id is immutable and generated from a has of the signature and is changed with every update to a signature.
func (s PatternSignature) SignatureID() *string {
	return &s.signatureid
}

// SignaturePattern gets the pattern of the signature
func (s PatternSignature) SignaturePattern() *regexp.Regexp {
	return s.match
}

func (s PatternSignature) Check(path string, kind types.Type, contents []byte, showSecrets bool) []*sarif.Result {

	var results []*sarif.Result

	// TODO - Add skip per signature
	if kind.MIME.Type == "application" {
		return results
	}

	for _, r := range IgnoreList {
		if r.MatchString(path) {
			return results
		}
	}

	if s.path != nil {
		if !s.path.MatchString(path) {
			return results
		}
	}

	matches := s.match.FindAllSubmatchIndex(contents, -1)
	if len(matches) > 0 {

		lines := make(map[int]int)

		line := 0
		for i, b := range contents {
			if b == '\n' {
				lines[i] = line
				line++
			}
		}

		keys := make([]int, 0, len(lines))
		for k := range lines {
			keys = append(keys, k)
		}
		sort.Ints(keys)

		for _, match := range matches {

			for len(keys) > 0 {
				if match[0] < keys[0] {
					break
				}
				keys = keys[1:]
			}

			startLine := lines[keys[0]] + 1

			secret := contents[match[0]:match[1]]
			if len(match) > 2 {
				secret = contents[match[2]:match[3]]
			}

			physical := sarif.NewPhysicalLocation()
			physical.ArtifactLocation = sarif.NewSimpleArtifactLocation(path)
			physical.Region = sarif.NewRegion()
			physical.Region.StartLine = &startLine
			location := sarif.NewLocationWithPhysicalLocation(physical)

			var arguments []string

			if showSecrets == true {
				arguments = []string{
					string(secret),
				}
			}

			var partialFingerprints = make(map[string]interface{})

			h := sha256.New()
			h.Write(secret)
			partialFingerprints["SECRET_FINGERPRINT_SHA256"] = hex.EncodeToString(h.Sum(nil))

			result := sarif.Result{
				RuleID: s.SignatureID(),
				Message: sarif.Message{
					Text:      s.Description(),
					Arguments: arguments,
				},
				Locations:           []*sarif.Location{location},
				PartialFingerprints: partialFingerprints,
			}

			isValid := true
			//for _, fp := range FalsePositives {
			//	if fp.Match(match) {
			//		isValid = false
			//		break
			//	}
			//}

			if isValid {
				results = append(results, &result)
			}
		}
	}

	return results
}

// LoadSignatures will load all known signatures for the various match types into the session
func LoadSignatures(content []byte, mLevel int) map[string]Signature {

	if len(Signatures) != 0 {
		return Signatures
	}
	// ensure that we have the proper home directory

	c, err := loadSignatureSet(content)
	if err != nil {
		os.Exit(2)
	}

	for _, i := range c.Ignore {
		r := regexp.MustCompile(i)
		IgnoreList = append(IgnoreList, *r)
	}

	for _, fp := range c.FalsePositive {
		r := regexp.MustCompile(fp)
		FalsePositives = append(FalsePositives, *r)
	}

	for _, curSig := range c.Signatures {
		if curSig.Enable > 0 && curSig.ConfidenceLevel >= mLevel {
			match := regexp.MustCompile(curSig.Match)
			var path *regexp.Regexp
			if curSig.Path != "" {
				path = regexp.MustCompile(curSig.Path)
			}

			Signatures[curSig.SignatureID] = PatternSignature{
				curSig.Comment,
				curSig.Description,
				curSig.Enable,
				curSig.Entropy,
				match,
				curSig.ConfidenceLevel,
				path,
				curSig.SignatureID,
			}
		}
	}

	return Signatures
}
