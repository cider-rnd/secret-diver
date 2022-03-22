package main

import (
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/source"
	"github.com/cider-rnd/secret-diver/secret"
	"github.com/h2non/filetype"
	"github.com/owenrumney/go-sarif/sarif"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

//go:embed settings.yaml
var defaultConfig []byte

func main() {

	imageScan := flag.String("image", "", "Image to scan")
	generateSettings := flag.Bool("generate-settings", false, "generates default settings.yaml in current directory")
	settingsFile := flag.String("settings", "./settings.yaml", "Image to scan")
	humanize := flag.Bool("human", false, "Allows humans to use the tool")
	skipGit := flag.Bool("skip-git", true, "Allows to scan git if you would like")
	showSecrets := flag.Bool("show-secrets", true, "Shows secrets")
	output := flag.String("output", "", "Output file")

	secretSanitizerCharacter := flag.String("secret-char", "*", "Secret character to sanitize")
	secretSanitizerRatio := flag.Float64("secret-ratio", 0.7, "Ratio which to mark secrets as false positive")

	flag.Parse()

	if *generateSettings {
		fmt.Println(string(defaultConfig))
		os.Exit(0)
	}

	if *imageScan == "" && *generateSettings != true {
		flag.Usage()
		os.Exit(1)
	}

	var outFile io.Writer = os.Stdout

	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			fmt.Println("Cannot open output file")
		}
		outFile = f
	}

	report, err := sarif.New(sarif.Version210)
	run := sarif.NewRun("secret-diver", "")
	report.AddRun(run)

	bytes, err := ioutil.ReadFile(*settingsFile)
	if err != nil {
		bytes = defaultConfig
	}

	signatures := secret.LoadSignatures(bytes, 0)

	_ = scanFull(imageScan, signatures, run, *skipGit, *showSecrets, *secretSanitizerCharacter, *secretSanitizerRatio)

	if *humanize {
		HumanWrite(report, outFile)
	} else {
		_ = PrettyWrite(report, outFile)
	}
}

func PrettyWrite(sarif *sarif.Report, w io.Writer) error {
	enc := json.NewEncoder(w)

	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	err := enc.Encode(sarif)
	return err
}

func scanFull(imageScan *string, signatures map[string]secret.Signature, run *sarif.Run, skipGit bool, showSecrets bool, secretChar string, secretRatio float64) error {
	theSource, cleanup, err := source.New(*imageScan, nil)
	if err != nil {
		return err
	}
	defer cleanup()

	files := parseImage(theSource)

	for _, f := range files {
		path := string(f.Reference.RealPath)

		if skipGit && (strings.HasPrefix(path, ".git/") || strings.Contains(path, "/.git/")) {
			continue
		}

		contents, err := ioutil.ReadAll(f.Reader)

		kind, _ := filetype.Match(contents)
		if err == nil {
			for _, signature := range signatures {
				results := signature.Check(path, kind, contents, showSecrets, secretChar, secretRatio)
				run.Results = append(run.Results, results...)
			}
		}
	}

	rulesFound := make(map[string]bool)
	for _, result := range run.Results {
		rulesFound[*result.RuleID] = true
	}

	for rule := range rulesFound {
		fullDescription := "Found by pattern ==> " + signatures[rule].SignaturePattern().String()
		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, &sarif.Rule{
			ID:               rule,
			ShortDescription: sarif.NewMultiformatMessageString(*signatures[rule].Description()),
			FullDescription:  sarif.NewMultiformatMessageString(fullDescription),
		})
	}

	return nil
}

func HumanWrite(report *sarif.Report, w io.Writer) {

	for _, r := range report.Runs {
		for _, result := range r.Results {
			for _, location := range result.Locations {

				fmt.Fprintf(w,
					"%s - %s ==> %s\n",
					*result.RuleID,
					*result.Message.Text,
					*location.PhysicalLocation.ArtifactLocation.URI,
				)

				for _, a := range result.Message.Arguments {
					fmt.Fprintf(w, "*****\n%s\n*****\n\n", a)
				}
			}
		}
	}
}

func parseImage(source source.Source) []secret.File {

	var files []secret.File

	switch source.Metadata.Scheme {

	case "DirectoryScheme":
		_ = filepath.WalkDir(source.Metadata.Path, func(path string, info os.DirEntry, err error) error {
			if !info.IsDir() {
				var newFile secret.File
				f, err := os.Open(path)

				if err == nil {
					newFile.Reference = *file.NewFileReference(file.Path(path))
					newFile.Reader = f
					files = append(files, newFile)
				}
			}
			return nil
		})
	default:
		if source.Image != nil {
			for _, layer := range source.Image.Layers {
				for _, reference := range layer.Tree.AllFiles() {
					reader, err := layer.FileContents(reference.RealPath)

					if err == nil {
						files = append(
							files,
							secret.File{
								Reference: reference,
								Reader:    reader,
							},
						)
					}
				}
			}
		}
	}

	return files
}
