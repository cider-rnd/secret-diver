package main

import (
	_ "embed"
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
)

//go:embed settings.yaml
var defaultConfig []byte

func main() {

	imageScan := flag.String("image", "", "Image to scan")
	generateSettings := flag.Bool("generate-settings", false, "generates default settings.yaml in current directory")
	settingsfile := flag.String("settings", "./settings.yaml", "Image to scan")
	humanize := flag.Bool("human", false, "Allows humans to use the tool")
	output := flag.String("output", "", "Output file")

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
	run := sarif.NewRun("secret-docker", "")
	report.AddRun(run)

	bytes, err := ioutil.ReadFile(*settingsfile)
	if err != nil {
		bytes = defaultConfig
	}

	signatures := secret.LoadSignatures(bytes, 0)

	_ = scanFull(imageScan, signatures, run)

	if *humanize {
		HumanWrite(report, outFile)
	} else {
		_ = report.PrettyWrite(outFile)
	}
}

func scanFull(imageScan *string, signatures []secret.Signature, run *sarif.Run) error {
	theSource, cleanup, err := source.New(*imageScan, nil)
	if err != nil {
		return err
	}
	defer cleanup()

	files := parseImage(theSource)

	for _, file := range files {
		path := string(file.Reference.RealPath)

		contents, err := ioutil.ReadAll(file.Reader)

		kind, _ := filetype.Match(contents)
		if err == nil {
			for _, signature := range signatures {
				results := signature.Check(path, kind, contents)
				run.Results = append(run.Results, results...)
			}
		}
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
