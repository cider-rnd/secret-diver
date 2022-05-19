package main

import (
	"github.com/cider-rnd/secret-diver/secret"
	"github.com/owenrumney/go-sarif/sarif"
	"io/ioutil"
	"os"
	"testing"
)

func isError(err error, t *testing.T) {
	if err != nil {
		t.Errorf("env var problem = %v", err)
	}
}

func Test_scanFull(t *testing.T) {
	err1 := os.Setenv("SECRET_1", "{\"match\":\"TEST(.*)\",\"name\":\"TEST\",\"description\":\"TEST\",\"signatureid\":\"TEST\",\"enable\":1,\"severity\":1, \"comment\":\"TEST\", \"entropy\":1}")
	isError(err1, t)

	err2 := os.Setenv("SECRET_!", "{\"match\":\"PASSWORD=(a!AO)\",\"name\":\"TEST\",\"description\":\"TEST\",\"signatureid\":\"PASSWORD\",\"enable\":1,\"severity\":6, \"comment\":\"TEST\", \"entropy\":1}")
	isError(err2, t)

	err3 := os.Setenv("SECRET_AAAAA", "{\"match\":\"PASSWORD=(.*)\",\"name\":\"TEST\",\"description\":\"TEST\",\"signatureid\":\"PASSWORD\",\"enable\":1,\"severity\":6, \"comment\":\"TEST\", \"entropy\":1}")
	isError(err3, t)

	err4 := os.Setenv("SECRET_", "{\"match\":\"[0-9A-F]+\",\"name\":\"TEST\",\"description\":\"TEST\",\"signatureid\":\"PASSWORD\",\"enable\":1,\"severity\":6, \"comment\":\"TEST\", \"entropy\":1}")
	isError(err4, t)

	bytes, err := ioutil.ReadFile("./settings.yaml")
	if err != nil {
		bytes = defaultConfig
	}

	signatures := secret.LoadSignatures(bytes, 0, false)

	run := sarif.NewRun("secret-diver", "")

	s := "dir:./test"
	err = scanFull(&s, signatures, run, false, true, "", 0)
	if err != nil {
		t.Errorf("scanFull() error = %v", err)
	}

	if len(run.Results) == 0 {
		t.Errorf("scanFull() error = empty results")
	}

	for _, result := range run.Results {
		if len(result.Message.Arguments) == 0 {
			t.Errorf("no match")
		}
	}
}
