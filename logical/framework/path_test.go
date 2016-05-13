package framework
import (
	"testing"
	"regexp"
)


func TestGenericNameRegex(t *testing.T) {
	re, err := regexp.Compile(GenericNameRegex("name"))
	if (err != nil) {
		t.Log("Problem compiling regex")
		t.Fail()
	}

	validNames := []string{"foo", "bar", "en", "us"}
	for _, name  := range validNames {
		match := re.MatchString(name)
		if (!match) {
			t.Log("Expected", name, "to match name regex but it didn't")
			t.Fail()
		}

	}


}
