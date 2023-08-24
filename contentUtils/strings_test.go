package contentUtils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Contains(t *testing.T) {
	testAssertTrueArray := []string{"1", "2", "apple"}
	testAssertTrueString := "apple"
	testAssertFalseArray := []string{"1", "2"}

	assertTrueContains := Contains(testAssertTrueArray, testAssertTrueString)
	assertFalseContains := Contains(testAssertFalseArray, testAssertTrueString)
	assert.True(t, assertTrueContains)
	assert.False(t, assertFalseContains)

}
