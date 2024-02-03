package singlesig

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/subrahamanyam341/andes-core-21/core/check"
)

func TestDisabledSingleSig_MethodsShouldNotPanic(t *testing.T) {
	defer func() {
		r := recover()
		if r != nil {
			assert.Fail(t, fmt.Sprintf("should have not panic: %v", r))
		}
	}()

	dss := &DisabledSingleSig{}

	recovBytes, err := dss.Sign(nil, nil)
	assert.Equal(t, []byte(signature), recovBytes)
	assert.Nil(t, err)

	assert.Nil(t, dss.Verify(nil, nil, nil))
	assert.False(t, check.IfNil(dss))
}
