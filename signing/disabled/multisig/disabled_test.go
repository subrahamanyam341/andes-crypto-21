package multisig

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/subrahamanyam341/andes-core-21/core/check"
)

func TestDisabledMultiSig_MethodsShouldNotPanic(t *testing.T) {
	defer func() {
		r := recover()
		if r != nil {
			assert.Fail(t, fmt.Sprintf("should have not panic: %v", r))
		}
	}()

	dms := &DisabledMultiSig{}
	recoveredBytes, err := dms.CreateSignatureShare(nil, nil)
	assert.Equal(t, []byte(signature), recoveredBytes)
	assert.Nil(t, err)

	recoveredBytes, err = dms.AggregateSigs(nil, nil)
	assert.Equal(t, []byte(signature), recoveredBytes)
	assert.Nil(t, err)

	assert.Nil(t, dms.VerifySignatureShare(nil, nil, nil))
	assert.False(t, check.IfNil(dms))
	assert.Nil(t, dms.VerifyAggregatedSig(nil, nil, nil))
}
