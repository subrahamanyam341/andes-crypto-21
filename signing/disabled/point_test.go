package disabled

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/subrahamanyam341/andes-core-21/core/check"
)

func TestDisabledPoint_MethodsShouldNotPanic(t *testing.T) {
	defer func() {
		r := recover()
		if r != nil {
			assert.Fail(t, fmt.Sprintf("should have not panic: %v", r))
		}
	}()

	dp := &disabledPoint{}

	recovBytes, err := dp.MarshalBinary()
	assert.Equal(t, []byte(marshaledPoint), recovBytes)
	assert.Nil(t, err)

	recovBool, err := dp.Equal(nil)
	assert.False(t, recovBool)
	assert.Nil(t, err)

	recovPoint, err := dp.Add(nil)
	assert.Equal(t, dp, recovPoint)
	assert.Nil(t, err)

	recovPoint, err = dp.Sub(nil)
	assert.Equal(t, dp, recovPoint)
	assert.Nil(t, err)

	recovPoint, err = dp.Mul(nil)
	assert.Equal(t, dp, recovPoint)
	assert.Nil(t, err)

	recovPoint, err = dp.Pick()
	assert.Equal(t, dp, recovPoint)
	assert.Nil(t, err)

	assert.Nil(t, dp.UnmarshalBinary(nil))
	assert.Equal(t, dp, dp.Null())
	assert.Nil(t, dp.Set(nil))
	assert.Equal(t, dp, dp.Clone())
	assert.Equal(t, dp, dp.Neg())
	assert.Nil(t, dp.GetUnderlyingObj())
	assert.False(t, check.IfNil(dp))
}
