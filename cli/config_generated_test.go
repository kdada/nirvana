/*
Copyright 2017 Caicloud Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// This file was autogenerated by set-gen. Do not edit it manually!

package cli

import (
	"reflect"
	"testing"

	"github.com/spf13/cast"
	"github.com/stretchr/testify/assert"
)

func TestGetBool(t *testing.T) {
	Reset()
	testcase := getTestCase("Bool")
	key := "dev"
	v.Set(key, testcase.want)
	want, err := cast.ToBoolE(testcase.want)
	assert.Nil(t, err)
	if got := GetBool(key); !reflect.DeepEqual(got, want) {
		assert.Equal(t, want, got)
	}
}

func TestGetDuration(t *testing.T) {
	Reset()
	testcase := getTestCase("Duration")
	key := "dev"
	v.Set(key, testcase.want)
	want, err := cast.ToDurationE(testcase.want)
	assert.Nil(t, err)
	if got := GetDuration(key); !reflect.DeepEqual(got, want) {
		assert.Equal(t, want, got)
	}
}

func TestGetFloat32(t *testing.T) {
	Reset()
	testcase := getTestCase("Float32")
	key := "dev"
	v.Set(key, testcase.want)
	want, err := cast.ToFloat32E(testcase.want)
	assert.Nil(t, err)
	if got := GetFloat32(key); !reflect.DeepEqual(got, want) {
		assert.Equal(t, want, got)
	}
}

func TestGetFloat64(t *testing.T) {
	Reset()
	testcase := getTestCase("Float64")
	key := "dev"
	v.Set(key, testcase.want)
	want, err := cast.ToFloat64E(testcase.want)
	assert.Nil(t, err)
	if got := GetFloat64(key); !reflect.DeepEqual(got, want) {
		assert.Equal(t, want, got)
	}
}

func TestGetInt(t *testing.T) {
	Reset()
	testcase := getTestCase("Int")
	key := "dev"
	v.Set(key, testcase.want)
	want, err := cast.ToIntE(testcase.want)
	assert.Nil(t, err)
	if got := GetInt(key); !reflect.DeepEqual(got, want) {
		assert.Equal(t, want, got)
	}
}

func TestGetInt32(t *testing.T) {
	Reset()
	testcase := getTestCase("Int32")
	key := "dev"
	v.Set(key, testcase.want)
	want, err := cast.ToInt32E(testcase.want)
	assert.Nil(t, err)
	if got := GetInt32(key); !reflect.DeepEqual(got, want) {
		assert.Equal(t, want, got)
	}
}

func TestGetInt64(t *testing.T) {
	Reset()
	testcase := getTestCase("Int64")
	key := "dev"
	v.Set(key, testcase.want)
	want, err := cast.ToInt64E(testcase.want)
	assert.Nil(t, err)
	if got := GetInt64(key); !reflect.DeepEqual(got, want) {
		assert.Equal(t, want, got)
	}
}

func TestGetString(t *testing.T) {
	Reset()
	testcase := getTestCase("String")
	key := "dev"
	v.Set(key, testcase.want)
	want, err := cast.ToStringE(testcase.want)
	assert.Nil(t, err)
	if got := GetString(key); !reflect.DeepEqual(got, want) {
		assert.Equal(t, want, got)
	}
}

func TestGetStringSlice(t *testing.T) {
	Reset()
	testcase := getTestCase("StringSlice")
	key := "dev"
	v.Set(key, testcase.want)
	want, err := cast.ToStringSliceE(testcase.want)
	assert.Nil(t, err)
	if got := GetStringSlice(key); !reflect.DeepEqual(got, want) {
		assert.Equal(t, want, got)
	}
}

func TestGetUint(t *testing.T) {
	Reset()
	testcase := getTestCase("Uint")
	key := "dev"
	v.Set(key, testcase.want)
	want, err := cast.ToUintE(testcase.want)
	assert.Nil(t, err)
	if got := GetUint(key); !reflect.DeepEqual(got, want) {
		assert.Equal(t, want, got)
	}
}

func TestGetUint32(t *testing.T) {
	Reset()
	testcase := getTestCase("Uint32")
	key := "dev"
	v.Set(key, testcase.want)
	want, err := cast.ToUint32E(testcase.want)
	assert.Nil(t, err)
	if got := GetUint32(key); !reflect.DeepEqual(got, want) {
		assert.Equal(t, want, got)
	}
}

func TestGetUint64(t *testing.T) {
	Reset()
	testcase := getTestCase("Uint64")
	key := "dev"
	v.Set(key, testcase.want)
	want, err := cast.ToUint64E(testcase.want)
	assert.Nil(t, err)
	if got := GetUint64(key); !reflect.DeepEqual(got, want) {
		assert.Equal(t, want, got)
	}
}