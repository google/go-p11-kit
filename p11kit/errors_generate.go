// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build ignore
//go:build ignore

package main

import (
	"bytes"
	"go/format"
	"log"
	"os"
	"strings"
	"text/template"
)

// Copied from http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/csd02/pkcs11-base-v2.40-csd02.html#_Toc385435538
const ckrRaw = `
#define CKR_OK                            0x00000000UL

#define CKR_CANCEL                        0x00000001UL

#define CKR_HOST_MEMORY                   0x00000002UL

#define CKR_SLOT_ID_INVALID               0x00000003UL

#define CKR_GENERAL_ERROR                 0x00000005UL

#define CKR_FUNCTION_FAILED               0x00000006UL

#define CKR_ARGUMENTS_BAD                 0x00000007UL

#define CKR_NO_EVENT                      0x00000008UL

#define CKR_NEED_TO_CREATE_THREADS        0x00000009UL

#define CKR_CANT_LOCK                     0x0000000AUL

#define CKR_ATTRIBUTE_READ_ONLY           0x00000010UL

#define CKR_ATTRIBUTE_SENSITIVE           0x00000011UL

#define CKR_ATTRIBUTE_TYPE_INVALID        0x00000012UL

#define CKR_ATTRIBUTE_VALUE_INVALID       0x00000013UL

#define CKR_COPY_PROHIBITED               0x0000001AUL

#define CKR_ACTION_PROHIBITED             0x0000001BUL

#define CKR_DATA_INVALID                  0x00000020UL

#define CKR_DATA_LEN_RANGE                0x00000021UL

#define CKR_DEVICE_ERROR                  0x00000030UL

#define CKR_DEVICE_MEMORY                 0x00000031UL

#define CKR_DEVICE_REMOVED                0x00000032UL

#define CKR_ENCRYPTED_DATA_INVALID        0x00000040UL

#define CKR_ENCRYPTED_DATA_LEN_RANGE      0x00000041UL

#define CKR_FUNCTION_CANCELED             0x00000050UL

#define CKR_FUNCTION_NOT_PARALLEL         0x00000051UL

#define CKR_FUNCTION_NOT_SUPPORTED        0x00000054UL

#define CKR_KEY_HANDLE_INVALID            0x00000060UL

#define CKR_KEY_SIZE_RANGE                0x00000062UL

#define CKR_KEY_TYPE_INCONSISTENT         0x00000063UL

#define CKR_KEY_NOT_NEEDED                0x00000064UL

#define CKR_KEY_CHANGED                   0x00000065UL

#define CKR_KEY_NEEDED                    0x00000066UL

#define CKR_KEY_INDIGESTIBLE              0x00000067UL

#define CKR_KEY_FUNCTION_NOT_PERMITTED    0x00000068UL

#define CKR_KEY_NOT_WRAPPABLE             0x00000069UL

#define CKR_KEY_UNEXTRACTABLE             0x0000006AUL

#define CKR_MECHANISM_INVALID             0x00000070UL

#define CKR_MECHANISM_PARAM_INVALID       0x00000071UL

#define CKR_OBJECT_HANDLE_INVALID         0x00000082UL

#define CKR_OPERATION_ACTIVE              0x00000090UL

#define CKR_OPERATION_NOT_INITIALIZED     0x00000091UL

#define CKR_PIN_INCORRECT                 0x000000A0UL

#define CKR_PIN_INVALID                   0x000000A1UL

#define CKR_PIN_LEN_RANGE                 0x000000A2UL

#define CKR_PIN_EXPIRED                   0x000000A3UL

#define CKR_PIN_LOCKED                    0x000000A4UL

#define CKR_SESSION_CLOSED                0x000000B0UL

#define CKR_SESSION_COUNT                 0x000000B1UL

#define CKR_SESSION_HANDLE_INVALID        0x000000B3UL

#define CKR_SESSION_PARALLEL_NOT_SUPPORTED 0x000000B4UL

#define CKR_SESSION_READ_ONLY             0x000000B5UL

#define CKR_SESSION_EXISTS                0x000000B6UL

#define CKR_SESSION_READ_ONLY_EXISTS      0x000000B7UL

#define CKR_SESSION_READ_WRITE_SO_EXISTS  0x000000B8UL

#define CKR_SIGNATURE_INVALID             0x000000C0UL

#define CKR_SIGNATURE_LEN_RANGE           0x000000C1UL

#define CKR_TEMPLATE_INCOMPLETE           0x000000D0UL

#define CKR_TEMPLATE_INCONSISTENT         0x000000D1UL

#define CKR_TOKEN_NOT_PRESENT             0x000000E0UL

#define CKR_TOKEN_NOT_RECOGNIZED          0x000000E1UL

#define CKR_TOKEN_WRITE_PROTECTED         0x000000E2UL

#define CKR_UNWRAPPING_KEY_HANDLE_INVALID 0x000000F0UL

#define CKR_UNWRAPPING_KEY_SIZE_RANGE     0x000000F1UL

#define CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT  0x000000F2UL

#define CKR_USER_ALREADY_LOGGED_IN        0x00000100UL

#define CKR_USER_NOT_LOGGED_IN            0x00000101UL

#define CKR_USER_PIN_NOT_INITIALIZED      0x00000102UL

#define CKR_USER_TYPE_INVALID             0x00000103UL

#define CKR_USER_ANOTHER_ALREADY_LOGGED_IN 0x00000104UL

#define CKR_USER_TOO_MANY_TYPES           0x00000105UL

#define CKR_WRAPPED_KEY_INVALID           0x00000110UL

#define CKR_WRAPPED_KEY_LEN_RANGE         0x00000112UL

#define CKR_WRAPPING_KEY_HANDLE_INVALID   0x00000113UL

#define CKR_WRAPPING_KEY_SIZE_RANGE       0x00000114UL

#define CKR_WRAPPING_KEY_TYPE_INCONSISTENT 0x00000115UL

#define CKR_RANDOM_SEED_NOT_SUPPORTED     0x00000120UL

#define CKR_RANDOM_NO_RNG                 0x00000121UL

#define CKR_DOMAIN_PARAMS_INVALID         0x00000130UL

#define CKR_CURVE_NOT_SUPPORTED           0x00000140UL

#define CKR_BUFFER_TOO_SMALL              0x00000150UL

#define CKR_SAVED_STATE_INVALID           0x00000160UL

#define CKR_INFORMATION_SENSITIVE         0x00000170UL

#define CKR_STATE_UNSAVEABLE              0x00000180UL

#define CKR_CRYPTOKI_NOT_INITIALIZED      0x00000190UL

#define CKR_CRYPTOKI_ALREADY_INITIALIZED  0x00000191UL

#define CKR_MUTEX_BAD                     0x000001A0UL

#define CKR_MUTEX_NOT_LOCKED              0x000001A1UL

#define CKR_FUNCTION_REJECTED             0x00000200UL

#define CKR_VENDOR_DEFINED                0x80000000UL
`

var tmpl = template.Must(template.New("errors.go").Parse(`// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by errors_generate.go; DO NOT EDIT.

//go:generate go run errors_generate.go

package p11kit

import "fmt"

// pkcs11Error represents a PKCS #11 return code.
type pkcs11Error uint64

// Error returns the spec name of the error.
func (e pkcs11Error) Error() string {
	if s, ok := errStrings[e]; ok {
		return s
	}
	return fmt.Sprintf("unknown pkcs11 error: 0x%08x", uint64(e))
}

var errStrings = map[pkcs11Error]string{
{{ range . }}{{ .GoName }}: "{{ .SpecName }}",
{{ end }}
}

// Error codes defined PKCS #11.
//
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/csd02/pkcs11-base-v2.40-csd02.html#_Toc385435538
const (
{{ range . }}{{ .GoName }} pkcs11Error = {{ .Value }}
{{ end }}
)
`))

type errorCode struct {
	SpecName string
	GoName   string
	Value    string
}

func toGoName(specName string) string {
	fields := strings.Split(specName, "_")
	s := "err"
	for i := 1; i < len(fields); i++ {
		word := fields[i]
		switch word {
		case "ID", "PIN", "RNG":
		default:
			if len(word) > 1 {
				word = word[:1] + strings.ToLower(word[1:])
			}
		}
		s = s + word
	}
	return s
}

func main() {
	var codes []errorCode
	for _, line := range strings.Split(ckrRaw, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		c := errorCode{}
		c.SpecName = fields[1]
		if c.SpecName == "CKR_OK" {
			continue
		}
		c.Value = strings.ToLower(strings.TrimSuffix(fields[2], "UL"))
		c.GoName = toGoName(c.SpecName)
		codes = append(codes, c)
	}

	b := &bytes.Buffer{}
	if err := tmpl.Execute(b, codes); err != nil {
		log.Fatalf("executing template: %v", err)
	}
	out, err := format.Source(b.Bytes())
	if err != nil {
		log.Fatalf("formatting source: %v", err)
	}
	if err := os.WriteFile("errors.go", out, 0644); err != nil {
		log.Fatalf("writing file: %v", err)
	}
}
