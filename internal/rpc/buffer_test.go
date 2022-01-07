package rpc

import (
	"bytes"
	"reflect"
	"testing"
)

func TestBuffer(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		do   func(b *buffer) []interface{}
		want []interface{}
	}{
		{
			"uint32",
			[]byte{0x00, 0x00, 0x12, 0x34},
			func(b *buffer) []interface{} {
				var n uint32
				if b.uint32(&n) {
					return []interface{}{n}
				}
				return nil
			},
			[]interface{}{uint32(0x1234)},
		},
		{
			"uint32Twice",
			[]byte{0x00, 0x00, 0x12, 0x34, 0x00, 0x00, 0x56, 0x78},
			func(b *buffer) []interface{} {
				var n1, n2 uint32
				if b.uint32(&n1) && b.uint32(&n2) {
					return []interface{}{n1, n2}
				}
				return nil
			},
			[]interface{}{uint32(0x1234), uint32(0x5678)},
		},
		{
			"uint64",
			[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34},
			func(b *buffer) []interface{} {
				var n uint64
				if b.uint64(&n) {
					return []interface{}{n}
				}
				return nil
			},
			[]interface{}{uint64(0x1234)},
		},
		{
			"byteArray",
			[]byte{0x00, 0x00, 0x00, 0x02, 0x12, 0x34},
			func(b *buffer) []interface{} {
				var a []byte
				if b.byteArray(&a) {
					return []interface{}{a}
				}
				return nil
			},
			[]interface{}{[]byte{0x12, 0x34}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			b := newBuffer(test.in)
			got := test.do(b)
			if len(b.Bytes()) != 0 {
				t.Errorf("Bytes() after read got=%x, expected no bytes", b.Bytes())
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("Decoding got=%#v, want=%#v", got, test.want)
			}
		})
	}
}

func TestBufferAdd(t *testing.T) {
	tests := []struct {
		name string
		do   func(b *buffer)
		want []byte
	}{
		{
			"addUint32",
			func(b *buffer) {
				b.addUint32(0x1234)
			},
			[]byte{0x00, 0x00, 0x12, 0x34},
		},
		{
			"addUint32Twice",
			func(b *buffer) {
				b.addUint32(0x1234)
				b.addUint32(0x5678)
			},
			[]byte{0x00, 0x00, 0x12, 0x34, 0x00, 0x00, 0x56, 0x78},
		},
		{
			"addUint64",
			func(b *buffer) {
				b.addUint64(0x1234)
			},
			[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34},
		},
		{
			"addByteArray",
			func(b *buffer) {
				b.addByteArray([]byte{0x12, 0x34})
			},
			[]byte{0x00, 0x00, 0x00, 0x02, 0x12, 0x34},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			b := &buffer{}
			test.do(b)
			got := b.Bytes()
			if !bytes.Equal(got, test.want) {
				t.Errorf("Bytes() got=%x, want=%x", got, test.want)
			}
		})
	}
}
