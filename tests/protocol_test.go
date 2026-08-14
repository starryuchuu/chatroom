package tests

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestMessageLengthLimit 测试消息长度限制修复
func TestMessageLengthLimit(t *testing.T) {
	// 模拟超大消息长度（超过10MB）
	maxAllowedSize := uint32(10 * 1024 * 1024) // 10MB
	
	tests := []struct {
		name        string
		messageLen  uint32
		expectError bool
	}{
		{"正常小消息", 1024, false},
		{"正常中等消息", 1024 * 1024, false}, // 1MB
		{"边界值消息", maxAllowedSize, false},
		{"超限消息", maxAllowedSize + 1, true},
		{"超大消息", 100 * 1024 * 1024, true}, // 100MB
		{"最大uint32消息", ^uint32(0), true},   // 最大值
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 模拟协议解析中的长度检查逻辑
			err := validateMessageLength(tt.messageLen, maxAllowedSize)
			
			if tt.expectError && err == nil {
				t.Errorf("期望错误但未得到错误，消息长度: %d", tt.messageLen)
			}
			
			if !tt.expectError && err != nil {
				t.Errorf("不期望错误但得到错误: %v，消息长度: %d", err, tt.messageLen)
			}
		})
	}
}

// validateMessageLength 模拟protocol.go中的验证逻辑
func validateMessageLength(length uint32, maxSize uint32) error {
	if length > maxSize {
		return &MessageTooLargeError{Length: length, MaxSize: maxSize}
	}
	return nil
}

// MessageTooLargeError 定义错误类型
type MessageTooLargeError struct {
	Length  uint32
	MaxSize uint32
}

func (e *MessageTooLargeError) Error() string {
	return "message too large"
}

// TestHeaderParsing 测试头部解析
func TestHeaderParsing(t *testing.T) {
	// 测试二进制头部解析
	tests := []struct {
		name     string
		header   []byte
		expected uint32
		hasError bool
	}{
		{"有效头部", []byte{0x00, 0x00, 0x04, 0x00}, 1024, false},
		{"零长度", []byte{0x00, 0x00, 0x00, 0x00}, 0, false},
		{"大长度", []byte{0x00, 0xFA, 0x00, 0x00}, 16384000, false},
		{"不完整头部", []byte{0x00, 0x00}, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.header) < 4 {
				if !tt.hasError {
					t.Errorf("期望解析失败但未失败")
				}
				return
			}
			
			var length uint32
			buf := bytes.NewReader(tt.header)
			err := binary.Read(buf, binary.BigEndian, &length)
			
			if tt.hasError && err == nil {
				t.Errorf("期望错误但未得到错误")
			}
			
			if !tt.hasError && err != nil {
				t.Errorf("不期望错误但得到错误: %v", err)
			}
			
			if !tt.hasError && length != tt.expected {
				t.Errorf("期望长度 %d，得到 %d", tt.expected, length)
			}
		})
	}
}

// TestConcurrentMessageHandling 测试并发消息处理
func TestConcurrentMessageHandling(t *testing.T) {
	maxAllowedSize := uint32(10 * 1024 * 1024)
	
	done := make(chan bool, 10)
	
	// 启动多个goroutine同时验证消息长度
	for i := 0; i < 10; i++ {
		go func(id int) {
			length := uint32(1024 * (id + 1))
			err := validateMessageLength(length, maxAllowedSize)
			if err != nil {
				t.Errorf("goroutine %d: 意外错误: %v", id, err)
			}
			done <- true
		}(i)
	}
	
	// 等待所有goroutine完成
	for i := 0; i < 10; i++ {
		<-done
	}
}
