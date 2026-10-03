// main_test 覆盖 schema 标注(裁决 #3 三厂商同名异义)、raisedError 文案、
// isCleanShutdown 归类、jsonResult 的非 ASCII 嵌入。tools 名↔manifest 一致性
// 由 76-daedalus-plugin-gen.sh 在构建期交叉核对,本文件不重复。
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestNoArgsSchema_GateEmptyObject 检查 gpu_list 的输入模式必须是"空对象"
// (非 null、非缺省),防止编译器丢关键字导致工具名漂移。
func TestNoArgsSchema_GateEmptyObject(t *testing.T) {
	if noArgsSchema.Type != "object" {
		t.Errorf("noArgsSchema.Type = %q, want object", noArgsSchema.Type)
	}
	if len(noArgsSchema.Properties) != 0 {
		t.Errorf("noArgsSchema.Properties = %v, want 空", noArgsSchema.Properties)
	}
}

// TestGPUSchema_OptionalInt 覆盖 gpu? 可选 int + 描述含「GPU 全局序号」。
func TestGPUSchema_OptionalInt(t *testing.T) {
	gpu, ok := gpuSelectSchema.Properties["gpu"]
	if !ok {
		t.Fatal("gpuSelectSchema 缺 gpu 字段")
	}
	if gpu.Type != "integer" {
		t.Errorf("gpu.Type = %q, want integer", gpu.Type)
	}
	if !strings.Contains(gpu.Description, "GPU 全局序号") {
		t.Errorf("gpu.Description 缺GPU 全局序号标注: %q", gpu.Description)
	}
	if !strings.Contains(gpu.Description, "可选") {
		t.Errorf("gpu.Description 缺可选标注: %q", gpu.Description)
	}
}

// TestIsCleanShutdown 归类 context.Canceled / io.EOF / "server is closing"。
func TestIsCleanShutdown(t *testing.T) {
	for _, err := range []error{
		context.Canceled,
		io.EOF,
		fmt.Errorf("server is closing: %w", io.EOF),
		errors.New("server is closing"),
	} {
		if !isCleanShutdown(err) {
			t.Errorf("isCleanShutdown(%v) = false, want true", err)
		}
	}
	if isCleanShutdown(errors.New("some fatal")) {
		t.Error("非预期 shutdown 时应 false")
	}
}

// TestRaisedError_Format FastMCP 风格 "Error executing tool <name>: <消息>"。
func TestRaisedError_Format(t *testing.T) {
	r := raisedError("gpu_status", errors.New("gpu 索引不存在: 99(共 2 张 GPU)"))
	if !r.IsError {
		t.Error("IsError 应为 true")
	}
	if len(r.Content) != 1 {
		t.Fatalf("Content 长度 = %d, want 1", len(r.Content))
	}
	tc, ok := r.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("Content[0] 类型 = %T, want *mcp.TextContent", r.Content[0])
	}
	if !strings.HasPrefix(tc.Text, "Error executing tool gpu_status: ") {
		t.Errorf("文案 = %q", tc.Text)
	}
	if !strings.Contains(tc.Text, "gpu 索引不存在: 99") {
		t.Errorf("文案缺错误消息: %q", tc.Text)
	}
}

// TestJSONResult_NonASCII jsonResult 必须不转义中文/unicode(SetEscapeHTML(false))。
func TestJSONResult_NonASCII(t *testing.T) {
	r := jsonResult(GPUListResult{
		GPUs: []GPUInfo{{Index: 0, Vendor: vendorNVIDIA, Name: "NVIDIA GeForce RTX 4090 显卡"}},
		Note: "备注",
	})
	if len(r.Content) != 1 {
		t.Fatalf("Content = %d", len(r.Content))
	}
	tc, ok := r.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("Content[0] 类型 = %T", r.Content[0])
	}
	if strings.Contains(tc.Text, `\u`) {
		t.Errorf("jsonResult 转义了 unicode,应直接嵌入:\n%s", tc.Text)
	}
	if !strings.Contains(tc.Text, "显卡") {
		t.Errorf("jsonResult 中文丢失:\n%s", tc.Text)
	}
	if !strings.Contains(tc.Text, "  ") {
		t.Errorf("jsonResult 应带缩进美化:\n%s", tc.Text)
	}
	if !strings.HasSuffix(tc.Text, "}") {
		t.Errorf("jsonResult 应去掉 Encoder.Encode 的尾换行:\n%s", tc.Text)
	}
}

// TestTextResult_Shape 单文本块成功结果形态(家族约定)。
func TestTextResult_Shape(t *testing.T) {
	r := textResult("hello")
	if len(r.Content) != 1 {
		t.Fatalf("Content = %d, want 1", len(r.Content))
	}
	tc, ok := r.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("Content[0] 类型 = %T", r.Content[0])
	}
	if tc.Text != "hello" {
		t.Errorf("Text = %q", tc.Text)
	}
	if r.IsError {
		t.Error("成功结果 IsError 应为 false")
	}
}
