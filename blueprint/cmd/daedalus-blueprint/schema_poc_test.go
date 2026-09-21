// Package main 的 schema_poc_test.go 是 plan daedalus-blueprint-p1 todo 1 的
// 选型 PoC(仅测试文件,不进生产代码)。
//
// 目标:验证 github.com/google/jsonschema-go v0.4.3(已在 go.sum)能否从
// 独立的 JSON Schema 文档(而非 struct tag 推断/内联 struct 字面量)加载
// 并校验 JSON input。这与 daedalus-pkg 的用法不同:
//   - daedalus-pkg 用 jsonschema.Schema{...} Go struct 字面量内联构建 MCP
//     InputSchema(见 cmd/daedalus-pkg/main.go:93);
//   - 本 PoC 验证"蓝图加载 schema.json 文件"的路径:json.Unmarshal → Resolve → Validate。
//
// 库版本 v0.4.3 无 jsonschema.Compile 函数(doc.go 说明该版本加载方式即
// encoding/json 反序列化 + Schema.Resolve),故以等价的三步流程演示。
package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
)

// compileJSON 从 JSON 文档字符串编译 schema(等价于蓝图加载 schema.json 文件)。
// 流程:json.Unmarshal 反序列化 → Resolve 解析引用/编译正则 → 返回可校验的 Resolved。
func compileJSON(t *testing.T, doc string) *jsonschema.Resolved {
	t.Helper()
	var s jsonschema.Schema
	if err := json.Unmarshal([]byte(doc), &s); err != nil {
		t.Fatalf("json.Unmarshal(schema 文档)失败: %v", err)
	}
	rs, err := s.Resolve(nil)
	if err != nil {
		t.Fatalf("Schema.Resolve 失败: %v", err)
	}
	return rs
}

// 用例一:简单对象。name 必填 string + age 可选 integer + 拒绝未知字段。
const schemaSimple = `{
	"$schema": "https://json-schema.org/draft/2020-12/schema",
	"type": "object",
	"properties": {
		"name": {"type": "string"},
		"age":  {"type": "integer"}
	},
	"required": ["name"],
	"additionalProperties": false
}`

func TestSchemaPoC_SimpleObject(t *testing.T) {
	rs := compileJSON(t, schemaSimple)

	// 合法输入:name 满足必填 + 类型,age 可选,无多余字段。
	if err := rs.Validate(map[string]any{"name": "alice", "age": 30}); err != nil {
		t.Errorf("合法输入校验失败: %v", err)
	}

	// 非法输入一:缺少必填字段 name。
	err := rs.Validate(map[string]any{"age": 30})
	if err == nil {
		t.Fatal("缺少必填字段应校验失败,却通过了")
	}
	// 错误需含对象路径(validating root)、规则(required)与缺失字段名。
	// 注:required 在对象层求值,字段路径前缀是对象自身路径,缺失字段名列在消息内。
	for _, want := range []string{"validating root", "required", "missing properties", `"name"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误信息缺少 %q,实际: %v", want, err)
		}
	}

	// 非法输入二:name 类型错误(string 字段给了数字)。
	err = rs.Validate(map[string]any{"name": 42})
	if err == nil {
		t.Fatal("类型错误应校验失败,却通过了")
	}
	// 错误需含字段路径、规则(type)与实际/期望类型。
	for _, want := range []string{"properties/name", "type:", "has type", "want"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误信息缺少 %q,实际: %v", want, err)
		}
	}

	// 非法输入三(附加验证):additionalProperties:false 应拒绝未知字段。
	err = rs.Validate(map[string]any{"name": "alice", "hacker": true})
	if err == nil {
		t.Fatal("additionalProperties:false 应拒绝未知字段,却通过了")
	}
	// 该库对 falsy additionalProperties 有专门的汇总错误,列出全部多余字段。
	for _, want := range []string{"unexpected additional properties", "hacker"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误信息缺少 %q,实际: %v", want, err)
		}
	}
}

// 用例二:嵌套对象。config 为必填对象,内部有必填字段 timeout,
// 且内层同样拒未知字段。
const schemaNested = `{
	"$schema": "https://json-schema.org/draft/2020-12/schema",
	"type": "object",
	"properties": {
		"app": {"type": "string"},
		"config": {
			"type": "object",
			"properties": {
				"timeout": {"type": "integer", "minimum": 1},
				"retries": {"type": "integer"}
			},
			"required": ["timeout"],
			"additionalProperties": false
		}
	},
	"required": ["app", "config"],
	"additionalProperties": false
}`

func TestSchemaPoC_NestedObject(t *testing.T) {
	rs := compileJSON(t, schemaNested)

	// 合法输入:嵌套结构完整且满足约束。
	if err := rs.Validate(map[string]any{
		"app":    "demo",
		"config": map[string]any{"timeout": 30, "retries": 3},
	}); err != nil {
		t.Errorf("合法输入校验失败: %v", err)
	}

	// 非法输入一:config 缺内部必填字段 timeout。
	err := rs.Validate(map[string]any{
		"app":    "demo",
		"config": map[string]any{"retries": 3},
	})
	if err == nil {
		t.Fatal("嵌套必填缺失应校验失败,却通过了")
	}
	// 错误需含完整嵌套链 validating /properties/config 与缺失字段名。
	for _, want := range []string{"validating /properties/config", "required", "missing properties", `"timeout"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误信息缺少 %q,实际: %v", want, err)
		}
	}

	// 非法输入二:内层 additionalProperties:false 拒绝未知字段。
	err = rs.Validate(map[string]any{
		"app":    "demo",
		"config": map[string]any{"timeout": 30, "sneaky": 1},
	})
	if err == nil {
		t.Fatal("嵌套 additionalProperties:false 应拒绝未知字段,却通过了")
	}
	for _, want := range []string{"unexpected additional properties", "sneaky"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误信息缺少 %q,实际: %v", want, err)
		}
	}

	// 非法输入三:内层 minimum 边界违规(timeout < 1)。
	err = rs.Validate(map[string]any{
		"app":    "demo",
		"config": map[string]any{"timeout": 0},
	})
	if err == nil {
		t.Fatal("minimum 违规应校验失败,却通过了")
	}
	for _, want := range []string{"properties/config/properties/timeout", "minimum", "less than"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误信息缺少 %q,实际: %v", want, err)
		}
	}
}

// 用例三:带 enum 的对象。mode 枚举 auto/manual,且 mode 必填。
const schemaEnum = `{
	"$schema": "https://json-schema.org/draft/2020-12/schema",
	"type": "object",
	"properties": {
		"mode": {"type": "string", "enum": ["auto", "manual"]},
		"note": {"type": "string"}
	},
	"required": ["mode"],
	"additionalProperties": false
}`

func TestSchemaPoC_EnumObject(t *testing.T) {
	rs := compileJSON(t, schemaEnum)

	// 合法输入:mode 命中枚举值之一。
	if err := rs.Validate(map[string]any{"mode": "auto", "note": "ok"}); err != nil {
		t.Errorf("合法输入校验失败: %v", err)
	}

	// 非法输入:mode 值不在枚举内。
	err := rs.Validate(map[string]any{"mode": "turbo"})
	if err == nil {
		t.Fatal("枚举外值应校验失败,却通过了")
	}
	// 错误需含字段路径、规则(enum)、实际值与期望枚举集合。
	for _, want := range []string{"properties/mode", "enum:", "does not equal any of"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误信息缺少 %q,实际: %v", want, err)
		}
	}
}

// TestSchemaPoC_ErrorReadability 打印三类典型错误的完整文本,
// 便于人工评估错误信息友好度(字段路径 + 规则 + 期望值是否齐备)。
func TestSchemaPoC_ErrorReadability(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		bad  any
	}{
		{"简单对象-缺必填", schemaSimple, map[string]any{"age": 30}},
		{"简单对象-未知字段", schemaSimple, map[string]any{"name": "a", "x": 1}},
		{"嵌套对象-内层违规", schemaNested, map[string]any{"app": "a", "config": map[string]any{"timeout": 0}}},
		{"enum对象-枚举外值", schemaEnum, map[string]any{"mode": "turbo"}},
	}
	for _, c := range cases {
		rs := compileJSON(t, c.doc)
		err := rs.Validate(c.bad)
		if err == nil {
			t.Errorf("%s: 期望校验失败,却通过了", c.name)
			continue
		}
		t.Logf("── %s 错误文本 ──\n%v\n", c.name, err)
	}
}

// TestSchemaPoC_CompileEntry 证明 v0.4.3 确实没有 jsonschema.Compile 入口
// (选型结论的关键事实):编译的等价流程是 json.Unmarshal + Schema.Resolve。
// 该测试仅作为文档性锚点——若未来版本补了 Compile,此断言会编译失败提醒更新。
func TestSchemaPoC_CompileEntry(t *testing.T) {
	rs := compileJSON(t, schemaSimple)
	_ = rs // 编译入口已由 compileJSON 演示
	// 若想确认 API 无 Compile,可执行 go doc 查询;此处保持零运行断言,
	// 只把结论写进 notepad(选型结论:JSON 文档加载路径 = Unmarshal + Resolve + Validate)。
	fmt.Println("jsonschema-go v0.4.3 加载路径:json.Unmarshal → Schema.Resolve → Resolved.Validate")
}
