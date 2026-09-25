package main

// state.go —— daedalus-blueprint 的进程内状态:注册表与 plan store,以及
// 横跨 render/apply/status/remove 四个工具共用的纯函数助手。
//
// 注册表在 main 启动时从嵌入数据 MustLoad 编译(含 schema 预编译);两处状态都
// 由 app 持有并在 newServer 时注入 handler,绝不使用赤裸的全局变量。

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"
	"sync"
	"text/template"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/Daedalusys/daedalus-sdk/blueprint"
)

// compiledBlueprint 把一个 *blueprint.Blueprint 与其预编译产物绑定在一起;
// 预编译发生在启动期,render 路径零编译开销。
type compiledBlueprint struct {
	Blueprint *blueprint.Blueprint

	// schemaResolved 为 nil 仅对应"无 schema 文件"的合法态(编译失败在启动即
	// panic,不会走到这里)。
	schemaResolved *jsonschema.Resolved
	schemaRaw      []byte
	templateRaw    string
	template       *template.Template
	// postCheckCmd 是 post_check.sh 原文;v1 由服务器按 shellpolicy 白名单逐行
	// argv 直发,此处保留原文供 audit/inspect 回显。
	postCheckCmd  string
	readmeSummary string
}

type registry struct {
	byID map[string]*compiledBlueprint
	ids  []string // 按 id 字典序,保证 list 输出顺序稳定。
}

// newRegistry 构建编译注册表:schema.json / template.tmpl 的加载与编译都在此
// 一次性完成;任何蓝图内容缺陷即返回 error(fail-closed),由调用方 panic 拒启。
func newRegistry(bs []*blueprint.Blueprint) (*registry, error) {
	r := &registry{byID: make(map[string]*compiledBlueprint, len(bs))}
	for _, b := range bs {
		cb, err := compileBlueprint(b)
		if err != nil {
			return nil, fmt.Errorf("blueprint: 编译 %s 失败: %w", b.ID, err)
		}
		r.byID[b.ID] = cb
		r.ids = append(r.ids, b.ID)
	}
	return r, nil
}

// compileBlueprint 把单个蓝图绑定到其嵌入数据文件;文件缺失或解析失败即 error。
func compileBlueprint(b *blueprint.Blueprint) (*compiledBlueprint, error) {
	fsRoot := EmbeddedBlueprints()
	dir := b.ID

	cb := &compiledBlueprint{Blueprint: b}

	if raw, err := readFSFile(fsRoot, dir+"/schema.json"); err == nil {
		cb.schemaRaw = raw
		var s jsonschema.Schema
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, fmt.Errorf("schema.json 解析失败: %w", err)
		}
		resolved, err := s.Resolve(nil)
		if err != nil {
			return nil, fmt.Errorf("schema.json 编译失败: %w", err)
		}
		cb.schemaResolved = resolved
	}

	// template.tmpl:启动期 Parse;用 missingkey=error 严格处理缺失键
	// (防模板引用未定义字段时静默输出空串)。
	tmplRaw, err := readFSFile(fsRoot, dir+"/template.tmpl")
	if err != nil {
		return nil, fmt.Errorf("读取 template.tmpl 失败: %w", err)
	}
	tmpl, err := template.New(b.ID).Option("missingkey=error").Parse(string(tmplRaw))
	if err != nil {
		return nil, fmt.Errorf("template.tmpl 解析失败: %w", err)
	}
	cb.template = tmpl
	cb.templateRaw = string(tmplRaw)

	if raw, err := readFSFile(fsRoot, dir+"/post_check.sh"); err == nil {
		cb.postCheckCmd = strings.TrimSpace(string(raw))
	}
	if raw, err := readFSFile(fsRoot, dir+"/README.md"); err == nil {
		cb.readmeSummary = string(raw)
	}

	return cb, nil
}

func (r *registry) get(id string) (*compiledBlueprint, bool) {
	cb, ok := r.byID[id]
	return cb, ok
}

// orderedIDs 返回按字典序排序的蓝图 id 列表(保证 list 输出顺序稳定)。
func (r *registry) orderedIDs() []string {
	return r.ids
}

type renderedPlan struct {
	Name     string
	Params   map[string]any
	Rendered string
	Target   string
	Token    blueprint.ConfirmToken
	// RemoveToken 是 apply 成功后为该 plan 生成的 remove 确认令牌;校验时比对
	// plan store 中存下的令牌而非任意非空串。
	RemoveToken blueprint.ConfirmToken
	// Applied 标记该 plan 是否已成功 apply;remove 用它判断"已应用",不用
	// 会消费令牌的 VerifyConfirmToken 做只读探测。
	Applied bool
}

type planStore struct {
	mu sync.Mutex // 串行化读写(工具调用可并发命中各 plan)
	m  map[string]renderedPlan
}

func newPlanStore() *planStore {
	return &planStore{m: make(map[string]renderedPlan)}
}

// 同名 plan_id 后写覆盖先写。
func (s *planStore) put(id string, p renderedPlan) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[id] = p
}

func (s *planStore) get(id string) (renderedPlan, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.m[id]
	return p, ok
}

func (s *planStore) countByName(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, p := range s.m {
		if p.Name == name {
			n++
		}
	}
	return n
}

// readFSFile 从嵌入 FS 读文件原文;error 透传(调用方按需区分"可选文件缺失"
// 与"必需文件缺失")。
func readFSFile(fsys fs.FS, name string) ([]byte, error) {
	return fs.ReadFile(fsys, name)
}

// fillTemplateData 用 schema 的 default 补齐 params 中缺席的键:missingkey=error
// 会把模板对缺席字段的访问判为错误,而蓝图 schema 大量字段带 default(如
// ssl:false)且模板依赖这些默认值,故渲染前必须填补,使"未显式传参"与"显式传
// 默认值"在模板视角等价。仅按顶层 Properties 逐键检查。
func fillTemplateData(resolved *jsonschema.Resolved, params map[string]any) map[string]any {
	if resolved == nil {
		return params
	}
	schema := resolved.Schema()
	if schema == nil || len(schema.Properties) == 0 {
		return params
	}
	out := make(map[string]any, len(params)+len(schema.Properties))
	for k, v := range params {
		out[k] = normalizeJSONNumbers(v)
	}
	for k, ps := range schema.Properties {
		if _, exists := out[k]; exists {
			continue
		}
		if ps != nil && ps.Default != nil {
			var dv any
			if err := json.Unmarshal(ps.Default, &dv); err == nil {
				out[k] = normalizeJSONNumbers(dv)
				continue
			}
		}
		// optional 无 default 的字段:填类型零值,保证 missingkey=error 下
		// 模板的 `{{ if .field }}` 求值不会因缺键报错(optional 语义 =
		// "缺席视为假/空",与模板 if/else 分支的直觉一致)。
		out[k] = zeroValueFor(ps)
	}
	return out
}

// zeroValueFor 按 schema 类型声明给出渲染数据的零值(仅用于模板缺键防护)。
// 类型未知或组合类型时保守取 ""——字符串零值对 if 求值同样为假。
func zeroValueFor(ps *jsonschema.Schema) any {
	if ps == nil {
		return ""
	}
	switch ps.Type {
	case "integer", "number":
		return 0
	case "boolean":
		return false
	case "array":
		return []any{}
	case "object":
		return map[string]any{}
	default:
		return ""
	}
}

// normalizeJSONNumbers 递归把 JSON 解码产生的整值 float64 转成 int:模板里存在
// 整数比较(如 `eq $p 443`),float64 与 int 字面量经 eq 比较会报 "incompatible
// types";非整值(如 443.5)保留 float64。
func normalizeJSONNumbers(v any) any {
	switch t := v.(type) {
	case float64:
		if t == float64(int64(t)) {
			return int(t)
		}
		return t
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = normalizeJSONNumbers(e)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[k] = normalizeJSONNumbers(e)
		}
		return out
	default:
		return v
	}
}

// validateOutputPath 校验目标路径是否落在允许目录内;采用 pathguard 同款"段
// 边界前缀"比较(防 /etc/nginx 匹配 /etc/nginx2),逐目录比对 clean 后的路径。
func validateOutputPath(outputDirs []string, target string) bool {
	t := cleanPath(target)
	for _, dir := range outputDirs {
		d := cleanPath(dir)
		if t == d || strings.HasPrefix(t, d+"/") {
			return true
		}
	}
	return false
}

// cleanPath 做词法规范化(去冗余 '/' 与尾部 '/'),不解析符号链接——
// 输出目录边界校验只关心词法前缀;落盘前的符号链接逃逸由
// validateOutputPathResolved(apply_tool.go)的 realpath 包含性门另行把关。
func cleanPath(p string) string {
	s := strings.ReplaceAll(p, "//", "/")
	for strings.Contains(s, "//") {
		s = strings.ReplaceAll(s, "//", "/")
	}
	return strings.TrimRight(s, "/")
}

// lineDiff 做简单行级 diff(不引入新依赖,不用 go-difflib):返回"从 old
// 派生到 new"的补丁视图。old 为空(目标文件不存在)→ 全部行以 '+' 前缀;
// 其余逐行:相同行保序、被替换行以 '-old' / '+new' 成对展示。
// 这是低成本的人类可读 diff,仅用于 render 结果的 preview。
func lineDiff(old, new string) string {
	if old == "" {
		var b strings.Builder
		for _, l := range strings.Split(new, "\n") {
			b.WriteString("+ " + l + "\n")
		}
		return strings.TrimRight(b.String(), "\n")
	}
	return unifiedDiff(old, new)
}

// unifiedDiff 基于逐行最长公共子序列输出极小替换视图:相同行原样;删行 '-x';
// 增行 '+x'。经典二维 DP(蓝图配置片段通常 <200 行,复杂度可接受)。
func unifiedDiff(old, new string) string {
	oldLines := strings.Split(old, "\n")
	newLines := strings.Split(new, "\n")
	lcs := lcsTable(oldLines, newLines)

	var b strings.Builder
	i, j := 0, 0
	for _, ln := range lcs {
		for i < ln.old {
			b.WriteString("- " + oldLines[i] + "\n")
			i++
		}
		for j < ln.new {
			b.WriteString("+ " + newLines[j] + "\n")
			j++
		}
		b.WriteString("  " + oldLines[i] + "\n")
		i++
		j++
	}
	for i < len(oldLines) {
		b.WriteString("- " + oldLines[i] + "\n")
		i++
	}
	for j < len(newLines) {
		b.WriteString("+ " + newLines[j] + "\n")
		j++
	}
	return strings.TrimRight(b.String(), "\n")
}

type lcsCell struct{ old, new int }

func lcsTable(a, b []string) []lcsCell {
	n, m := len(a), len(b)
	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else if dp[i+1][j] >= dp[i][j+1] {
				dp[i][j] = dp[i+1][j]
			} else {
				dp[i][j] = dp[i][j+1]
			}
		}
	}
	var cells []lcsCell
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			cells = append(cells, lcsCell{i, j})
			i++
			j++
		case dp[i+1][j] >= dp[i][j+1]:
			i++
		default:
			j++
		}
	}
	return cells
}

// newPlanID 生成 plan_id(crypto/rand 8 字节,与 tx-id 同形状);rand 失败即
// panic(fail-closed)。
func newPlanID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("blueprint: crypto/rand 读取失败(fail-closed): " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
