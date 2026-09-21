package main

// state.go —— daedalus-blueprint 的进程内状态:注册表与 plan store,以及
// 横跨 render/apply/status/remove 四个工具共用的纯函数助手。
//
// 本文件是"注册表作为包级状态传入各工具 handler"的承重实现:注册表在
// main 启动时从嵌入数据 MustLoad 编译(含 schema 预编译),plan store 记录
// render 阶段产生的 plan_id → {params, rendered, target_path, token} 映射,
// 供 apply/status/remove 按名取用。两处状态都由 app 持有并在 newServer
// 时注入 handler,绝不使用赤裸的全局变量(测试可构造独立 app)。

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

// compiledBlueprint 把一个 *blueprint.Blueprint 与其预编译产物(模板、
// schema 解析结果)绑定在一起。预编译发生在启动期,render 路径零编译开销
// (plan 框架验证第 2 条:JSON Schema compile-once + 失败 fail-closed)。
type compiledBlueprint struct {
	Blueprint *blueprint.Blueprint

	// schemaResolved 是 schema.json 经 Resolve 后的可校验对象(Pre-compiled);
	// 为 nil 表示该蓝图无 schema 或 schema 编译失败(编译失败在启动即 panic,
	// 此处 nil 仅对应"无 schema 文件"的合法态)。
	schemaResolved *jsonschema.Resolved
	// schemaRaw 是 schema.json 原文(inspect 工具回显用)。
	schemaRaw []byte
	// templateRaw 是 template.tmpl 原文(inspect 工具预览回显用)。
	templateRaw string
	// template 是 template.tmpl 解析后的模板(启动期 Parse,render 期 Execute)。
	template *template.Template
	// postCheckCmd 是 post_check.sh 的完整命令 argv 首项(来自策略白名单的
	// 脚本壳命令,见 manifest 层——v1 由服务器按 reload/common 命令直发,
	// 此处保留原文供 audit/inspect)。
	postCheckCmd string
	// readmeSummary 是 README.md 的内容(inspect 工具摘要回显)。
	readmeSummary string
}

// registry 是编译后的蓝图注册表(按 id 索引)。
type registry struct {
	byID map[string]*compiledBlueprint
	ids  []string // 按 id 字典序,保证 list 输出顺序稳定。
}

// newRegistry 从 []*blueprint.Blueprint 构建编译注册表。schema.json /
// template.tmpl 的加载与编译都在此一次性完成;任何蓝图内容缺陷(schema
// 非法 JSON、模板 Parse 失败)即返回 error(fail-closed),由调用方 panic
// 拒启——与 plan "初始化时 6 个蓝图齐全,缺一即 panic" 的语义一致。
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

// compileBlueprint 把单个蓝图绑定到其嵌入数据文件(schema.json /
// template.tmpl / post_check.sh / README.md)。文件缺失或解析失败即 error。
func compileBlueprint(b *blueprint.Blueprint) (*compiledBlueprint, error) {
	fsRoot := EmbeddedBlueprints()
	dir := b.ID

	cb := &compiledBlueprint{Blueprint: b}

	// schema.json:预编译(Unmarshal → Resolve),render 期直接 Validate。
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

	// post_check.sh 原文(inspect 回显;v1 由服务器 shellpolicy 白名单直发)。
	if raw, err := readFSFile(fsRoot, dir+"/post_check.sh"); err == nil {
		cb.postCheckCmd = strings.TrimSpace(string(raw))
	}
	// README.md 摘要(inspect 回显)。
	if raw, err := readFSFile(fsRoot, dir+"/README.md"); err == nil {
		cb.readmeSummary = string(raw)
	}

	return cb, nil
}

// get 按 id 取编译蓝图。
func (r *registry) get(id string) (*compiledBlueprint, bool) {
	cb, ok := r.byID[id]
	return cb, ok
}

// orderedIDs 返回按字典序排序的蓝图 id 列表(list 工具输出顺序稳定)。
func (r *registry) orderedIDs() []string {
	return r.ids
}

// renderedPlan 是 render 工具落进 plan store 的计划记录。
type renderedPlan struct {
	Name     string
	Params   map[string]any
	Rendered string
	Target   string
	Token    blueprint.ConfirmToken
	// RemoveToken 是 apply 成功后为该 plan 生成的 remove 确认令牌
	// (F1/F2 复审 2a 修复:remove 必须有真实的 token 生产路径,校验时
	// 比对 plan store 中存下的令牌而非任意非空串)。
	RemoveToken blueprint.ConfirmToken
	// Applied 标记该 plan 是否已成功 apply(F2 R1 修复:remove 用它判断"已应用",不再用会消费令牌的 VerifyConfirmToken 做只读探测)。
	Applied bool
}

// planStore 是 plan_id → renderedPlan 的进程内映射(并发安全)。
type planStore struct {
	mu sync.Mutex // 串行化读写(工具调用可并发命中各 plan)
	m  map[string]renderedPlan
}

// newPlanStore 构造空 plan store。
func newPlanStore() *planStore {
	return &planStore{m: make(map[string]renderedPlan)}
}

// put 存入(覆盖语义:同名 plan_id 后写覆盖先写)。
func (s *planStore) put(id string, p renderedPlan) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[id] = p
}

// get 取回。
func (s *planStore) get(id string) (renderedPlan, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.m[id]
	return p, ok
}

// countByName 统计给定蓝图名的活动计划数(status 工具用)。
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

// ──── 纯函数助手 ────

// readFSFile 从嵌入 FS 读文件原文;error 透传(调用方按需区分"可选文件缺失"
// 与"必需文件缺失")。
func readFSFile(fsys fs.FS, name string) ([]byte, error) {
	return fs.ReadFile(fsys, name)
}

// fillTemplateData 用 schema 的 default 补齐 params 中缺席的键。
//
// missingkey=error 会把模板对缺席字段的访问判为错误,而蓝图 schema 大量
// 字段带 default(如 ssl:false、listen_ports:[80,443])——模板依赖这些
// 默认值的访问如 `{{ if .ssl }}`。因此渲染前必须把 default 填补进数据,
// 使"未显式传参"与"显式传默认值"在模板视角等价。
//
// 实现按 schema 的 Properties 逐键检查:实例中缺席且 schema 有 default 的
// 键,以 default 原样填入(仅顶层对象,与蓝图 params 的扁平面一致)。
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

// zeroValueFor 按 schema 类型声明给出渲染数据的零值。
//
// 仅用于模板缺键防护:type=string→""、integer/number→int(0)、boolean→false、
// array→[]any{}、object→map[string]any{};类型未知(或组合类型)时保守取
// ""(字符串零值对 if 求值同样为假,不会误触发布尔分支)。
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

// normalizeJSONNumbers 递归把 JSON 解码产生的 float64 整数值转成 int。
//
// encoding/json 把一切数字解码为 float64,而蓝图模板里存在整数比较
// (如 nginx-vhost 的 `eq $p 443`):float64(443) 与 int 字面量 443 经
// eq 比较会报 "incompatible types"。整值 float64 归一为 int 后,模板
// 侧数值比较与 range 索引行为与直觉一致;非整值(如 443.5)保留 float64。
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

// validateOutputPath 校验渲染出的目标路径是否落在允许目录(outputDirs)内。
//
// 采用 pathguard 同款"段边界前缀"比较(防 /etc/nginx 匹配 /etc/nginx2),
// 逐目录比对规范化(clean)后的路径。任一允许目录命中即通过。
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

// lineDiff 做简单行级 diff(任务不引入新依赖,不用 go-difflib):
// 返回"从 old 派生到 new"的补丁视图。v1 语义:
//   - old 为空(目标文件不存在)→ 全部行以 '+' 前缀(新增文件);
//   - 其余输出逐行:相同行保序、被替换行以 '-old' / '+new' 成对展示。
//
// 这是一份低成本的人类可读 diff,仅用于 render 结果的 preview;
// 精确算法(最长公共子序列等)不做——任务明确"简单 LCS 或逐行对比"。
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

// unifiedDiff 基于逐行最长公共子序列输出极小替换视图。
//
// 算法:两序列的 LCS 一次性算好后,线性扫描输出:相同行原样;删行 '-x';
// 增行 '+x'。任务允许"简单 LCS",此处用经典二维 DP 的保守面积实现
// (蓝图配置片段通常 <200 行,复杂度可接受;超过视为合理边界不予优化)。
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

// lcsTable 返回两行序列的一条最长公共子序列(保序的匹配对)。
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

// newPlanID 生成 16 位小写十六进制 plan_id(crypto/rand 8 字节)。
// 与 tx-id 同形状(便于 plan_id 将来与 tx 关联);rand 失败即 panic(fail-closed)。
func newPlanID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("blueprint: crypto/rand 读取失败(fail-closed): " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
