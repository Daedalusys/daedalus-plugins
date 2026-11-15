package main

// ui.go —— `ui` 子命令:只监听 127.0.0.1 的本地蓝图管理界面。
//
// 为什么必须是独立常驻子命令:MCP 模式(`daedalus-host run-plugin` + wrapper
// exec)每次工具调用起一个进程、stdio 用完即退,无法承载 HTTP 服务。故同一个
// `daedalus-blueprint` 二进制新增 `ui` 子命令,进程内直接调 render/apply 的
// 业务函数(renderOnce / applyOnce),不走 MCP、不写第二套业务逻辑。
//
// 四道防护缺一不可(逐一见 guard 注释):
//  1. Host 白名单         —— 防 DNS rebinding;
//  2. X-Daedalus-Ui: 1    —— 跨站表单设不了自定义头,硬闸;
//  3. Origin 同源         —— 带 Origin 时必须与 Host 一致;
//  4. RemoteAddr loopback —— 非本机来源一律拒绝。
//
// 令牌纪律:confirm_token 只出现在应用表单的 <input type="hidden"> 里,不进
// data-* 属性、不进内联 JS、不进 localStorage、不写日志。过期时刻由服务端按
// confirmation.ConfirmTokenTTL 计算(render 时 now+15m),apply 前再核一次。

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/Daedalusys/daedalus-sdk/confirmation"
)

// uiDefaultListen 是 UI 的默认监听地址(只 loopback)。
const uiDefaultListen = "127.0.0.1:8787"

// uiHeader 是 POST /api/* 必须携带的自定义头名(跨站表单无法设置)。
const uiHeader = "X-Daedalus-Ui"

// uiTemplatesFS 内嵌四份模板(layout/list/render/apply)。无构建步骤、无外部资源。
//
//go:embed templates/*.html
var uiTemplatesFS embed.FS

// pageData 是一次页面渲染的全部数据。
type pageData struct {
	Bind       string // 监听地址(顶栏显示)
	Active     string // list | render | apply
	Blueprints []uiRow
	Render     renderView
	Apply      applyView
}

// uiRow 是列表页的一行:摘要字段来自 blueprint_list 投影,资源列来自
// blueprint_inspect 的 output_path_template / reload_service。
type uiRow struct {
	ID          string
	DisplayName string
	Category    string
	Description string
	OutputPath  string // 取不到时为空,模板显示 "—"
	Reload      string
}

// uiField 是一个按 schema 生成的表单字段。
type uiField struct {
	Name        string // schema 属性名,同时是表单 name
	Label       string // schema title,缺省用属性名
	Type        string // string/integer/number/boolean/array
	IsBool      bool
	Required    bool
	Value       string // 文本回填值(数组按 ", " 连接)
	Checked     bool   // boolean 字段的回填态
	Description string
}

// renderView 是渲染预览视图。
type renderView struct {
	Blueprint string
	Display   string
	Reload    string
	Fields    []uiField
	NeedPick  bool // 尚未选择蓝图
	ErrorMsg  string
	Preview   *renderPreview
}

// renderPreview 是 blueprint_render 成功结果的人类可读投影。
type renderPreview struct {
	PlanID          string
	TargetPath      string
	RenderedContent string
	Diff            []diffLine
	Added           int
	Removed         int
	NewFile         bool // 目标文件不存在(render 返回空 diff)
	Warnings        []string
	ConfirmToken    string // 只进 hidden 字段
	ExpiresAt       string // RFC 3339,服务端算
}

// applyView 是应用视图。
type applyView struct {
	Blueprint  string
	Display    string
	TargetPath string
	Reload     string
	PostCheck  string
	Empty      bool // 尚未渲染过计划
	PlanID     string
	// ConfirmToken 只渲染进 <form> 的 hidden 输入;模板里不显示、不进 data-*。
	ConfirmToken string
	ExpiresAt    string
	Expired      bool
	CanApply     bool
	ErrorMsg     string
	RolledBack   bool
	Result       *applyResultView
}

// applyResultView 是 blueprint_apply 成功结果。
type applyResultView struct {
	TxID        string
	AppliedAt   string
	ConfigPath  string
	PostCheckOK bool
	ReloadOK    bool
	HasRemove   bool
}

// diffLine 是一行差异的渲染形态。旧/新行号按 unified diff 惯例:
// `+` 行没有旧行号,`-` 行没有新行号。
type diffLine struct {
	OldNo string
	NewNo string
	Sign  string // "+" / "-" / " " / "@@" / "\"
	Text  string
	Class string // add / del / ctx / hunk
}

// uiServer 持有 UI 的全部运行期状态。handler() 可直接交给 httptest,
// 不需要真监听端口。
type uiServer struct {
	app   *app
	addr  string
	hosts map[string]bool // Host 白名单(127.0.0.1:<port> / localhost:<port>)
	tmpl  *template.Template
	// detailOf 是列表页取 output_path_template/reload_service 的注入缝;
	// 默认 blueprintDetailOf,测试可覆写以模拟"某条 inspect 失败"。
	detailOf func(*app, string) (blueprintDetail, bool)
}

// newUIServer 解析模板并算出 Host 白名单。addr 必须是 host:port。
func newUIServer(a *app, addr string) (*uiServer, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("监听地址 %q 无法解析: %w", addr, err)
	}
	tmpl, err := template.New("ui").ParseFS(uiTemplatesFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("解析 UI 模板失败: %w", err)
	}
	return &uiServer{
		app:  a,
		addr: addr,
		hosts: map[string]bool{
			net.JoinHostPort("127.0.0.1", port): true,
			net.JoinHostPort("localhost", port): true,
			net.JoinHostPort(host, port):        true,
		},
		tmpl:     tmpl,
		detailOf: blueprintDetailOf,
	}, nil
}

// handler 组装路由与四道防护。
func (s *uiServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.guard(s.handleIndex))
	mux.HandleFunc("POST /api/render", s.guard(s.handleRender))
	mux.HandleFunc("POST /api/apply", s.guard(s.handleApply))
	return mux
}

// guard 是四道防护的唯一实现点(所有路由共用,不给出可绕过的旁路)。
func (s *uiServer) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Host 白名单:只认本机监听地址的两种写法。DNS rebinding 会把
		//    恶意域名解析到 127.0.0.1,但浏览器仍发送该域名为 Host。
		if !s.hosts[r.Host] {
			forbid(w, fmt.Sprintf("Host %q 不在白名单(只允许 127.0.0.1 / localhost 的本机监听端口)", r.Host))
			return
		}
		// 4. RemoteAddr 必须 loopback:SSH 端口转发等场景下本可绕过 Host 检查。
		if !isLoopbackAddr(r.RemoteAddr) {
			forbid(w, fmt.Sprintf("RemoteAddr %q 不是 loopback", r.RemoteAddr))
			return
		}
		if strings.EqualFold(r.Method, http.MethodPost) && strings.HasPrefix(r.URL.Path, "/api/") {
			// 2. 自定义头:跨站 <form> 无法设置自定义请求头,强制 preflight,
			//    而本服务不返回任何 CORS 许可 —— 最高性价比的一道硬闸。
			if r.Header.Get(uiHeader) != "1" {
				forbid(w, "POST /api 请求缺少 "+uiHeader+": 1 自定义头")
				return
			}
			// 3. Origin 若存在必须同源(与现代浏览器一样,不带 Origin 的同源
			//    fetch 放行;带了就必须对得上)。
			if origin := r.Header.Get("Origin"); origin != "" && !sameOrigin(origin, r.Host) {
				forbid(w, fmt.Sprintf("Origin %q 与 Host %q 不同源", origin, r.Host))
				return
			}
		}
		setSecurityHeaders(w)
		next(w, r)
	}
}

// setSecurityHeaders 收紧浏览器行为:无外部资源、禁止内联之外的注入面。
// (内联 style/script 是本页的唯一形态,故保留 unsafe-inline。)
func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'")
}

// forbid 是四道防护统一的拒绝应答(403 + 可读原因,便于自查为什么被拒)。
func forbid(w http.ResponseWriter, reason string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, "403 forbidden: %s\n", reason)
}

// isLoopbackAddr 判定 "host:port" 形式地址的主机部分是回环地址。
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// sameOrigin 判定 Origin 是否与当前请求同源(只服务 http)。
func sameOrigin(origin, host string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return u.Scheme == "http" && u.Host == host
}

// handleIndex 渲染整页。?view=render&name=<id> 直接进预览表单(列表按钮走
// 这个地址,服务端生成 schema 表单,无需前端再拉一次 schema)。
func (s *uiServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	data := s.baseData()
	switch r.URL.Query().Get("view") {
	case "render":
		data.Active = "render"
		if name := r.URL.Query().Get("name"); name != "" {
			s.fillRenderForm(&data, name, nil)
		}
	case "apply":
		data.Active = "apply"
	default:
		data.Active = "list"
	}
	s.renderFull(w, data)
}

// baseData 组装列表页数据。
//
// "管理的资源"列的数据来源(一次性决定):blueprint_list 不返回资源路径,故
// 逐条调用 blueprint_inspect 的等价纯函数 blueprintDetailOf 取
// output_path_template + reload_service。6 条的成本可忽略;单条取不到只让该行
// 显示 "—",绝不让整页 500。
func (s *uiServer) baseData() pageData {
	data := pageData{Bind: s.addr, Render: renderView{NeedPick: true}, Apply: applyView{Empty: true}}
	for _, sum := range blueprintSummaries(s.app) {
		row := uiRow{
			ID:          sum.ID,
			DisplayName: sum.DisplayName,
			Category:    sum.Category,
			Description: sum.Description,
		}
		if detail, ok := s.detailOf(s.app, sum.ID); ok {
			row.OutputPath = detail.OutputPathTemplate
			row.Reload = detail.ReloadService
		}
		data.Blueprints = append(data.Blueprints, row)
	}
	return data
}

// fillRenderForm 按蓝图 schema 生成表单(可带已填值回填)。ok=false 表示
// 蓝图不存在,视图退化为提示。
func (s *uiServer) fillRenderForm(data *pageData, name string, values map[string]string) bool {
	cb, ok := s.app.reg.get(name)
	if !ok {
		data.Render = renderView{NeedPick: true, ErrorMsg: fmt.Sprintf("蓝图 %q 不存在", name)}
		return false
	}
	data.Render = renderView{
		Blueprint: name,
		Display:   cb.Blueprint.DisplayName,
		Reload:    cb.Blueprint.ReloadService,
		Fields:    buildFields(cb, values),
	}
	return true
}

// buildFields 从 schema 的 Properties 生成表单字段。顺序按属性名排序,保证
// 同一份 schema 每次渲染顺序一致(Go map 迭代无序)。
func buildFields(cb *compiledBlueprint, values map[string]string) []uiField {
	if cb.schemaResolved == nil {
		return nil
	}
	schema := cb.schemaResolved.Schema()
	if schema == nil || len(schema.Properties) == 0 {
		return nil
	}
	required := make(map[string]bool, len(schema.Required))
	for _, name := range schema.Required {
		required[name] = true
	}
	names := make([]string, 0, len(schema.Properties))
	for name := range schema.Properties {
		names = append(names, name)
	}
	sort.Strings(names)

	fields := make([]uiField, 0, len(names))
	for _, name := range names {
		ps := schema.Properties[name]
		if ps == nil {
			continue
		}
		f := uiField{
			Name:        name,
			Label:       ps.Title,
			Type:        ps.Type,
			IsBool:      ps.Type == "boolean",
			Required:    required[name],
			Description: ps.Description,
		}
		if f.Label == "" {
			f.Label = name
		}
		checked, text := schemaDefaultText(ps)
		f.Checked, f.Value = checked, text
		if v, ok := values[name]; ok {
			if f.IsBool {
				f.Checked = isTruthy(v)
			} else {
				f.Value = v
			}
		}
		fields = append(fields, f)
	}
	return fields
}

// schemaDefaultText 把 schema 的 default 转成表单可回填的 (bool 态, 文本)。
func schemaDefaultText(ps *jsonschema.Schema) (bool, string) {
	if ps.Default == nil {
		return false, ""
	}
	var v any
	if err := json.Unmarshal(ps.Default, &v); err != nil {
		return false, ""
	}
	switch t := v.(type) {
	case bool:
		return t, ""
	case string:
		return false, t
	case float64:
		if t == float64(int64(t)) {
			return false, strconv.FormatInt(int64(t), 10)
		}
		return false, strconv.FormatFloat(t, 'g', -1, 64)
	case []any:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			parts = append(parts, fmt.Sprintf("%v", e))
		}
		return false, strings.Join(parts, ", ")
	default:
		return false, ""
	}
}

// isTruthy 判定 checkbox 提交值是否代表"选中"。
func isTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "on", "true", "1", "yes":
		return true
	}
	return false
}

// handleRender 处理 POST /api/render:表单原值(全是字符串)→ 按 schema 归一化
// → renderOnce(与 MCP 共用业务与审计)→ 返回 render + apply 两段片段。
//
// 渲染失败一律 HTTP 200 + 片段(片段里 role="alert" 显示原因,表单保留用户
// 已填的值)——失败态不清空表单是设计稿的明确约定。
func (s *uiServer) handleRender(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeRenderRequest(w, r)
	if !ok {
		return
	}
	data := s.baseData()
	data.Active = "render"
	if !s.fillRenderForm(&data, req.Name, req.Params) {
		s.writeFragments(w, http.StatusOK, data, "render", "apply")
		return
	}
	cb, _ := s.app.reg.get(req.Name)
	params, err := coerceParams(cb, req.Params)
	if err != nil {
		data.Render.ErrorMsg = err.Error()
		s.writeFragments(w, http.StatusOK, data, "render", "apply")
		return
	}
	out, _, cause := renderOnce(s.app, renderIn{Name: req.Name, Params: params})
	if cause != nil {
		data.Render.ErrorMsg = cause.Error()
		s.writeFragments(w, http.StatusOK, data, "render", "apply")
		return
	}
	expires := s.planExpiry(out.PlanID)
	diff, added, removed, newFile := previewDiff(out)
	data.Render.Preview = &renderPreview{
		PlanID:          out.PlanID,
		TargetPath:      out.TargetPath,
		RenderedContent: out.RenderedContent,
		Diff:            diff,
		Added:           added,
		Removed:         removed,
		NewFile:         newFile,
		Warnings:        out.Warnings,
		ConfirmToken:    out.ConfirmToken,
		ExpiresAt:       formatExpiry(expires),
	}
	data.Apply = newApplyView(cb, req.Name, out.PlanID, out.ConfirmToken, out.TargetPath, expires, time.Now())
	data.Apply.CanApply = !data.Apply.Expired
	s.writeFragments(w, http.StatusOK, data, "render", "apply")
}

// handleApply 处理 POST /api/apply。
//
// 过期由服务端判:plan store 里的 Token.Expires 是 render 时
// confirmation.GenerateConfirmToken 记下的 now+15m,浏览器自报的任何时间都不采信。
func (s *uiServer) handleApply(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name         string `json:"name"`
		PlanID       string `json:"plan_id"`
		ConfirmToken string `json:"confirm_token"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writePlain(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	data := s.baseData()
	data.Active = "apply"

	cb, ok := s.app.reg.get(req.Name)
	if !ok {
		data.Apply = applyView{Blueprint: req.Name, ErrorMsg: fmt.Sprintf("蓝图 %q 不存在", req.Name)}
		s.writeFragments(w, http.StatusForbidden, data, "apply")
		return
	}
	plan, ok := s.app.plans.get(req.PlanID)
	if !ok {
		// 进程内 plan store 重启即失效(与 SDK 令牌登记表语义一致,fail-closed)。
		data.Apply = applyView{
			Blueprint: req.Name, Display: cb.Blueprint.DisplayName,
			Reload:   cb.Blueprint.ReloadService,
			ErrorMsg: "计划不存在或已失效(服务重启后计划即作废),请回到预览重新渲染",
		}
		s.writeFragments(w, http.StatusForbidden, data, "apply")
		return
	}
	// 目标路径与过期时刻都以 plan store 为准(不采信表单回传的任何一项)。
	view := newApplyView(cb, req.Name, req.PlanID, req.ConfirmToken, plan.Target, plan.Token.Expires, time.Now())
	// apply 前再核一次有效期:过期不给"带滚动提示的失败",而是明确 403 +
	// 让操作员回预览页重新渲染。
	if view.Expired {
		view.ErrorMsg = "令牌已过期，请回到预览重新渲染"
		data.Apply = view
		s.writeFragments(w, http.StatusForbidden, data, "apply")
		return
	}

	out, _, outcome, cause := applyOnce(r.Context(), s.app, applyIn{
		Name:         req.Name,
		PlanID:       req.PlanID,
		ConfirmToken: req.ConfirmToken,
	})
	status := http.StatusOK
	if outcome != "success" {
		status = http.StatusForbidden // denied:令牌/plan/白名单拒绝
		if outcome == "error" {
			status = http.StatusOK // 执行故障(已回滚):页面要展示回滚结论
		}
		view.ErrorMsg = cause.Error()
		view.RolledBack = strings.Contains(view.ErrorMsg, "已回滚")
		data.Apply = view
		s.writeFragments(w, status, data, "apply")
		return
	}
	// 成功后令牌已被消费:片段里不再回填 confirm_token,按钮也不可再点。
	view.Result = &applyResultView{
		TxID:        out.TxID,
		AppliedAt:   out.AppliedAt,
		ConfigPath:  out.ConfigPath,
		PostCheckOK: out.PostCheckOK,
		ReloadOK:    out.ReloadOK,
		HasRemove:   out.RemoveToken != "",
	}
	view.TargetPath = out.ConfigPath
	data.Apply = view
	s.writeFragments(w, http.StatusOK, data, "apply")
}

// newApplyView 组装应用视图的非秘密上下文。token 只供模板渲染进 hidden 字段;
// 过期判定与展示时刻都由服务端算(expires 来自 render 时签发的令牌记录)。
func newApplyView(cb *compiledBlueprint, name, planID, token, target string, expires int64, now time.Time) applyView {
	v := applyView{
		Blueprint:    name,
		Display:      cb.Blueprint.DisplayName,
		TargetPath:   target,
		Reload:       cb.Blueprint.ReloadService,
		PostCheck:    cb.postCheckCmd,
		PlanID:       planID,
		ConfirmToken: token,
		ExpiresAt:    formatExpiry(expires),
		Expired:      isExpired(expires, now),
	}
	// CanApply 默认 false:应用表单只在"刚渲染出新令牌"时给出(见 handleRender)。
	// apply 之后一律不再回填令牌 —— 成功时已消费,失败时也可能已消费。
	return v
}

// planExpiry 从 plan store 取 render 时由 SDK 记下的过期时刻(Unix 毫秒)。
// 取不到(理论面)时按当前时刻 + TTL 兜底,仍然由服务端算,不采信客户端。
func (s *uiServer) planExpiry(planID string) int64 {
	if plan, ok := s.app.plans.get(planID); ok && plan.Token.Expires > 0 {
		return plan.Token.Expires
	}
	return time.Now().Add(confirmation.ConfirmTokenTTL).UnixMilli()
}

// formatExpiry 把 Unix 毫秒转成 RFC 3339(模板倒计时用 data-expires-at)。
func formatExpiry(unixMilli int64) string {
	return time.UnixMilli(unixMilli).UTC().Format(time.RFC3339)
}

// isExpired 判定过期时刻是否已过。
func isExpired(unixMilli int64, now time.Time) bool {
	return now.UnixMilli() > unixMilli
}

// renderFormRequest 是 POST /api/render 的请求体:表单原值全是字符串,
// 类型归一化交给 coerceParams(服务端按 schema 转)。
type renderFormRequest struct {
	Name   string            `json:"name"`
	Params map[string]string `json:"params"`
}

// decodeRenderRequest 解析 render 请求体;失败时已写响应,调用方直接返回。
func decodeRenderRequest(w http.ResponseWriter, r *http.Request) (renderFormRequest, bool) {
	var req renderFormRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writePlain(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return req, false
	}
	return req, true
}

// decodeJSON 读取至多 1MiB 的 JSON 请求体。
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	defer func() { _ = r.Body.Close() }()
	return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v)
}

// writePlain 写纯文本应答(仅用于请求体损坏这类无法渲染模板的路径)。
func writePlain(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintln(w, msg)
}

// renderFull 渲染整页。
func (s *uiServer) renderFull(w http.ResponseWriter, data pageData) {
	var buf bytes.Buffer
	if err := s.tmpl.ExecuteTemplate(&buf, "layout", data); err != nil {
		writePlain(w, http.StatusInternalServerError, "模板渲染失败: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

// writeFragments 渲染若干具名模板,每段包在 [data-frag] 容器里供前端原位替换。
// 片段里保留 id 与 data-*,否则前端 JS 找不到节点。
func (s *uiServer) writeFragments(w http.ResponseWriter, status int, data pageData, names ...string) {
	var buf bytes.Buffer
	for _, name := range names {
		buf.WriteString(`<div data-frag="` + name + `">`)
		if err := s.tmpl.ExecuteTemplate(&buf, name, data); err != nil {
			writePlain(w, http.StatusInternalServerError, "模板渲染失败: "+err.Error())
			return
		}
		buf.WriteString("</div>\n")
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// coerceParams 把表单原值(全部是字符串)按 schema 归一化成 JSON 值。
// 表单无法表达数字/布尔/数组的类型,这一层是"表单 → blueprint_render 入参"
// 的唯一转换点;不在模板或 JS 里各写一套。
func coerceParams(cb *compiledBlueprint, raw map[string]string) (map[string]any, error) {
	params := make(map[string]any, len(raw))
	if cb == nil || cb.schemaResolved == nil {
		for k, v := range raw {
			params[k] = v
		}
		return params, nil
	}
	schema := cb.schemaResolved.Schema()
	if schema == nil {
		return params, nil
	}
	required := make(map[string]bool, len(schema.Required))
	for _, name := range schema.Required {
		required[name] = true
	}
	for name, ps := range schema.Properties {
		if ps == nil {
			continue
		}
		rawVal, ok := raw[name]
		if !ok {
			continue // 缺席交给 schema default / fillTemplateData
		}
		v, set, err := coerceField(name, ps, rawVal, required[name])
		if err != nil {
			return nil, err
		}
		if set {
			params[name] = v
		}
	}
	return params, nil
}

// coerceField 按 schema 类型归一化单个字段。set=false 表示"留空即缺席"
// (非必填字符串为空),让它回落到 schema 默认值 / 模板零值。
func coerceField(name string, ps *jsonschema.Schema, raw string, required bool) (any, bool, error) {
	switch ps.Type {
	case "boolean":
		return isTruthy(raw), true, nil
	case "integer", "number":
		s := strings.TrimSpace(raw)
		if s == "" {
			return nil, false, nil
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return nil, false, fmt.Errorf("字段 %q 需要整数, 得到 %q", name, raw)
		}
		return int(n), true, nil
	case "array":
		itemType := ""
		if ps.Items != nil {
			itemType = ps.Items.Type
		}
		parts := splitCSV(raw)
		if len(parts) == 0 {
			return nil, false, nil
		}
		arr := make([]any, 0, len(parts))
		for _, p := range parts {
			switch itemType {
			case "integer", "number":
				n, err := strconv.ParseInt(p, 10, 64)
				if err != nil {
					return nil, false, fmt.Errorf("字段 %q 需要整数列表, 得到 %q", name, p)
				}
				arr = append(arr, int(n))
			case "boolean":
				arr = append(arr, isTruthy(p))
			default:
				arr = append(arr, p)
			}
		}
		return arr, true, nil
	default:
		if raw == "" && !required {
			return nil, false, nil
		}
		return raw, true, nil
	}
}

// splitCSV 把逗号分隔的输入切成条目(去空白、丢空项)。
func splitCSV(raw string) []string {
	raw = strings.ReplaceAll(raw, "，", ",")
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// previewDiff 把 blueprint_render 的 diff 转成可渲染的行数组。
//
// render 在目标文件**不存在**时返回空 diff(它算不出差异);UI 的语义应把它
// 展示为"新建文件、全部新增"——直接复用本仓既有的 lineDiff("", content),
// 不在 UI 里另写一套"新文件 diff"。
func previewDiff(out renderOut) (lines []diffLine, added, removed int, newFile bool) {
	raw := out.Diff
	if strings.TrimSpace(raw) == "" {
		raw = lineDiff("", out.RenderedContent)
		newFile = true
	}
	lines = parseUnifiedDiff(raw)
	added, removed = diffStats(raw)
	return lines, added, removed, newFile
}

// parseUnifiedDiff 把 diff 文本解析成行数组。两种形态都支持:
//
//   - 本仓 lineDiff/unifiedDiff 的紧凑形态:`"+ "`/`"- "`/`"  "` 前缀,无 @@ 头;
//   - 标准 unified diff:单字符前缀 + `@@ -a,b +c,d @@` hunk 头。
//
// 判据是文本里是否出现 hunk 头(本仓产出永不出现 @@)。行号按 unified diff
// 惯例填:+ 行无旧行号,- 行无新行号。`\ No newline at end of file` 这类标记
// 行必须保留可读(不能吞掉)。
func parseUnifiedDiff(text string) []diffLine {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	standard := strings.HasPrefix(text, "@@") || strings.Contains(text, "\n@@")
	oldNo, newNo := 1, 1
	lines := make([]diffLine, 0, strings.Count(text, "\n")+1)
	for _, raw := range strings.Split(text, "\n") {
		switch {
		case strings.HasPrefix(raw, "@@"):
			oldNo, newNo = parseHunkHeader(raw, oldNo, newNo)
			lines = append(lines, diffLine{Sign: "@@", Text: raw, Class: "hunk"})
			continue
		case strings.HasPrefix(raw, `\`):
			lines = append(lines, diffLine{Sign: `\`, Text: raw, Class: "hunk"})
			continue
		}
		sign, rest := splitDiffSign(raw, standard)
		switch sign {
		case '+':
			lines = append(lines, diffLine{NewNo: strconv.Itoa(newNo), Sign: "+", Text: rest, Class: "add"})
			newNo++
		case '-':
			lines = append(lines, diffLine{OldNo: strconv.Itoa(oldNo), Sign: "-", Text: rest, Class: "del"})
			oldNo++
		default:
			lines = append(lines, diffLine{
				OldNo: strconv.Itoa(oldNo), NewNo: strconv.Itoa(newNo),
				Sign: " ", Text: rest, Class: "ctx",
			})
			oldNo++
			newNo++
		}
	}
	return lines
}

// splitDiffSign 拆出符号与内容。紧凑形态的符号后跟一个分隔空格,标准形态
// 没有;两者都靠"整篇是否标准形态"一次性判定,避免逐行歧义。
func splitDiffSign(raw string, standard bool) (byte, string) {
	if standard {
		if len(raw) == 0 {
			return ' ', ""
		}
		switch raw[0] {
		case '+', '-', ' ':
			return raw[0], raw[1:]
		}
		return ' ', raw
	}
	if len(raw) >= 2 {
		switch raw[0] {
		case '+', '-', ' ':
			// 紧凑形态固定为 "<sign><space><content>"。
			if raw[1] == ' ' {
				return raw[0], raw[2:]
			}
			return raw[0], raw[1:]
		}
	}
	if len(raw) == 1 {
		switch raw[0] {
		case '+', '-', ' ':
			return raw[0], ""
		}
	}
	return ' ', raw
}

// parseHunkHeader 解析 `@@ -a,b +c,d @@` 的行号起点;解析失败保持原计数器。
func parseHunkHeader(raw string, oldNo, newNo int) (int, int) {
	fields := strings.Fields(raw)
	for _, f := range fields {
		switch {
		case strings.HasPrefix(f, "-"):
			if n, ok := hunkStart(f[1:]); ok {
				oldNo = n
			}
		case strings.HasPrefix(f, "+"):
			if n, ok := hunkStart(f[1:]); ok {
				newNo = n
			}
		}
	}
	return oldNo, newNo
}

// hunkStart 取 "a,b" / "a" 的起始行号。
func hunkStart(spec string) (int, bool) {
	if i := strings.IndexByte(spec, ','); i >= 0 {
		spec = spec[:i]
	}
	n, err := strconv.Atoi(spec)
	if err != nil {
		return 0, false
	}
	return n, true
}

// diffStats 统计 diff 文本里的新增/删除行数。
func diffStats(text string) (added, removed int) {
	if strings.TrimSpace(text) == "" {
		return 0, 0
	}
	standard := strings.HasPrefix(text, "@@") || strings.Contains(text, "\n@@")
	for _, raw := range strings.Split(text, "\n") {
		if strings.HasPrefix(raw, "@@") || strings.HasPrefix(raw, `\`) {
			continue
		}
		sign, _ := splitDiffSign(raw, standard)
		switch sign {
		case '+':
			added++
		case '-':
			removed++
		}
	}
	return added, removed
}

// parseListen 解析 --listen:空 → 默认值;off → 关闭;其余必须是 loopback 的
// host:port。非 loopback 一律拒绝启动(rc=2),因为 Host 白名单只认 127.0.0.1 /
// localhost —— 允许监听其它地址等于让所有请求都 403。
func parseListen(v string) (addr string, off bool, err error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return uiDefaultListen, false, nil
	}
	if v == "off" {
		return "", true, nil
	}
	host, port, splitErr := net.SplitHostPort(v)
	if splitErr != nil {
		return "", false, fmt.Errorf("--listen 需要 host:port 形式, 得到 %q", v)
	}
	if host != "127.0.0.1" && host != "localhost" {
		return "", false, fmt.Errorf("--listen %q 不是 loopback:UI 只允许 127.0.0.1 或 localhost", v)
	}
	n, convErr := strconv.Atoi(port)
	if convErr != nil || n < 0 || n > 65535 {
		return "", false, fmt.Errorf("--listen %q 的端口不合法", v)
	}
	return net.JoinHostPort(host, port), false, nil
}

// runUI 是 `daedalus-blueprint ui` 的入口。返回进程退出码。
func runUI(args []string) int {
	fs := flag.NewFlagSet("ui", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	listen := fs.String("listen", uiDefaultListen, "监听地址(只允许 127.0.0.1 / localhost);off 关闭")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	addr, off, err := parseListen(*listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s ui: %v\n", serverName, err)
		return 2
	}
	if off {
		fmt.Fprintf(os.Stderr, "%s ui: --listen off,不启动 UI\n", serverName)
		return 0
	}

	a, err := initRuntime()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s server error: %v\n", serverName, err)
		return 1
	}
	s, err := newUIServer(a, addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s ui error: %v\n", serverName, err)
		return 1
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           s.handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	fmt.Fprintf(os.Stderr, "%s ui 监听 http://%s (仅本机)\n", serverName, addr)

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "%s ui error: %v\n", serverName, err)
			return 1
		}
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}
	return 0
}
