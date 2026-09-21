// 状态记忆接线测试(计划 todo 20,Happy/Failure QA 前缀 TestStateWiring):
// 成功的 service.query / service.list 各落一条 state 条目、失败调用零落盘、
// stateLog 报错时 best-effort(工具结果逐字节不变 + stderr 一行中文提示)。
// systemctl 注入复用 main_test.go 的 fakeSystemctl,状态路径经
// t.Setenv(dirs.EnvStatePath) 指向 t.TempDir() 独占文件——断言精确计数
// 不被其他测试的写入污染。
package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Daedalusys/daedalus-sdk/dirs"
	"github.com/Daedalusys/daedalus-sdk/objectmodel"
	"github.com/Daedalusys/daedalus-sdk/state"
)

// TestMain 为全包钉死 DAEDALUS_STATE_PATH 基线:todo 20 起每次成功的
// query/list 都会真实追加写 state.jsonl,若不隔离,dirs 解析链会落到
// /var/lib/daedalus 或 $HOME/.local/share/daedalus——跑一遍测试就污染
// 开发者真实状态记忆(测试隔离纪律)。个别测试用 t.Setenv 覆写本基线。
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "daedalus-service-state-*")
	if err != nil {
		os.Exit(1)
	}
	os.Setenv(dirs.EnvStatePath, filepath.Join(dir, "state.jsonl"))
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// useTempState 把状态文件指到本测试独占的新路径并返回它(t.Setenv 自动还原)。
func useTempState(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "state.jsonl")
	t.Setenv(dirs.EnvStatePath, p)
	return p
}

// readState 全量回读状态文件(容错读取器语义:文件不存在 → 零条目零错误)。
func readState(t *testing.T) []state.StateEntry {
	t.Helper()
	entries, err := state.Read(time.Time{})
	if err != nil {
		t.Fatalf("state.Read 失败: %v", err)
	}
	return entries
}

// TestStateWiring_QueryAppendsEntry Happy:成功 query sshd → 恰一条条目,
// Kind/Name 精确,ObservedAt 为近期时刻,Payload 反序列化回 ServiceState
// 且携带夹具真实属性(反造假:凭输入拼 {kind,name} 的桩载荷必然在此爆红)。
// 计划 Happy QA 文字指定的读回入口 state.LatestByKind("service") 同步断言。
func TestStateWiring_QueryAppendsEntry(t *testing.T) {
	fakeSystemctl(t, happyFixtureOutput)
	useTempState(t)
	session, ctx := connectSession(t)

	start := time.Now().UTC().Add(-time.Minute)
	res, text := callTool(t, session, ctx, map[string]any{"name": "sshd"})
	if res.IsError {
		t.Fatalf("合法查询被误判为错误: %s", text)
	}

	entries := readState(t)
	if len(entries) != 1 {
		t.Fatalf("state 条目数 = %d, want 1(每次成功 query 恰一条)", len(entries))
	}
	e := entries[0]
	if e.Kind != "service" || e.Name != "sshd.service" {
		t.Errorf("条目骨架 = kind=%q name=%q, want kind=service name=sshd.service", e.Kind, e.Name)
	}
	if e.ObservedAt.Before(start) || e.ObservedAt.After(time.Now().UTC().Add(time.Minute)) {
		t.Errorf("ObservedAt = %v, want 近期时刻", e.ObservedAt)
	}

	var got objectmodel.ServiceState
	if err := json.Unmarshal(e.Payload, &got); err != nil {
		t.Fatalf("Payload 反序列化失败: %v\n%s", err, e.Payload)
	}
	if got.Properties["ActiveState"] != "inactive" || got.Name != "sshd.service" || got.Kind != "service" {
		t.Errorf("Payload round-trip = %+v, want 夹具原文 ActiveState=inactive", got)
	}

	latest, err := state.LatestByKind("service")
	if err != nil {
		t.Fatalf("LatestByKind 失败: %v", err)
	}
	if len(latest) != 1 || latest[0].Name != "sshd.service" {
		t.Errorf("LatestByKind(service) = %+v, want 恰一条 sshd.service", latest)
	}
}

// TestStateWiring_ListSingleEntryPerCall 钉死 list 语义读法:计划标题逐字
// "one state entry per successful service.query / service.list **call**"
// ——list 一条/调用、不分单元;Name=生效过滤模式(缺省 "*"),
// Payload 与工具回包同值的完整数组 JSON。
func TestStateWiring_ListSingleEntryPerCall(t *testing.T) {
	fakeSystemctl(t, listFixtureOutput)
	useTempState(t)
	session, ctx := connectSession(t)

	res, text := callListTool(t, session, ctx, map[string]any{"filter": "sshd"})
	if res.IsError {
		t.Fatalf("合法列出被误判为错误: %s", text)
	}
	entries := readState(t)
	if len(entries) != 1 {
		t.Fatalf("state 条目数 = %d, want 1(单次 list 调用不分单元)", len(entries))
	}
	e := entries[0]
	if e.Kind != "service" || e.Name != "sshd" {
		t.Errorf("条目骨架 = kind=%q name=%q, want service/sshd(Name=过滤模式)", e.Kind, e.Name)
	}
	var states []objectmodel.ServiceState
	if err := json.Unmarshal(e.Payload, &states); err != nil {
		t.Fatalf("Payload 非数组: %v\n%s", err, e.Payload)
	}
	if len(states) != 3 || states[2].Name != "sshd.service" || states[2].Properties["ActiveState"] != "active" {
		t.Errorf("Payload 数组 = %+v, want 夹具三单元(sshd active)", states)
	}
	// 载荷与工具回包必须是同一份 JSON(同值断言,不受缩进/紧凑排版差异影响)。
	var fromText, fromPayload any
	if err := json.Unmarshal([]byte(text), &fromText); err != nil {
		t.Fatalf("回包解析失败: %v", err)
	}
	if err := json.Unmarshal(e.Payload, &fromPayload); err != nil {
		t.Fatalf("载荷解析失败: %v", err)
	}
	if !reflect.DeepEqual(fromText, fromPayload) {
		t.Errorf("Payload 与工具回包不同值:\ntext=%s\npayload=%s", text, e.Payload)
	}

	// 缺省 filter(未提供 → "*")同样一条,Name 钉为 "*"。
	res2, text2 := callListTool(t, session, ctx, map[string]any{})
	if res2.IsError {
		t.Fatalf("缺省 filter 列出被误判为错误: %s", text2)
	}
	entries = readState(t)
	if len(entries) != 2 {
		t.Fatalf("两次调用后条目数 = %d, want 2", len(entries))
	}
	if entries[1].Name != "*" {
		t.Errorf("缺省调用条目 Name = %q, want \"*\"", entries[1].Name)
	}
}

// TestStateWiring_FailedCallsWriteNothing Failure QA:unit not-found、
// 校验拒名、空 filter 三种失败面皆不落任何条目——连文件都不存在
// (stateLog 从未被调用,O_CREATE 没有触发)。
func TestStateWiring_FailedCallsWriteNothing(t *testing.T) {
	fakeSystemctl(t, "LoadState=not-found\n")
	p := useTempState(t)
	session, ctx := connectSession(t)

	if res, text := callTool(t, session, ctx, map[string]any{"name": "missing"}); !res.IsError {
		t.Fatalf("not-found 单元竟然成功: %s", text)
	}
	if res, text := callTool(t, session, ctx, map[string]any{"name": "a b"}); !res.IsError {
		t.Fatalf("非法名竟然成功: %s", text)
	}
	if res, text := callListTool(t, session, ctx, map[string]any{"filter": ""}); !res.IsError {
		t.Fatalf("空 filter 竟然成功: %s", text)
	}

	if entries := readState(t); len(entries) != 0 {
		t.Errorf("失败调用产生了条目: %+v", entries)
	}
	if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("失败调用创建了状态文件: %v", err)
	}
}

// TestStateWiring_StateWriteFailureKeepsResult best-effort 语义:stateLog
// 覆写为恒报错桩后,工具结果与注入前的成功基线**逐字节相同**、IsError 仍为
// false,唯一可观察差异是 stderr 一行中文提示;且失败的这次调用不留半行。
func TestStateWiring_StateWriteFailureKeepsResult(t *testing.T) {
	fakeSystemctl(t, happyFixtureOutput)
	useTempState(t)
	session, ctx := connectSession(t)

	// 基线:注入前一次正常成功调用的回包字节。
	_, want := callTool(t, session, ctx, map[string]any{"name": "sshd"})

	orig := stateLog
	stateLog = func(state.StateEntry) error { return errors.New("模拟写盘失败") }
	t.Cleanup(func() { stateLog = orig })

	origStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("建 stderr 捕获管道失败: %v", err)
	}
	os.Stderr = w
	res, text := callTool(t, session, ctx, map[string]any{"name": "sshd"})
	// CallTool 同步等到 handler 返回,Fprintf 已发生;先还原再排空管道。
	os.Stderr = origStderr
	_ = w.Close()
	captured, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("读取 stderr 捕获失败: %v", err)
	}

	if res.IsError {
		t.Fatalf("状态写失败泄漏进工具结果: %s", text)
	}
	if text != want {
		t.Errorf("工具结果字节变了:\ngot  %q\nwant %q", text, want)
	}
	msg := string(captured)
	if !strings.Contains(msg, "daedalus-service: 状态写入失败:") || !strings.Contains(msg, "模拟写盘失败") {
		t.Errorf("stderr 提示缺失/内容漂移: %q", msg)
	}
	// 失败这次没落任何条目:文件里只有基线那一条。
	if entries := readState(t); len(entries) != 1 {
		t.Errorf("条目数 = %d, want 1(仅基线那次;写失败不留行)", len(entries))
	}
}
