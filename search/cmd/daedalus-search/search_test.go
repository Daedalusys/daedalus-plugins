// search_test.go 是 daedalus.search 服务层的单测:夹具/替身驱动,零触碰宿主
// Baloo 索引与 D-Bus。
//
// 覆盖:
//   - 参数校验(query/dir/mimetype/since/until/size_min/size_max);
//   - D-Bus 可达 + Baloo 注册 + 索引启用的正常搜索路径;
//   - D-Bus 不可达 / Baloo 未注册 / 索引禁用 三条降级路径(advisory,不阻塞 fork);
//   - mimetype 过滤通过 Baloo `type:` 前缀注入;
//   - baloosearch 退出错误翻译(ExecError/D-Bus 错误);
//   - search_reindex L1 deferred;
//   - file:// URL 与路径互转、parseBalooPaths。
package main

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- 替身 ---

// fakeDBus 是可注入 balooDBus 替身:可配置 NameHasOwner / IndexingEnabled 的
// 返回与错误,并记录 Close 调用。
type fakeDBus struct {
	owned       bool
	ownedErr    error
	indexing    bool
	indexingErr error
	closed      bool
}

func (f *fakeDBus) NameHasOwner(string) (bool, error) { return f.owned, f.ownedErr }
func (f *fakeDBus) IndexingEnabled() (bool, error)    { return f.indexing, f.indexingErr }
func (f *fakeDBus) Close() error                      { f.closed = true; return nil }

// fakeRunner 复制自 smart 家族:按 results 顺序分配每次 baloosearch 调用的
// stdout/err;记录 calls / argv。
type fakeRunner struct {
	calls   int
	results []fakeResult
	lastBin string
	lastArg []string
}

type fakeResult struct {
	lines [][]byte
	err   error
}

func (f *fakeRunner) run(_ context.Context, bin string, _ io.Reader, onLine func([]byte) bool, args ...string) error {
	f.lastBin = bin
	f.lastArg = append([]string(nil), args...)
	idx := f.calls
	f.calls++
	if idx >= len(f.results) {
		return nil
	}
	r := f.results[idx]
	for _, line := range r.lines {
		if !onLine(line) {
			return nil
		}
	}
	return r.err
}

// newFakeService 装配挂 fakeRunner 的 service;connect 可另行覆盖。
func newFakeService(results ...fakeResult) (*service, *fakeRunner) {
	fr := &fakeRunner{results: results}
	return &service{
		connect: func() (balooDBus, error) { return &fakeDBus{owned: true, indexing: true}, nil },
		run:     fr.run,
		binary:  "baloosearch-stub",
		timeout: searchTimeout,
	}, fr
}

// lines 把字符串按行拆成 [][]byte。
func lines(s string) [][]byte {
	var out [][]byte
	for _, l := range strings.Split(s, "\n") {
		out = append(out, []byte(l))
	}
	return out
}

// --- 参数校验 ---

func TestValidateSearchQuery(t *testing.T) {
	valid := []string{"foo", "content:hello world", "filename:*.go", "温度", "a-b/c"}
	for _, q := range valid {
		if err := validateSearchQuery(q); err != nil {
			t.Errorf("query %q 应通过, got %v", q, err)
		}
	}
	invalid := []string{"", "a\nb", "a\tb", "a\rb", "a\x00b"}
	for _, q := range invalid {
		if err := validateSearchQuery(q); err == nil {
			t.Errorf("query %q 应拒绝", q)
		}
	}
}

func TestValidateSearchDir(t *testing.T) {
	valid := []string{"", "/home", "/home/user/docs", "/media/data/项目", "/a.b-c_d"}
	for _, d := range valid {
		if err := validateSearchDir(d); err != nil {
			t.Errorf("dir %q 应通过, got %v", d, err)
		}
	}
	invalid := []string{
		"relative/path",
		"/home/../etc",
		"/home/user a",
		"-/home",
		"/home/user;rm",
		"/home/user|cat",
		"/home/user`id`",
		"/home/user$(id)",
		"/home/user&",
		"/home/\x00",
		"/home/user\n",
	}
	for _, d := range invalid {
		if err := validateSearchDir(d); err == nil {
			t.Errorf("dir %q 应拒绝", d)
		}
	}
}

func TestValidateMimetype(t *testing.T) {
	for _, m := range []string{"", "text/plain", "image/png", "application/x-tar"} {
		if err := validateMimetype(m); err != nil {
			t.Errorf("mimetype %q 应通过, got %v", m, err)
		}
	}
	for _, m := range []string{"plain", "text", "text/", "/plain", "text plain"} {
		if err := validateMimetype(m); err == nil {
			t.Errorf("mimetype %q 应拒绝", m)
		}
	}
}

func TestValidateTimestamp(t *testing.T) {
	if _, err := validateTimestamp("since", ""); err != nil {
		t.Errorf("空时间戳应通过, got %v", err)
	}
	if _, err := validateTimestamp("since", "2024-01-02T15:04:05Z"); err != nil {
		t.Errorf("RFC3339 应通过, got %v", err)
	}
	if _, err := validateTimestamp("since", "2024/01/02"); err == nil {
		t.Errorf("非 RFC3339 应拒绝")
	}
}

func TestValidateSize(t *testing.T) {
	z, n := int64(0), int64(-1)
	if err := validateSize("size_min", nil); err != nil {
		t.Errorf("nil 应通过")
	}
	if err := validateSize("size_min", &z); err != nil {
		t.Errorf("0 应通过")
	}
	if err := validateSize("size_min", &n); err == nil {
		t.Errorf("负数应拒绝")
	}
}

// --- URL 转换 / parseBalooPaths ---

func TestPathURLRoundtrip(t *testing.T) {
	for _, p := range []string{"/home/user/a.txt", "/media/数据/b.md", "/tmp/x y.tar"} {
		u := pathToFileURL(p)
		if !strings.HasPrefix(u, "file://") {
			t.Fatalf("pathToFileURL(%q) = %q", p, u)
		}
		got := fileURLToPath(u)
		if got != filepath.Clean(p) {
			t.Errorf("roundtrip %q → %q → %q", p, u, got)
		}
	}
	if fileURLToPath("not-a-url") != "" {
		t.Errorf("非 file URL 应返空")
	}
	if pathToFileURL("file:///already") != "file:///already" {
		t.Errorf("已是 file URL 应原样")
	}
}

func TestParseBalooPaths(t *testing.T) {
	raw := "file:///home/a.txt\n\nElapsed: 3 msecs\n/home/b.go\nError: bad\nfile:///media/%E6%96%87\n"
	got := parseBalooPaths(lines(raw))
	if len(got) != 3 {
		t.Fatalf("paths = %v, want 3", got)
	}
}

// --- 正常搜索 ---

func TestSearchFiles_NormalPath(t *testing.T) {
	// 构造真实临时文件,验证 stat 过滤/字段填充。
	dir := t.TempDir()
	f := filepath.Join(dir, "hello.txt")
	if err := os.WriteFile(f, []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	svc, fr := newFakeService(fakeResult{lines: lines(f)})
	res, err := svc.SearchFiles(context.Background(), SearchFileArgs{Query: "hello"})
	if err != nil {
		t.Fatalf("SearchFiles: %v", err)
	}
	if fr.calls != 1 {
		t.Errorf("calls = %d, want 1", fr.calls)
	}
	if len(res.Files) != 1 || res.Files[0].Path != f {
		t.Fatalf("files = %+v", res.Files)
	}
	if res.Files[0].Size != 2 {
		t.Errorf("size = %d, want 2", res.Files[0].Size)
	}
	if res.Files[0].Mtime == "" {
		t.Errorf("mtime 应被填充")
	}
	if res.Count != 1 {
		t.Errorf("count = %d", res.Count)
	}
	// argv 应含 -l 200 与 query。
	if fr.lastArg[len(fr.lastArg)-1] != "hello" {
		t.Errorf("argv = %v", fr.lastArg)
	}
}

func TestSearchFiles_DirPassedAsArg(t *testing.T) {
	svc, fr := newFakeService(fakeResult{lines: lines("")})
	if _, err := svc.SearchFiles(context.Background(), SearchFileArgs{Query: "q", Dir: "/home/u"}); err != nil {
		t.Fatalf("SearchFiles: %v", err)
	}
	joined := strings.Join(fr.lastArg, " ")
	if !strings.Contains(joined, "-d /home/u") {
		t.Errorf("argv = %v, 应含 -d /home/u", fr.lastArg)
	}
}

func TestSearchFiles_SizeFilter(t *testing.T) {
	dir := t.TempDir()
	small := filepath.Join(dir, "small")
	big := filepath.Join(dir, "big")
	_ = os.WriteFile(small, []byte("x"), 0o644)
	_ = os.WriteFile(big, []byte(strings.Repeat("y", 100)), 0o644)
	svc, _ := newFakeService(fakeResult{lines: lines(small + "\n" + big)})
	min := int64(50)
	res, err := svc.SearchFiles(context.Background(), SearchFileArgs{Query: "q", SizeMin: &min})
	if err != nil {
		t.Fatalf("SearchFiles: %v", err)
	}
	if len(res.Files) != 1 || res.Files[0].Path != big {
		t.Fatalf("size_min 过滤错: %+v", res.Files)
	}
}

func TestSearchContent_NormalPath(t *testing.T) {
	svc, fr := newFakeService(fakeResult{lines: lines("/home/a.go\n/home/b.go")})
	res, err := svc.SearchContent(context.Background(), ContentSearchArgs{Query: "func main"})
	if err != nil {
		t.Fatalf("SearchContent: %v", err)
	}
	if fr.calls != 1 || len(res.Files) != 2 {
		t.Fatalf("content res = %+v (calls=%d)", res, fr.calls)
	}
	if res.Files[0].Path != "/home/a.go" {
		t.Errorf("path = %q", res.Files[0].Path)
	}
}

// --- 降级路径 ---

func TestSearchFiles_DBusUnreachable_StillForks(t *testing.T) {
	// D-Bus 仅 advisory:不可达不阻塞 baloosearch fork,仍尝试查询。
	dir := t.TempDir()
	f := filepath.Join(dir, "x.txt")
	if err := os.WriteFile(f, []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	svc, fr := newFakeService(fakeResult{lines: lines(f)})
	svc.connect = func() (balooDBus, error) { return nil, errors.New("no session bus") }
	res, err := svc.SearchFiles(context.Background(), SearchFileArgs{Query: "q"})
	if err != nil {
		t.Fatalf("不可达不应致命: %v", err)
	}
	if fr.calls != 1 {
		t.Errorf("不可达仍应 fork baloosearch: calls=%d", fr.calls)
	}
	if len(res.Files) != 1 {
		t.Errorf("应返回 1 条结果: %+v", res.Files)
	}
	if !strings.Contains(res.Note, "D-Bus session bus 不可达") {
		t.Errorf("note 应含 D-Bus advisory: %q", res.Note)
	}
}

func TestSearchFiles_BalooNotRegistered_StillForks(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "x.txt")
	if err := os.WriteFile(f, []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	svc, fr := newFakeService(fakeResult{lines: lines(f)})
	svc.connect = func() (balooDBus, error) { return &fakeDBus{owned: false}, nil }
	res, err := svc.SearchFiles(context.Background(), SearchFileArgs{Query: "q"})
	if err != nil {
		t.Fatalf("未注册不应致命: %v", err)
	}
	if fr.calls != 1 {
		t.Errorf("未注册仍应 fork baloosearch: calls=%d", fr.calls)
	}
	if !strings.Contains(res.Note, "org.kde.baloo 未注册") {
		t.Errorf("note = %q", res.Note)
	}
}

func TestSearchFiles_IndexingDisabled_StillForks(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "x.txt")
	if err := os.WriteFile(f, []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	svc, fr := newFakeService(fakeResult{lines: lines(f)})
	svc.connect = func() (balooDBus, error) { return &fakeDBus{owned: true, indexing: false}, nil }
	res, err := svc.SearchFiles(context.Background(), SearchFileArgs{Query: "q"})
	if err != nil {
		t.Fatalf("索引禁用不应致命: %v", err)
	}
	if fr.calls != 1 {
		t.Errorf("索引禁用仍应 fork baloosearch: calls=%d", fr.calls)
	}
	if !strings.Contains(res.Note, "IndexingEnabled=false") {
		t.Errorf("note = %q", res.Note)
	}
}

func TestSearchContent_DBusUnreachable_StillForks(t *testing.T) {
	svc, fr := newFakeService(fakeResult{lines: lines("/home/a.go")})
	svc.connect = func() (balooDBus, error) { return nil, errors.New("no bus") }
	res, err := svc.SearchContent(context.Background(), ContentSearchArgs{Query: "q"})
	if err != nil {
		t.Fatalf("不可达不应致命: %v", err)
	}
	if len(res.Files) != 1 || !strings.Contains(res.Note, "D-Bus") {
		t.Errorf("res = %+v", res)
	}
	if fr.calls != 1 {
		t.Errorf("不可达仍应 fork: calls=%d", fr.calls)
	}
}

// --- 错误翻译 ---

func TestTranslateBalooError(t *testing.T) {
	// nil → 成功
	if note, fatal := translateBalooError(nil); note != "" || fatal {
		t.Errorf("nil → (%q,%v)", note, fatal)
	}
	// binary 缺失 → note,不 fatal
	miss := &fs.PathError{Op: "fork/exec", Path: "/usr/bin/baloosearch", Err: fs.ErrNotExist}
	if note, fatal := translateBalooError(miss); fatal || !strings.Contains(note, "不可用") {
		t.Errorf("missing → (%q,%v)", note, fatal)
	}
	// rc=1 无 stderr → note,不 fatal
	rc1 := &execError{Code: 1, Cause: errors.New("exit 1")}
	if note, fatal := translateBalooError(rc1); fatal || !strings.Contains(note, "命令行") {
		t.Errorf("rc1 → (%q,%v)", note, fatal)
	}
	// rc=2 无 stderr → note,不 fatal
	rc2 := &execError{Code: 2, Cause: errors.New("exit 2")}
	if note, fatal := translateBalooError(rc2); fatal || !strings.Contains(note, "退出码 2") {
		t.Errorf("rc2 → (%q,%v)", note, fatal)
	}
	// 真 stderr → fatal
	se := &execError{Code: 2, Stderr: "Cannot connect to daemon", Cause: errors.New("exit 2")}
	if _, fatal := translateBalooError(se); !fatal {
		t.Errorf("真 stderr 应 fatal")
	}
	// 其它错误 → fatal
	if _, fatal := translateBalooError(errors.New("pipe broke")); !fatal {
		t.Errorf("非 execError 应 fatal")
	}
}

func TestSearchFiles_StderrFatal(t *testing.T) {
	svc, _ := newFakeService(fakeResult{err: &execError{Code: 2, Stderr: "boom", Cause: errors.New("exit 2")}})
	_, err := svc.SearchFiles(context.Background(), SearchFileArgs{Query: "q"})
	if err == nil {
		t.Fatalf("真 stderr 应上抛错误")
	}
	if !strings.Contains(err.Error(), "search_files") {
		t.Errorf("错误应带工具名: %v", err)
	}
}

func TestSearchFiles_BinaryMissingDegrades(t *testing.T) {
	svc, _ := newFakeService(fakeResult{err: &fs.PathError{Op: "fork/exec", Path: "baloosearch-stub", Err: fs.ErrNotExist}})
	res, err := svc.SearchFiles(context.Background(), SearchFileArgs{Query: "q"})
	if err != nil {
		t.Fatalf("缺 binary 应降级: %v", err)
	}
	if !strings.Contains(res.Note, "不可用") {
		t.Errorf("note = %q", res.Note)
	}
}

// --- 参数校验前置:非法参数不 fork ---

func TestSearchFiles_ValidationDoesNotFork(t *testing.T) {
	cases := []SearchFileArgs{
		{Query: ""},
		{Query: "q", Dir: "relative"},
		{Query: "q", Mimetype: "bad"},
		{Query: "q", Since: "not-a-date"},
		{Query: "q", SizeMin: int64Ptr(-1)},
	}
	for i, c := range cases {
		svc, fr := newFakeService()
		if _, err := svc.SearchFiles(context.Background(), c); err == nil {
			t.Errorf("case %d 应报错: %+v", i, c)
		}
		if fr.calls != 0 {
			t.Errorf("case %d 不应 fork: calls=%d", i, fr.calls)
		}
	}
}

func TestSearchFiles_SizeRangeReversed(t *testing.T) {
	svc, fr := newFakeService()
	_, err := svc.SearchFiles(context.Background(), SearchFileArgs{Query: "q", SizeMin: int64Ptr(100), SizeMax: int64Ptr(10)})
	if err == nil {
		t.Fatalf("size_min>size_max 应报错")
	}
	if fr.calls != 0 {
		t.Errorf("不应 fork")
	}
}

func TestSearchFiles_SinceAfterUntil(t *testing.T) {
	// 对称 size_min>size_max:since > until 拒绝,不 fork。
	svc, fr := newFakeService()
	_, err := svc.SearchFiles(context.Background(), SearchFileArgs{
		Query: "q",
		Since: "2024-12-31T00:00:00Z",
		Until: "2024-01-01T00:00:00Z",
	})
	if err == nil {
		t.Fatalf("since > until 应报错")
	}
	if !strings.Contains(err.Error(), "since=") || !strings.Contains(err.Error(), "until=") {
		t.Errorf("错误应含 since/until: %v", err)
	}
	if fr.calls != 0 {
		t.Errorf("不应 fork: calls=%d", fr.calls)
	}
}

// --- mimetype 过滤:Baloo `type:` 前缀注入 ---

func TestSearchFiles_MimetypeInjectedAsTypePrefix(t *testing.T) {
	// mimetype 应作为 Baloo `type:` 前缀并入 query 末尾之前的部分。
	svc, fr := newFakeService(fakeResult{lines: lines("")})
	_, err := svc.SearchFiles(context.Background(), SearchFileArgs{
		Query: "hello", Mimetype: "text/plain",
	})
	if err != nil {
		t.Fatalf("SearchFiles: %v", err)
	}
	// argv 末项是 query,形态应为 `type:text/plain hello`。
	last := fr.lastArg[len(fr.lastArg)-1]
	if last != "type:text/plain hello" {
		t.Errorf("argv 末项 = %q, want %q", last, "type:text/plain hello")
	}
}

func TestSearchFiles_MimetypeAlreadyInQuery_NotOverridden(t *testing.T) {
	// 若 query 自身已带 `type:` 前缀,用户显式优先,不二次注入。
	svc, fr := newFakeService(fakeResult{lines: lines("")})
	_, _ = svc.SearchFiles(context.Background(), SearchFileArgs{
		Query: "type:image/png logo", Mimetype: "text/plain",
	})
	joined := strings.Join(fr.lastArg, " ")
	if strings.Count(joined, "type:") != 1 {
		t.Errorf("应仅 1 个 type: 前缀, got %v", fr.lastArg)
	}
	if !strings.Contains(joined, "type:image/png logo") {
		t.Errorf("用户原始 type: 应保留: %v", fr.lastArg)
	}
}

func TestSearchFiles_MimetypeAbsent_NoInjection(t *testing.T) {
	// 未传 mimetype 时 query 不被改动。
	svc, fr := newFakeService(fakeResult{lines: lines("")})
	_, _ = svc.SearchFiles(context.Background(), SearchFileArgs{Query: "hello"})
	last := fr.lastArg[len(fr.lastArg)-1]
	if last != "hello" {
		t.Errorf("argv 末项 = %q, want %q", last, "hello")
	}
}

func TestSearchFiles_MimetypeFilledInHit(t *testing.T) {
	// 当用户传 mimetype,FileHit.Mimetype 应被回填(无需 file --mime-type fork)。
	dir := t.TempDir()
	f := filepath.Join(dir, "x.txt")
	if err := os.WriteFile(f, []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	svc, _ := newFakeService(fakeResult{lines: lines(f)})
	res, err := svc.SearchFiles(context.Background(), SearchFileArgs{
		Query: "x", Mimetype: "text/plain",
	})
	if err != nil {
		t.Fatalf("SearchFiles: %v", err)
	}
	if len(res.Files) != 1 || res.Files[0].Mimetype != "text/plain" {
		t.Errorf("FileHit.Mimetype 未回填: %+v", res.Files)
	}
}

func TestSearchFiles_MimetypeAbsent_HitMimetypeEmpty(t *testing.T) {
	// 未传 mimetype 时 FileHit.Mimetype 留空(避免无 file --mime-type 而瞎填)。
	dir := t.TempDir()
	f := filepath.Join(dir, "x.txt")
	if err := os.WriteFile(f, []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	svc, _ := newFakeService(fakeResult{lines: lines(f)})
	res, _ := svc.SearchFiles(context.Background(), SearchFileArgs{Query: "x"})
	if len(res.Files) != 1 || res.Files[0].Mimetype != "" {
		t.Errorf("未传 mimetype 时 FileHit.Mimetype 应空: %+v", res.Files)
	}
}

// --- baloosearch 解析:KF6 优先 ---

func TestResolveBalooSearch_Baloosearch6Preferred(t *testing.T) {
	// PATH 含 baloosearch6 + baloosearch,期望命中 baloosearch6(KF6 优先)。
	dir := t.TempDir()
	for _, name := range balooSearchCandidates {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	got := resolveBalooSearch()
	want := filepath.Join(dir, "baloosearch6")
	if got != want {
		t.Errorf("应命中 baloosearch6, got %q want %q", got, want)
	}
}

func TestResolveBalooSearch_BaloosearchFallback(t *testing.T) {
	// PATH 仅 baloosearch(KF5 / 旧 Plasma),回落到它。
	dir := t.TempDir()
	p := filepath.Join(dir, "baloosearch")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	got := resolveBalooSearch()
	if got != p {
		t.Errorf("应命中 baloosearch, got %q want %q", got, p)
	}
}

func TestResolveBalooSearch_DefaultPathFallback(t *testing.T) {
	// PATH 空,走 defaultBalooSearchPaths 候选;若无候选存在,返首个绝对路径
	//(让后续 translateBalooError 走 missing binary 路径,不 panic)。
	t.Setenv("PATH", "")
	got := resolveBalooSearch()
	if got != defaultBalooSearchPaths[0] && got != defaultBalooSearchPaths[1] {
		t.Errorf("默认路径应候选集内, got %q", got)
	}
}

// --- reindex L1 deferred ---

func TestReindex_L1Deferred(t *testing.T) {
	svc, fr := newFakeService()
	res, err := svc.Reindex(context.Background(), ReindexArgs{Dir: "/home/u"})
	if err != nil {
		t.Fatalf("Reindex: %v", err)
	}
	if res.Started {
		t.Errorf("Started 应 false")
	}
	if res.Dir != "/home/u" {
		t.Errorf("dir 应回显, got %q", res.Dir)
	}
	if !strings.Contains(res.Note, "L1 deferred") {
		t.Errorf("note = %q", res.Note)
	}
	if fr.calls != 0 {
		t.Errorf("reindex 不应 fork baloosearch: calls=%d", fr.calls)
	}
}

func TestReindex_BalooUnavailableNote(t *testing.T) {
	svc, _ := newFakeService()
	svc.connect = func() (balooDBus, error) { return nil, errors.New("no bus") }
	res, err := svc.Reindex(context.Background(), ReindexArgs{})
	if err != nil {
		t.Fatalf("Reindex: %v", err)
	}
	if !strings.Contains(res.Note, "D-Bus session bus 不可达") {
		t.Errorf("connect 失败 note 应含 D-Bus 不可达, got %q", res.Note)
	}
}

func TestReindex_NameHasOwnerErrorNote(t *testing.T) {
	// NameHasOwner 失败 ≠ connect 失败:note 应说"属性/名字查询失败",不是
	// "D-Bus 不可达"。
	svc, _ := newFakeService()
	svc.connect = func() (balooDBus, error) {
		return &fakeDBus{owned: false, ownedErr: errors.New("query failed")}, nil
	}
	res, err := svc.Reindex(context.Background(), ReindexArgs{})
	if err != nil {
		t.Fatalf("Reindex: %v", err)
	}
	if strings.Contains(res.Note, "D-Bus session bus 不可达") {
		t.Errorf("NameHasOwner 失败不应误称 D-Bus 不可达: %q", res.Note)
	}
	if !strings.Contains(res.Note, "注册查询失败") {
		t.Errorf("note 应含'注册查询失败': %q", res.Note)
	}
}

func TestReindex_NotOwnedNote(t *testing.T) {
	svc, _ := newFakeService()
	svc.connect = func() (balooDBus, error) { return &fakeDBus{owned: false}, nil }
	res, _ := svc.Reindex(context.Background(), ReindexArgs{})
	if !strings.Contains(res.Note, "org.kde.baloo 未注册") {
		t.Errorf("note 应含未注册: %q", res.Note)
	}
}

func TestReindex_InvalidDir(t *testing.T) {
	svc, _ := newFakeService()
	if _, err := svc.Reindex(context.Background(), ReindexArgs{Dir: "/a/../b"}); err == nil {
		t.Errorf("非法 dir 应报错")
	}
}

func int64Ptr(v int64) *int64 { return &v }

// --- 真 fork 回归:stderr 必须在 Start() 之前接管 ---

// TestExecHelper_RealStderrCaptured 真 fork 一个写 stderr 的 shell,断言
// execError.Stderr 捕获到真内容(Stderr 挪到 Start() 之后即 FAIL)。
func TestExecHelper_RealStderrCaptured(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-baloosearch")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho 'Cannot connect to daemon' >&2\nexit 2\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := execHelper(context.Background(), script, nil, func([]byte) bool { return true })
	if err == nil {
		t.Fatal("应返回错误")
	}
	var ee *execError
	if !errors.As(err, &ee) {
		t.Fatalf("err 类型 = %T", err)
	}
	if !strings.Contains(ee.Stderr, "Cannot connect to daemon") {
		t.Errorf("Stderr 未捕获真内容: %q (err=%v)", ee.Stderr, err)
	}
	if ee.Code != 2 {
		t.Errorf("code = %d, want 2", ee.Code)
	}
}

// TestExecHelper_RealMissingBinary 真 fork 不存在的 binary → isMissingBinary。
func TestExecHelper_RealMissingBinary(t *testing.T) {
	err := execHelper(context.Background(), "/nonexistent/baloosearch-xyz", nil, func([]byte) bool { return true })
	if !isMissingBinary(err) {
		t.Errorf("应判 missing binary: %v", err)
	}
}

// TestExecHelper_RealCtxTimeout 真 fork /bin/sleep + 短 ctx → ctx 取消即早停。
// 直用 /bin/sleep(非 sh -c 包装)确保被 kill 的就是持有 stdout 的进程。
func TestExecHelper_RealCtxTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := execHelper(ctx, "/bin/sleep", nil, func([]byte) bool { return true }, "5")
	if err == nil {
		t.Fatal("超时应返回错误")
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("ctx 超时未早停: %v", time.Since(start))
	}
}
