package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Daedalusys/daedalus-sdk/pathguard"
)

// withAllowed 临时替换白名单;写校验读的是包级 AllowedDirs。
func withAllowed(t *testing.T, dirs ...string) {
	t.Helper()
	orig := append([]string(nil), pathguard.AllowedDirs...)
	pathguard.WithAllowedDirs(dirs)
	t.Cleanup(func() { pathguard.WithAllowedDirs(orig) })
}

// 白名单放宽到含 /etc 后,写 /etc 下的敏感文件仍必须被拒 —— 且被拒语义是
// "denied"(不是 error、不是静默成功)。
func TestWriteFile_DeniedBySecondTierGuard(t *testing.T) {
	withAllowed(t, "/tmp", "/etc", "/proc")

	_, outcome, err := writeFileResult(writeFileIn{
		Path:    "/etc/sudoers.d/probe-guard",
		Content: "probe",
	})
	if err == nil {
		t.Fatal("放宽白名单后写 /etc/sudoers.d/* 必须被拒")
	}
	if !strings.Contains(err.Error(), "write denied") {
		t.Fatalf("错误信息应来自二档校验(含 'write denied'), got %v", err)
	}
	if outcome != "denied" {
		t.Fatalf("被拒语义应为 denied, got %q", outcome)
	}
}

// 正常目标不能被收紧:白名单内的普通文件仍须写成功。
func TestWriteFile_AllowsNormalTarget(t *testing.T) {
	tmp := t.TempDir()
	withAllowed(t, tmp)
	target := filepath.Join(tmp, "ok.txt")

	if _, outcome, err := writeFileResult(writeFileIn{Path: target, Content: "hi"}); err != nil {
		t.Fatalf("白名单内普通写应成功, got outcome=%q err=%v", outcome, err)
	}
	b, rerr := os.ReadFile(target)
	if rerr != nil || string(b) != "hi" {
		t.Fatalf("文件内容应为 hi, got %q (err=%v)", b, rerr)
	}
}

// move 的两端都要过二档:把敏感文件"移出"也是写语义(读出 + 删除)。
func TestMoveFile_DeniedWhenSrcIsSensitive(t *testing.T) {
	tmp := t.TempDir()
	withAllowed(t, tmp, "/etc")
	dst := filepath.Join(tmp, "stolen")
	if _, outcome, err := moveFileResult(moveFileIn{Src: "/etc/shadow", Dst: dst}); err == nil {
		t.Fatal("把 /etc/shadow 移出必须被拒")
	} else if !strings.Contains(err.Error(), "write denied") {
		t.Fatalf("拒绝应来自二档校验(含 'write denied'), got %v", err)
	} else if outcome != "denied" {
		t.Fatalf("被拒语义应为 denied, got %q", outcome)
	}
}

// move 的目标端同样要过二档。
func TestMoveFile_DeniedWhenDstIsSensitive(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "a.txt")
	if err := os.WriteFile(src, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	withAllowed(t, tmp, "/etc")
	if _, outcome, err := moveFileResult(moveFileIn{Src: src, Dst: "/etc/sudoers.d/x"}); err == nil {
		t.Fatal("把文件移到 /etc/sudoers.d 下必须被拒")
	} else if !strings.Contains(err.Error(), "write denied") {
		t.Fatalf("拒绝应来自二档校验(含 'write denied'), got %v", err)
	} else if outcome != "denied" {
		t.Fatalf("被拒语义应为 denied, got %q", outcome)
	}
}

// 正常 move 仍须成功(防止收紧打坏主路径)。
func TestMoveFile_AllowsNormalMove(t *testing.T) {
	tmp := t.TempDir()
	withAllowed(t, tmp)
	src := filepath.Join(tmp, "a.txt")
	dst := filepath.Join(tmp, "b.txt")
	if err := os.WriteFile(src, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, outcome, err := moveFileResult(moveFileIn{Src: src, Dst: dst}); err != nil {
		t.Fatalf("白名单内 move 应成功, got outcome=%q err=%v", outcome, err)
	}
	if _, err := os.Stat(dst); err != nil {
		t.Fatalf("目标应存在: %v", err)
	}
}

// move 的源端必须真实存在:二档强制完整 realpath,不存在的源不再走到 rename
// 的 ENONT 报错,而是被写成"写必须知道落点"的拒绝。这条契约变化有意为之,
// 挡住"源端可能是指向白名单外的悬空链接"这类猜测。
func TestMoveFile_SrcNonexistentReportsWriteDenied(t *testing.T) {
	tmp := t.TempDir()
	withAllowed(t, tmp)
	missing := filepath.Join(tmp, "never-existed")
	_, outcome, err := moveFileResult(moveFileIn{Src: missing, Dst: filepath.Join(tmp, "dst")})
	if err == nil {
		t.Fatal("不存在的 src 必须被拒")
	}
	if !strings.Contains(err.Error(), "write denied: cannot resolve realpath") {
		t.Fatalf("报错契约应为 write denied: cannot resolve realpath, got %v", err)
	}
	if outcome != "denied" {
		t.Fatalf("被拒语义应为 denied, got %q", outcome)
	}
}
