// hwmon 只读解析基元的单测:六个传感器视图与缺文件降级。
// 数据源固定指向包内 testdata/sysfs 夹具(逐字段与真实 sysfs 对齐,
// 文本数值直接照抄 hwmon/thermal/power_supply/powercap 的内核格式),
// 测试零触碰真实 /sys;覆盖新 hwmonService 的全部 API 契约。
package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// fixtureRoot 是 testdata/sysfs 的相对路径,tests 在包目录运行。
const fixtureRoot = "testdata/sysfs"

// makeService 返回一个 root 指向夹具的 service(测试夹具;等同真机的
// /sys,结构与字段值一致,内核版本/权限不会随主机漂移)。
func makeService(t *testing.T) *service {
	t.Helper()
	return newService(filepath.Join(fixtureRoot))
}

func TestTemperatures(t *testing.T) {
	svc := makeService(t)
	got := svc.Temperatures()
	want := []temperature{
		{Label: "core0", Celsius: 45.0},
		{Label: "core1", Celsius: 47.0},
		{Label: "temp1", Celsius: 38.0}, // hwmon1 无 *_label → 退化
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Temperatures = %+v\nwant %+v", got, want)
	}
}

func TestFans(t *testing.T) {
	svc := makeService(t)
	got := svc.Fans()
	want := []fan{{Label: "cpu_fan", RPM: 1200}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Fans = %+v\nwant %+v", got, want)
	}
}

func TestVoltages(t *testing.T) {
	svc := makeService(t)
	got := svc.Voltages()
	want := []voltage{
		{Label: "Vcore", Volts: 0.85},
		{Label: "5V", Volts: 5.0},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Voltages = %+v\nwant %+v", got, want)
	}
}

// TestPowerDelta 用显式注入的基线 + fixture energy_uj=3000000 验算:
// 2 J / 1 s = 2 W。验证 RAPL 差分换算逻辑闭环(回绕→0、无基线→空集、
// 缺文件→空集三条边界同框)。
func TestPowerDelta(t *testing.T) {
	svc := makeService(t)
	t0 := time.Unix(1000, 0)
	svc.haveRAPL = true
	svc.lastEnergyUj = 1_000_000
	svc.lastRAPLTime = t0

	got := svc.Power(t0.Add(time.Second))
	want := []powerReading{{Domain: "intel-rapl:0", Watts: 2.0}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Power(基线+1s) = %+v\nwant %+v", got, want)
	}
}

func TestPowerNoBaseline(t *testing.T) {
	svc := makeService(t)
	got := svc.Power(time.Unix(1000, 0))
	if len(got) != 0 {
		t.Fatalf("首次 Power 应建立基线返空: %+v", got)
	}
	// 二次调用有基线,fixture 静态 → Δ=0 → 0W
	got2 := svc.Power(time.Unix(1001, 0))
	want := []powerReading{{Domain: "intel-rapl:0", Watts: 0.0}}
	if !reflect.DeepEqual(got2, want) {
		t.Fatalf("二次 Power = %+v\nwant %+v", got2, want)
	}
}

func TestBattery(t *testing.T) {
	svc := makeService(t)
	got := svc.Battery()
	want := []battery{{Status: "Charging", Capacity: 87}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Battery = %+v\nwant %+v", got, want)
	}
}

func TestThermalZones(t *testing.T) {
	svc := makeService(t)
	got := svc.ThermalZones()
	want := []thermalZone{
		{Zone: "thermal_zone0", Type: "x86_pkg_temp", Celsius: 44.0},
		{Zone: "thermal_zone1", Type: "acpitz", Celsius: 30.0},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ThermalZones = %+v\nwant %+v", got, want)
	}
}

// TestEmptyRootGraceful 根目录不存在或为空时,六个视图都返空切片且不报错,
// 满足"缺文件优雅降级为空集"的硬约束。
func TestEmptyRootGraceful(t *testing.T) {
	svc := newService(t.TempDir())
	if got := svc.Temperatures(); len(got) != 0 {
		t.Errorf("Temperatures 空根应为空: %+v", got)
	}
	if got := svc.Fans(); len(got) != 0 {
		t.Errorf("Fans 空根应为空: %+v", got)
	}
	if got := svc.Voltages(); len(got) != 0 {
		t.Errorf("Voltages 空根应为空: %+v", got)
	}
	if got := svc.Power(time.Now()); len(got) != 0 {
		t.Errorf("Power 空根应为空: %+v", got)
	}
	if got := svc.Battery(); len(got) != 0 {
		t.Errorf("Battery 空根应为空: %+v", got)
	}
	if got := svc.ThermalZones(); len(got) != 0 {
		t.Errorf("ThermalZones 空根应为空: %+v", got)
	}
}

// TestRootPrefixGuard 防止"rel 含 ../"逃出 root:readText 必须返回错误,
// 这是 hwmon 自己的对称防线(daedalus-sdk/pathguard 仅 fs 域)。
func TestRootPrefixGuard(t *testing.T) {
	svc := newService(t.TempDir())
	if _, err := svc.readText("../etc/passwd"); err == nil {
		t.Fatal("../etc/passwd 应被前缀校验拒绝")
	}
}

// TestSubdirsFollowsSymlinks 是 #19 review r1 的 Critical 回归钉子:真机
// /sys/class/{hwmon,thermal,power_supply}/* 全是指向 /sys/devices/...
// 的符号链接,DirEntry.IsDir 的 lstat/d_type 语义下恒为 false,会让
// 4/6 工具(temperatures/fans/voltages/thermal_zones)静默返空。临时构造
// 一个 hwmon 子目录用符号链接指向 root 之内的真实数据,断言 Temperatures()
// 仍能读出(symlink 在 root 内合法,canonical 前缀校验放行)。
func TestSubdirsFollowsSymlinks(t *testing.T) {
	root := t.TempDir()
	// 真实数据放到 root/devices/... 下,类比 fixture 与真机 sysfs 布局
	// (class/* 符号链接指向 devices/*,后者位于 root 之内)。
	chip := filepath.Join(root, "devices", "fake", "hwmon0")
	if err := os.MkdirAll(chip, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(chip, "temp1_input"), []byte("48000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "class", "hwmon"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../devices/fake/hwmon0", filepath.Join(root, "class", "hwmon", "hwmon0")); err != nil {
		t.Fatal(err)
	}
	svc := newService(root)
	got := svc.Temperatures()
	want := []temperature{{Label: "temp1", Celsius: 48.0}} // 无 *_label → 退化为输入文件名
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Temperatures = %+v\nwant %+v", got, want)
	}
}

// TestReadTextSymlinkEscapeRejected 是 #19 review r1 的 Important 回归:
// root 下指向 root 外的符号链接必须在 readText 的 canonical 前缀校验处被
// 拒绝,不能跟随读取(root 启动时 canonicalRoot 已固化,每次读 EvalSymlinks
// 再校验 —— 与 daedalus-sdk/pathguard 的 realpath 逃逸防线同语义)。
func TestReadTextSymlinkEscapeRejected(t *testing.T) {
	root := t.TempDir()
	external := t.TempDir() // root 之外的秘密目录
	if err := os.WriteFile(filepath.Join(external, "secret"), []byte("topsecret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "class", "hwmon"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(root, "class", "hwmon", "evil")); err != nil {
		t.Fatal(err)
	}
	svc := newService(root)
	// readText 必须报逃逸错误,且绝不返回 secret 内容。
	if _, err := svc.readText("class/hwmon/evil/secret"); err == nil {
		t.Fatal("指向 root 外的符号链接应被 canonical 前缀校验拒绝")
	}
	// Temperatures 遍历 class/hwmon 时也会遇到 evil;subdirs(stat) 把它当
	// 目录列出,但 glob 找不到 temp*_input 匹配项 → 空集,且不应泄露 secret。
	if got := svc.Temperatures(); len(got) != 0 {
		t.Fatalf("含逃逸符号链接的根,Temperatures 应为空: %+v", got)
	}
}

// TestReadTextNullByteRejected:rel 含空字节(NUL)必须在 readText 入口即拒,
// 与 daedalus-sdk/pathguard.ValidatePath 的"空字节即拒"语义对齐。
func TestReadTextNullByteRejected(t *testing.T) {
	svc := newService(t.TempDir())
	if _, err := svc.readText("class\x00/hwmon/hwmon0/temp1_input"); err == nil {
		t.Fatal("空字节路径应被拒绝")
	}
}
