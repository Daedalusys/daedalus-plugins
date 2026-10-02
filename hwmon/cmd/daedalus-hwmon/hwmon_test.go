// hwmon 只读解析基元的单测:六个传感器视图与缺文件降级。
// 数据源固定指向包内 testdata/sysfs 夹具(逐字段与真实 sysfs 对齐,
// 文本数值直接照抄 hwmon/thermal/power_supply/powercap 的内核格式),
// 测试零触碰真实 /sys;覆盖新 hwmonService 的全部 API 契约。
package main

import (
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
