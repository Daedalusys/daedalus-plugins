// hwmon 只读基元:枚举 sysfs 下的 hwmon/thermal/power_supply/powercap 传感器
// 文本,换算为工程单位(摄氏度、RPM、伏、瓦)。
//
// 安全边界:零 exec、零写入、零外部依赖(不集成 lm-sensors);全部经
// os.ReadFile。根目录可经 DAEDALUS_HWMON_ROOT 覆盖(测试夹具/容器挂载点),
// 读取前强制根前缀校验,拒绝任何路径逃逸 —— daedalus-sdk/pathguard 的白名单
// 仅覆盖 fs 域(/home /var/log /tmp),故 sysfs 域由本包自行对称守门。
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// EnvHwmonRoot 覆盖 sysfs 根目录(测试夹具与容器挂载点用);非空时优先于
// 默认 /sys,不校验其是否为 /sys —— 前缀逃逸防线以该值为基准。
const EnvHwmonRoot = "DAEDALUS_HWMON_ROOT"

// defaultSysRoot 是生产环境的 sysfs 挂载点。
const defaultSysRoot = "/sys"

// raplEnergyRel 是 Intel RAPL 包级能耗累计计数器(微焦耳);缺失即降级空集。
const raplEnergyRel = "class/powercap/intel-rapl/intel-rapl:0/energy_uj"

// batteryRel 是电池 sysfs 目录;仅读 BAT0,缺失即降级空集。
const batteryRel = "class/power_supply/BAT0"

// service 持有 sysfs 根与 RAPL 差分所需的进程内上一次读数基线。
// 长驻 MCP 进程内跨工具调用持久;mu 保护基线以防并发调用竞争。
type service struct {
	root string
	mu   sync.Mutex

	haveRAPL     bool
	lastEnergyUj float64
	lastRAPLTime time.Time
}

// newService 以给定 sysfs 根装配 service(生产传 resolveRoot())。
func newService(root string) *service {
	return &service{root: root}
}

// resolveRoot 解析 sysfs 根:DAEDALUS_HWMON_ROOT 优先,否则 /sys。
func resolveRoot() string {
	if v := os.Getenv(EnvHwmonRoot); v != "" {
		return v
	}
	return defaultSysRoot
}

// readText 读取 root 下 rel 文本并去除首尾空白。前缀校验是路径逃逸防线:
// rel 含 ".." 时 filepath.Join 会归一化到 root 之外,此处显式拒绝。
func (s *service) readText(rel string) (string, error) {
	root := filepath.Clean(s.root)
	p := filepath.Join(root, rel)
	if p != root && !strings.HasPrefix(p, root+string(os.PathSeparator)) {
		return "", fmt.Errorf("hwmon: 路径逃逸根目录 %q: %q", root, rel)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// subdirs 列出 root 下 rel 目录的直接子目录名(字典序,os.ReadDir 保证);
// 不存在或不可读返回 nil,由调用方按空集处理。
func (s *service) subdirs(rel string) []string {
	entries, err := os.ReadDir(filepath.Join(s.root, rel))
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names
}

// glob 返回 root 下 relDir/pattern 匹配的文件基名(字典序);无匹配返回 nil。
func (s *service) glob(relDir, pattern string) []string {
	matches, err := filepath.Glob(filepath.Join(s.root, relDir, pattern))
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, filepath.Base(m))
	}
	sort.Strings(names)
	return names
}

// sensorLabel 取 <sensor>_label 文本;缺失或无 label 约定时退化为输入文件名
// 去掉 _input(如 temp1),保证每条读数都有可定位的标签。
func (s *service) sensorLabel(relDir, input string) string {
	labelFile := strings.TrimSuffix(input, "_input") + "_label"
	if v, err := s.readText(filepath.Join(relDir, labelFile)); err == nil && v != "" {
		return v
	}
	return strings.TrimSuffix(input, "_input")
}

// milli 读 <relDir>/<input> 的毫单位整数并换算为基本单位(如 mV→V、m°C→°C)。
func (s *service) milli(relDir, input string) (float64, error) {
	raw, err := s.readText(filepath.Join(relDir, input))
	if err != nil {
		return 0, err
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, fmt.Errorf("hwmon: %s 非数值: %q", input, raw)
	}
	return v / 1000, nil
}

// temperature 是 hwmon 温度读数(milli-celsius → 摄氏度)。
type temperature struct {
	Label   string  `json:"label"`
	Celsius float64 `json:"celsius"`
}

// Temperatures 遍历 /sys/class/hwmon/*/temp*_input。
func (s *service) Temperatures() []temperature {
	out := []temperature{}
	for _, chip := range s.subdirs("class/hwmon") {
		base := filepath.Join("class", "hwmon", chip)
		for _, name := range s.glob(base, "temp*_input") {
			c, err := s.milli(base, name)
			if err != nil {
				continue
			}
			out = append(out, temperature{Label: s.sensorLabel(base, name), Celsius: c})
		}
	}
	return out
}

// fan 是 hwmon 风扇转速读数(RPM)。
type fan struct {
	Label string `json:"label"`
	RPM   int    `json:"rpm"`
}

// Fans 遍历 /sys/class/hwmon/*/fan*_input。
func (s *service) Fans() []fan {
	out := []fan{}
	for _, chip := range s.subdirs("class/hwmon") {
		base := filepath.Join("class", "hwmon", chip)
		for _, name := range s.glob(base, "fan*_input") {
			raw, err := s.readText(filepath.Join(base, name))
			if err != nil {
				continue
			}
			rpm, err := strconv.Atoi(raw)
			if err != nil {
				continue
			}
			out = append(out, fan{Label: s.sensorLabel(base, name), RPM: rpm})
		}
	}
	return out
}

// voltage 是 hwmon 电压读数(milli-volt → 伏)。
type voltage struct {
	Label string  `json:"label"`
	Volts float64 `json:"volts"`
}

// Voltages 遍历 /sys/class/hwmon/*/in*_input。
func (s *service) Voltages() []voltage {
	out := []voltage{}
	for _, chip := range s.subdirs("class/hwmon") {
		base := filepath.Join("class", "hwmon", chip)
		for _, name := range s.glob(base, "in*_input") {
			v, err := s.milli(base, name)
			if err != nil {
				continue
			}
			out = append(out, voltage{Label: s.sensorLabel(base, name), Volts: v})
		}
	}
	return out
}

// powerReading 是 RAPL 平均功率读数(瓦);计数值不直接对外暴露。
type powerReading struct {
	Domain string  `json:"domain"`
	Watts  float64 `json:"watts"`
}

// Power 读 RAPL 累计能耗并与上一次读数求差换算平均功率:
// watts = Δenergy_uj / 1e6 / Δt秒。首次调用(无基线)只建立基线并返回空集;
// 缺文件/非数值同样返回空集。计数器回绕或时间倒流时钳制为 0,不产生负功率。
func (s *service) Power(now time.Time) []powerReading {
	raw, err := s.readText(raplEnergyRel)
	if err != nil {
		return []powerReading{}
	}
	energy, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return []powerReading{}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	prevE, prevT, have := s.lastEnergyUj, s.lastRAPLTime, s.haveRAPL
	s.lastEnergyUj, s.lastRAPLTime, s.haveRAPL = energy, now, true
	if !have {
		return []powerReading{}
	}
	dt := now.Sub(prevT).Seconds()
	if dt <= 0 {
		return []powerReading{}
	}
	delta := energy - prevE
	if delta < 0 {
		delta = 0
	}
	return []powerReading{{Domain: "intel-rapl:0", Watts: delta / 1e6 / dt}}
}

// battery 是电池状态读数;部分设备无 capacity(如 UPS)时跳过不报错。
type battery struct {
	Status   string `json:"status"`
	Capacity int    `json:"capacity"`
}

// Battery 只读 /sys/class/power_supply/BAT0/{status,capacity};目录缺失返回空集。
func (s *service) Battery() []battery {
	status, err := s.readText(filepath.Join(batteryRel, "status"))
	if err != nil {
		return []battery{}
	}
	capRaw, err := s.readText(filepath.Join(batteryRel, "capacity"))
	if err != nil {
		return []battery{}
	}
	capacity, err := strconv.Atoi(capRaw)
	if err != nil {
		return []battery{}
	}
	return []battery{{Status: status, Capacity: capacity}}
}

// thermalZone 是 /sys/class/thermal 热区读数(milli-celsius → 摄氏度)。
type thermalZone struct {
	Zone    string  `json:"zone"`
	Type    string  `json:"type"`
	Celsius float64 `json:"celsius"`
}

// ThermalZones 遍历 /sys/class/thermal/thermal_zone*/{temp,type};非
// thermal_zoneN 形式的子目录被跳过,N 非数字同样跳过。
func (s *service) ThermalZones() []thermalZone {
	out := []thermalZone{}
	for _, z := range s.subdirs("class/thermal") {
		idx, ok := strings.CutPrefix(z, "thermal_zone")
		if !ok {
			continue
		}
		if _, err := strconv.Atoi(idx); err != nil {
			continue
		}
		base := filepath.Join("class", "thermal", z)
		c, err := s.milli(base, "temp")
		if err != nil {
			continue
		}
		typ, _ := s.readText(filepath.Join(base, "type"))
		out = append(out, thermalZone{Zone: z, Type: typ, Celsius: c})
	}
	return out
}
