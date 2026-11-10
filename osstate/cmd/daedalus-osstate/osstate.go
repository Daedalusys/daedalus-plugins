package main

import "strings"

// distroInfo 是 os-release 里我们关心的三个字段。
type distroInfo struct {
	ID         string `json:"id"`
	VersionID  string `json:"version_id"`
	PrettyName string `json:"pretty_name"`
}

// packageManager 是命中的包管理器及其二进制绝对路径。
type packageManager struct {
	Name   string `json:"name"`
	Binary string `json:"binary"`
}

// packageManagerCandidates 是包管理器候选表,顺序即优先级:同一宿主可能同时
// 存在多个包管理器(迁移期并存的 dnf 与 yum 是常见形态),固定顺序让结果稳定。
//
// 这些路径只做 stat 存在性探测,从不打开文件内容,因此不进 manifest 的
// permissions.read —— read 只声明内容会被读取的路径。
var packageManagerCandidates = []struct {
	Name  string
	Paths []string
}{
	{Name: "apt", Paths: []string{"/usr/bin/apt-get", "/bin/apt-get"}},
	{Name: "dnf", Paths: []string{"/usr/bin/dnf", "/usr/sbin/dnf", "/bin/dnf", "/sbin/dnf"}},
	{Name: "yum", Paths: []string{"/usr/bin/yum", "/usr/sbin/yum", "/bin/yum", "/sbin/yum"}},
	{Name: "zypper", Paths: []string{"/usr/bin/zypper", "/usr/sbin/zypper"}},
	{Name: "apk", Paths: []string{"/usr/sbin/apk", "/usr/bin/apk", "/sbin/apk", "/bin/apk"}},
}

// initSystemdPath 是 systemd 的运行期标志目录:目录存在即 systemd 在跑。
const initSystemdPath = "/run/systemd/system"

// detectPackageManager 按候选表顺序返回第一个命中的包管理器;全不命中时给
// unknown —— 证据不足时写 unknown 比猜一个更有用。
func detectPackageManager(exists func(string) bool) packageManager {
	for _, cand := range packageManagerCandidates {
		for _, p := range cand.Paths {
			if exists(p) {
				return packageManager{Name: cand.Name, Binary: p}
			}
		}
	}
	return packageManager{Name: "unknown"}
}

// detectInit 只认 systemd 一个 init:除 /run/systemd/system 之外一律 unknown。
func detectInit(exists func(string) bool) string {
	if exists(initSystemdPath) {
		return "systemd"
	}
	return "unknown"
}

// osStatePayload 组装 os_state 回包。发行版读不到时(SDK 给的是带 error 键的
// map)整包退化为 error 键,不抛 MCP 错误 —— 与 sysinfo 的 error-key 约定一致。
func osStatePayload(osr map[string]any) map[string]any {
	if errVal, ok := osr["error"]; ok {
		return map[string]any{"error": errVal}
	}
	return map[string]any{
		"distro": distroInfo{
			ID:         osReleaseField(osr, "ID"),
			VersionID:  osReleaseField(osr, "VERSION_ID"),
			PrettyName: osReleaseField(osr, "PRETTY_NAME"),
		},
		"package_manager": detectPackageManager(pathExists),
		"init":            detectInit(pathExists),
	}
}

// osReleaseField 取 os-release 的一个字段;缺失或类型不符时给空串。
func osReleaseField(osr map[string]any, key string) string {
	v, ok := osr[key].(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(v)
}
