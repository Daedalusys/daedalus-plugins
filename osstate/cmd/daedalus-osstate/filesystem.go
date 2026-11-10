package main

import (
	"fmt"
	"strings"
	"unicode"
)

// mountEntry 是 mountinfo 里一条挂载的三元组事实。
type mountEntry struct {
	Mountpoint string `json:"mountpoint"`
	Device     string `json:"device"`
	Fstype     string `json:"fstype"`
}

// mountInfoPath 是挂载表的唯一来源。刻意不读 /proc/mounts:mountinfo 用 " - "
// 分隔挂载选项与文件系统信息,fstype/source 的位置由结构决定,不必按字段序号
// 猜;而 /proc/mounts 的 device 列在 bind mount 下给的是 none、/dev/root 之类,
// 语义更差。
const mountInfoPath = "/proc/self/mountinfo"

// mountInfoSeparator 是 mountinfo 行内挂载选项与文件系统信息的经典分隔符。
const mountInfoSeparator = "-"

// filesystemPayload 组装 filesystem_info 回包:按请求顺序返回挂载事实,
// 任一挂载点未命中即整包给 error(不返回半份结果,下游无从误读成"该挂载点不存在")。
func filesystemPayload(source []byte, requested []string) map[string]any {
	if len(requested) == 0 {
		requested = []string{"/"}
	}
	for _, mp := range requested {
		if msg := validateMountpoint(mp); msg != "" {
			return map[string]any{"error": msg}
		}
	}

	// 同一挂载点可被多次挂载(mountinfo 按挂载顺序追加,后出现者即当前可见挂载),
	// 故索引直接覆盖,天然实现"取最后一条"。
	latest := map[string]mountEntry{}
	for _, e := range parseMountInfo(source) {
		latest[e.Mountpoint] = e
	}

	found := make([]mountEntry, 0, len(requested))
	var missing []string
	for _, mp := range requested {
		e, ok := latest[mp]
		if !ok {
			missing = append(missing, mp)
			continue
		}
		found = append(found, e)
	}
	if len(missing) > 0 {
		return map[string]any{"error": "未知挂载点: " + strings.Join(missing, " ")}
	}
	return map[string]any{"mountpoints": found}
}

// validateMountpoint 在查询前拒绝空串与控制字符;拒绝发生在任何路径拼接之前。
func validateMountpoint(mp string) string {
	if mp == "" {
		return "挂载点不能为空"
	}
	if strings.IndexFunc(mp, unicode.IsControl) >= 0 {
		return fmt.Sprintf("非法挂载点: %q", mp)
	}
	return ""
}

// parseMountInfo 解析 mountinfo 文本。每行形如
//
//	id parent major:minor root mountpoint options [optional...] - fstype source superopts
//
// 缺 " - " 分隔或字段数不足的畸形行跳过而不是报错:单行异常不该让整张表不可用。
func parseMountInfo(data []byte) []mountEntry {
	entries := []mountEntry{}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		sep := -1
		for i, f := range fields {
			if f == mountInfoSeparator {
				sep = i
				break
			}
		}
		// 分隔符前至少要有 id/parent/maj:min/root/mountpoint 五个字段,
		// 分隔符后至少要有 fstype/source 两个字段。
		if sep < 5 || len(fields) < sep+3 {
			continue
		}
		entries = append(entries, mountEntry{
			Mountpoint: unescapeMountField(fields[4]),
			Fstype:     unescapeMountField(fields[sep+1]),
			Device:     unescapeMountField(fields[sep+2]),
		})
	}
	return entries
}

// unescapeMountField 还原 mountinfo 的 POSIX octal 转义(空格 \040、tab \011、
// 换行 \012、反斜杠 \134 等);其余反斜杠序列无法解释,原样保留。
func unescapeMountField(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && isOctal(s[i+1]) && isOctal(s[i+2]) && isOctal(s[i+3]) {
			b.WriteByte((s[i+1]-'0')<<6 | (s[i+2]-'0')<<3 | (s[i+3] - '0'))
			i += 3
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isOctal(c byte) bool { return c >= '0' && c <= '7' }
