// 五个 proc 工具的注册:名称、中文描述、手写 jsonschema 与只读注解。
// 工具名与 manifest.tools 逐字一致(76 脚本构建期交叉核对 manifest ↔
// 二进制 tools/list,漂移即构建失败)。
package main

import (
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Daedalusys/daedalus-sdk/version"
)

func newServer() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    serverName,
		Version: version.Version,
	}, nil)

	// go-sdk 的 DestructiveHint/OpenWorldHint 为 *bool 且 SDK 未导出取址
	// 助手,按实证形态用局部变量取址(只读侦察必然非破坏性、封闭世界)。
	nonDestructive := false
	closedWorld := false
	annotations := &mcp.ToolAnnotations{
		ReadOnlyHint:    true,
		DestructiveHint: &nonDestructive,
		IdempotentHint:  true,
		OpenWorldHint:   &closedWorld,
	}

	mcp.AddTool(server, &mcp.Tool{
		Name:        "proc_list",
		Description: "只读列出全部进程的精简快照(pid/name/ppid/state/cmdline/cpu_percent/memory_rss_bytes)。\n\n双采样(100ms 窗口)计算 CPU%,jiffies 累计值同列给出;内核线程 cmdline 为空属常态。\n\n参数:\n    filter: 可选,子串匹配 comm 或完整命令行(区分大小写,1-128 字符)。\n\n返回:\n    {proc_root, filter, processes[], total, skipped_unreadable}。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"filter": {Type: "string", Description: "comm/命令行的子串过滤(等值包含,非正则),省略则列全部。"},
			},
		},
		Annotations: annotations,
	}, handleProcList)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "proc_tree",
		Description: "只读构建以指定进程为根的进程树(嵌套 children,按 pid 升序)。\n\nppid 环等异常拓扑在 visited 防护下剪枝;根进程不存在则报错。\n\n参数:\n    root_pid: 可选,根 PID(正整数),缺省 1。\n\n返回:\n    {proc_root, root_pid, tree{pid,name,children[]}, total_processes}。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"root_pid": {Type: "integer", Description: "进程树根 PID(缺省 1 = init)。"},
			},
		},
		Annotations: annotations,
	}, handleProcTree)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "proc_fds",
		Description: "只读列出进程打开的文件描述符(kind=file/socket/pipe/other,target 为链接目标,pos 为 fdinfo 偏移)。\n\nsocket/pipe 显示 socket:[ino]/pipe:[ino] 形态;anon_inode 等归入 other。\n\n参数:\n    pid: 必填,正整数进程 PID。\n    kinds: 可选,取值子集 [file, socket, pipe, other];省略 = 全收。\n\n返回:\n    {proc_root, pid, kinds, entries[], total, unreadable}。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"pid": {Type: "integer", Description: "目标进程 PID(正整数)。"},
				"kinds": {Type: "array", Description: "类别白名单(省略 = 全部类别),如 [\"socket\"] 只看网络 fd。",
					Items: &jsonschema.Schema{Type: "string", Enum: []any{"file", "socket", "pipe", "other"}}},
			},
			Required: []string{"pid"},
		},
		Annotations: annotations,
	}, handleProcFds)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "proc_listen",
		Description: "只读列出监听端口并反查归属进程(直读 /proc/net/{tcp,tcp6,udp,udp6},零 exec 不用 ss/netstat)。\n\ntcp 取 LISTEN 态,udp 取远端全零的未连接绑定;inode→pid 反查受权限限制,反查不到列入 unowned_sockets。\n\n参数:\n    port: 可选,1-65535 端口过滤。\n    proto: 可选,tcp(缺省)或 udp。\n\n返回:\n    {proc_root, proto, port, listeners[{proto,local_address,local_port,state,inode,pids,names}], scanned_sockets, unowned_sockets}。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"port":  {Type: "integer", Description: "监听端口过滤(省略 = 全部端口)。"},
				"proto": {Type: "string", Description: "协议,缺省 tcp。", Enum: []any{"tcp", "udp"}},
			},
		},
		Annotations: annotations,
	}, handleProcListen)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "proc_cgroup",
		Description: "只读定位进程所属 systemd 单元(解析 /proc/<pid>/cgroup)。\n\n返回控制器→cgroup 路径全量 map 与最内层单元名(v2 取 0:: 行末段,v1 取 systemd 行;\\xNN 转义还原)。容器/用户态进程无匹配单元时 unit 为空串。\n\n参数:\n    pid: 必填,正整数进程 PID。\n\n返回:\n    {proc_root, pid, unit, cgroups{controller:path}}。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"pid": {Type: "integer", Description: "目标进程 PID(正整数)。"},
			},
			Required: []string{"pid"},
		},
		Annotations: annotations,
	}, handleProcCgroup)

	return server
}
