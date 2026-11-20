// tools.go —— 六个工具的注册。工具名与 manifest.tools 逐字一致(76 脚本构建期
// 交叉核对 manifest ↔ 二进制 tools/list,漂移即构建失败)。
//
// 已实现 tx_preview(只读判定)与 tx_apply(按档位执行);其余四个照常注册但返回
// 结构化错误 "unsupported in this phase" —— 工具清单一次定死,客户端看到的契约
// 不随分期变。
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Daedalusys/daedalus-sdk/autonomy"
	"github.com/Daedalusys/daedalus-sdk/version"
)

func newServer(cfg *autonomy.Config) *mcp.Server {
	// 条子用量在进程启动时折叠一次:之后以内存计数判定,不再逐次读 append-only
	// 记账。折叠失败只记 stderr —— 第二档会在消费时 fail-closed,不影响只读工具。
	if err := grantUsage.load(); err != nil {
		fmt.Fprintf(os.Stderr, "%s: 条子用量折叠失败(第二档将 fail-closed): %v\n", serverName, err)
	}
	server := mcp.NewServer(&mcp.Implementation{Name: serverName, Version: version.Version}, nil)

	// go-sdk 的 DestructiveHint/OpenWorldHint 是 *bool 且未导出取址助手,
	// 按家族实证形态用局部变量取址。
	notDestructive := false
	destructive := true
	closedWorld := false
	readOnlyAnnotations := &mcp.ToolAnnotations{
		ReadOnlyHint:    true,
		DestructiveHint: &notDestructive,
		IdempotentHint:  true,
		OpenWorldHint:   &closedWorld,
	}
	// 写面工具如实标成可破坏:即使本阶段是占位实现,注解也是客户端的前置预期。
	writeAnnotations := &mcp.ToolAnnotations{
		ReadOnlyHint:    false,
		DestructiveHint: &destructive,
		IdempotentHint:  false,
		OpenWorldHint:   &closedWorld,
	}

	mcp.AddTool(server, &mcp.Tool{
		Name: "tx_preview",
		Description: "只读预览一次受控变更:判定档位(auto/confirm/human)、命中的规则来源、" +
			"所需作用域、将执行的 argv 与机器自动查的属性快照。零副作用(只读 systemctl 观测,不建事务、不落盘)。\n\n" +
			"参数:\n    kind: 对象类型,本阶段只接 service。\n" +
			"    name: systemd 用户域单元名,必须以 .service 结尾(不做隐式补后缀)。\n" +
			"    desired_state: started/stopped/restarted/enabled/disabled(reload 不在词表内)。\n\n" +
			"返回:\n    {kind,name,desired_state,adapter,scope,tier,reason,required_scope[],argv[],attributes{domain,high_risk,enabled,running,known}}。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				// 不用 enum 把 kind/动作拦在 schema 层:设计要求拒绝面统一返回
				// 结构化原因(unsupported_kind / unsupported_desired_state),而不是
				// 各客户端文案不同的 schema 校验错误。
				"kind":          {Type: "string", Description: "对象类型(本阶段只接 service)。"},
				"name":          {Type: "string", Description: "systemd 用户域单元名,必须以 .service 结尾。"},
				"desired_state": {Type: "string", Description: "期望状态:started/stopped/restarted/enabled/disabled。"},
			},
			Required: []string{"kind", "name", "desired_state"},
		},
		Annotations: readOnlyAnnotations,
	}, func(_ context.Context, _ *mcp.CallToolRequest, in previewIn) (*mcp.CallToolResult, any, error) {
		unit, serr := preparePreview(in)
		if serr != nil {
			return errorResult(serr), nil, nil
		}
		// v1 只寻址 systemd 用户域:service.set 适配器 argv 恒 --user,
		// service-observe 也只看用户域;system 域无从观测,自然落第三档。
		view, serr := buildPreview(in.DesiredState, unit, domainUser, cfg, observeUnit(unit))
		if serr != nil {
			return errorResult(serr), nil, nil
		}
		return jsonResult(view), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "tx_apply",
		Description: "按档位执行一次受控变更:auto 直接走事务(daedalus-tx begin/propose/apply);" +
			"confirm 只认匹配作用域的有效条子(先记账再执行);human 只出一份待办," +
			"人批准同一份 argv 后再调用才执行。\n\n" +
			"幂等:期望状态已在位 ⇒ outcome=noop,不建事务。\n" +
			"注意:同一台机器只应运行一个 daedalus-tx-mcp 实例 —— 条子单次性靠进程内\n" +
			"计数与互斥锁兜住,多实例并发会各记各的账。\n\n" +
			"参数:\n    kind: 对象类型,本阶段只接 service。\n" +
			"    name: systemd 用户域单元名,必须以 .service 结尾(不做隐式补后缀)。\n" +
			"    desired_state: started/stopped/restarted/enabled/disabled。\n" +
			"    grant_id: 可选,第二档所需的条子 id(条子文件在 /run/daedalus/grants)。\n" +
			"    actor: 可选,客户端自报身份,只作审计线索,不参与判定。\n\n" +
			"返回(成功):{tx_id,tier,outcome:\"applied|noop\",grant_id?,pending_id?,approved_by?}。\n" +
			"返回(拒绝):{error,tier,required_scope?,pending_id?,argv?,argv_sha256?,reason,detail?} —— " +
			"error 是机器可读码:grant_required/grant_expired/grant_exhausted/grant_scope_mismatch/" +
			"grant_revoked/grant_unauthorized/grant_invalid/grant_usage_failed/" +
			"human_approval_required/approval_untrusted/approval_mismatch/pending_write_failed/tx_failed。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"kind":          {Type: "string", Description: "对象类型(本阶段只接 service)。"},
				"name":          {Type: "string", Description: "systemd 用户域单元名,必须以 .service 结尾。"},
				"desired_state": {Type: "string", Description: "期望状态:started/stopped/restarted/enabled/disabled。"},
				"grant_id":      {Type: "string", Description: "授权条子 id(第二档)。"},
				"actor":         {Type: "string", Description: "客户端自报身份,仅作审计线索。"},
			},
			Required: []string{"kind", "name", "desired_state"},
		},
		Annotations: writeAnnotations,
	}, func(_ context.Context, _ *mcp.CallToolRequest, in applyIn) (*mcp.CallToolResult, any, error) {
		view, rej := txApply(cfg, in)
		if rej != nil {
			return rejectionResult(rej), nil, nil
		}
		return jsonResult(view), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "tx_status",
		Description: "按 tx_id 读事务 journal(本阶段未实现,返回 {\"error\":\"unsupported in this phase\"})。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"tx_id": {Type: "string", Description: "事务 ID。"},
			},
			Required: []string{"tx_id"},
		},
		Annotations: readOnlyAnnotations,
	}, unsupportedInPhase)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "tx_list",
		Description: "列出最近的事务(本阶段未实现,返回 {\"error\":\"unsupported in this phase\"})。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"limit": {Type: "integer", Description: "最多返回条数。"},
			},
		},
		Annotations: readOnlyAnnotations,
	}, unsupportedInPhase)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "tx_pending",
		Description: "列出待人批准的动作(本阶段未实现,返回 {\"error\":\"unsupported in this phase\"})。",
		InputSchema: &jsonschema.Schema{Type: "object"},
		Annotations: readOnlyAnnotations,
	}, unsupportedInPhase)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "tx_rollback",
		Description: "按 tx_id 回滚(本阶段未实现,返回 {\"error\":\"unsupported in this phase\"})。回滚同样走档位判定,不是免票通道。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"tx_id": {Type: "string", Description: "事务 ID。"},
			},
			Required: []string{"tx_id"},
		},
		Annotations: writeAnnotations,
	}, unsupportedInPhase)

	return server
}

// unsupportedInPhase 是占位工具的统一应答。结构化 JSON + isError:客户端能按
// error 字段分支,不会把它误当成"执行成功但没有输出"。
func unsupportedInPhase(_ context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, any, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: `{"error":"unsupported in this phase"}`}},
		IsError: true,
	}, nil, nil
}

// rejectionResult 把结构化拒绝写成 isError 结果:没有执行就是失败,不能让客户端
// 把"出了个待办/被拒"读成成功。
func rejectionResult(rej *applyRejection) *mcp.CallToolResult {
	res := jsonResult(rej)
	res.IsError = true
	return res
}
