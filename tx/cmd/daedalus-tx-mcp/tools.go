// tools.go —— 六个工具的注册。工具名与 manifest.tools 逐字一致(76 脚本构建期
// 交叉核对 manifest ↔ 二进制 tools/list,漂移即构建失败)。
//
// tx_preview / tx_apply 是判定与执行面,tx_status / tx_list / tx_pending 是只读面,
// tx_rollback 是"重新判定后再执行"的写面 —— 六个工具一次定死,客户端看到的契约
// 不随实现进度变。
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
		Name: "tx_status",
		Description: "按 tx_id 读一条事务 journal 的核心字段(只读):state 是 proposed/applying/applied/" +
			"rolled_back/failed 之一,steps 是逐步的适配器执行记录。\n\n" +
			"参数:\n    tx_id: 16 位小写十六进制事务 ID。\n\n" +
			"返回:{tx_id,state,steps[]}。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"tx_id": {Type: "string", Description: "16 位小写十六进制事务 ID。"},
			},
			Required: []string{"tx_id"},
		},
		Annotations: readOnlyAnnotations,
	}, func(_ context.Context, _ *mcp.CallToolRequest, in statusIn) (*mcp.CallToolResult, any, error) {
		view, serr := txStatus(in)
		if serr != nil {
			return errorResult(serr), nil, nil
		}
		return jsonResult(view), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "tx_list",
		Description: "列出最近的事务(只读):直接枚举事务 journal,按时间倒序;limit 省略或为 0 表示全部。\n\n" +
			"参数:\n    limit: 可选,最多返回条数(正整数)。\n\n" +
			"返回:{items:[{tx_id,state,created_at}]}。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"limit": {Type: "integer", Description: "最多返回条数;省略或 0 表示全部。"},
			},
		},
		Annotations: readOnlyAnnotations,
	}, func(_ context.Context, _ *mcp.CallToolRequest, in listIn) (*mcp.CallToolResult, any, error) {
		view, serr := txList(in)
		if serr != nil {
			return errorResult(serr), nil, nil
		}
		return jsonResult(view), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "tx_pending",
		Description: "列出等人批准的动作(只读,绝不写待办目录):每条含将执行的 argv 与 argv_sha256," +
			"人把指纹抄给 daedalus-tx approve --expect-sha256 才算批准了同一份命令。\n\n" +
			"返回:{items:[{id,kind,name,desired_state,scope,argv[],argv_sha256,reason,created_at,expires_at}]}。",
		InputSchema: &jsonschema.Schema{Type: "object"},
		Annotations: readOnlyAnnotations,
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		view, serr := txPending()
		if serr != nil {
			return errorResult(serr), nil, nil
		}
		return jsonResult(view), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "tx_rollback",
		Description: "按 tx_id 回滚(写面)。回滚同样走档位判定,不是免票通道:从 journal 的每一步" +
			"重建目标作用域并重新认定属性,任一步落在第三档就整笔拒绝,且不调用 rollback。" +
			"未知适配器或参数无法重建目标时同样 fail-closed。\n\n" +
			"参数:\n    tx_id: 16 位小写十六进制事务 ID。\n\n" +
			"返回(成功):{tx_id,outcome:\"rolled_back\",tier}。\n" +
			"返回(拒绝):{error,tx_id,outcome:\"denied\",tier?,reason,detail?} —— error 是机器可读码:" +
			"invalid_tx_id/tx_failed/nothing_to_rollback/unsupported_rollback_target/rollback_denied。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"tx_id": {Type: "string", Description: "16 位小写十六进制事务 ID。"},
			},
			Required: []string{"tx_id"},
		},
		Annotations: writeAnnotations,
	}, func(_ context.Context, _ *mcp.CallToolRequest, in rollbackIn) (*mcp.CallToolResult, any, error) {
		view, rej := txRollback(cfg, in)
		if rej != nil {
			return rollbackResult(rej), nil, nil
		}
		return jsonResult(view), nil, nil
	})

	return server
}

// rollbackResult 把回滚拒绝写成 isError 结果:没有执行就是失败,不能让客户端把
// "被拒"读成"回滚完成"。
func rollbackResult(rej *rollbackRejection) *mcp.CallToolResult {
	res := jsonResult(rej)
	res.IsError = true
	return res
}

// rejectionResult 把结构化拒绝写成 isError 结果:没有执行就是失败,不能让客户端
// 把"出了个待办/被拒"读成成功。
func rejectionResult(rej *applyRejection) *mcp.CallToolResult {
	res := jsonResult(rej)
	res.IsError = true
	return res
}
