// dbus.go 是 godbus/v5 客户端:探测 Baloo 在会话 bus 上的可用性。D-Bus 客户
// 端与 CLI runner 是两条独立路径,不复用。
//
// 接口面:仅 NameHasOwner + IndexingEnabled。IndexingEnabled 走
// org.freedesktop.DBus.Properties.Get 在 (org.kde.baloo, /,
// org.kde.baloo.main) 上取值;godbus 调用失败一律降级 (false, err),上层
// 只看 nil→disabled。
//
// DynamicUser 沙箱下找不到 /run/user/<dynuid>/bus,connect 失败即降级
// (不 panic)。
package main

import (
	"errors"
	"fmt"

	"github.com/godbus/dbus/v5"
)

// balooDBusConn 是 balooDBus 接口的 godbus 实现(production)。
// 连接会话 bus 时 godbus 会用 $DBUS_SESSION_BUS_ADDRESS 或
// "/run/user/<uid>/bus" 默认值;DynamicUser 沙箱里 uid 取 dynuid,
// 路径不存在 → conn 为 nil,err 非 nil。
type balooDBusConn struct {
	conn *dbus.Conn
}

// defaultDBusConnect 默认生产态 connect:开 SessionBus conn。失败时返
// (nil, err),**不 panic**。
func defaultDBusConnect() (balooDBus, error) {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return nil, fmt.Errorf("dbus.ConnectSessionBus: %w", err)
	}
	return &balooDBusConn{conn: conn}, nil
}

// NameHasOwner 走 org.freedesktop.DBus.NameHasOwner。dbus godbus 返回
// ([]any, error);若 dbus.Error 反映 "not connected" 等,降级为 (false, err)。
func (d *balooDBusConn) NameHasOwner(name string) (bool, error) {
	if d == nil || d.conn == nil {
		return false, errors.New("balooDBusConn: nil conn")
	}
	obj := d.conn.Object("org.freedesktop.DBus", "/org/freedesktop/DBus")
	call := obj.Call("org.freedesktop.DBus.NameHasOwner", 0, name)
	if call.Err != nil {
		return false, fmt.Errorf("NameHasOwner(%s): %w", name, call.Err)
	}
	if len(call.Body) < 1 {
		return false, errors.New("NameHasOwner 返回空 body")
	}
	owned, ok := call.Body[0].(bool)
	if !ok {
		return false, fmt.Errorf("NameHasOwner body[0] 类型=%T 期望 bool", call.Body[0])
	}
	return owned, nil
}

// IndexingEnabled 走 org.freedesktop.DBus.Properties.Get 在
// (org.kde.baloo, /, "org.kde.baloo.main.IndexingEnabled") 上取值。失败时
// 返回 (false, err),**不 panic**。
func (d *balooDBusConn) IndexingEnabled() (bool, error) {
	if d == nil || d.conn == nil {
		return false, errors.New("balooDBusConn: nil conn")
	}
	obj := d.conn.Object("org.kde.baloo", "/")
	call := obj.Call("org.freedesktop.DBus.Properties.Get", 0,
		"org.kde.baloo.main", "IndexingEnabled")
	if call.Err != nil {
		return false, fmt.Errorf("org.kde.baloo.main.IndexingEnabled: %w", call.Err)
	}
	if len(call.Body) < 1 {
		return false, errors.New("Properties.Get 返回空 body")
	}
	variant, ok := call.Body[0].(dbus.Variant)
	if !ok {
		return false, fmt.Errorf("Properties.Get body[0] 类型=%T 期望 dbus.Variant", call.Body[0])
	}
	b, ok := variant.Value().(bool)
	if !ok {
		return false, fmt.Errorf("IndexingEnabled variant 解包类型=%T 期望 bool", variant.Value())
	}
	return b, nil
}

// Close 释放 conn;失败忽略。
func (d *balooDBusConn) Close() error {
	if d == nil || d.conn == nil {
		return nil
	}
	return d.conn.Close()
}
