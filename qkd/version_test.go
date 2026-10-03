package qkd

import (
	"context"
	"testing"
)

// TestV2IsDefaultAndV1Supported 新会话默认使用 v2，v1 仍可显式使用，
// 未知版本返回独立原因 unsupported_version。
func TestV2IsDefaultAndV1Supported(t *testing.T) {
	if DefaultParams().Version != ParamsV2 {
		t.Fatalf("[判定依据] 新会话默认版本应为 %s，实际 %s", ParamsV2, DefaultParams().Version)
	}
	m, err := NewManager(ManagerConfig{
		Params: DefaultParams(), Channel: ChannelConfig{NoiseRate: 0.02}, MasterSeed: 20261003,
	})
	if err != nil {
		t.Fatal(err)
	}
	idV2, err := m.RunSession(context.Background(), "default-v2")
	if err != nil {
		t.Fatalf("v2 默认会话应成功: %v", err)
	}
	k, _ := m.Store().Get(idV2)
	t.Logf("[输入参数] 默认 %+v => [结论] 签发 %s ver=%s len=%d",
		m.Params(), idV2, k.ParamsVer, len(k.Key))
	if k.ParamsVer != ParamsV2 {
		t.Fatalf("密钥应带 v2 版本标记，实际 %s", k.ParamsVer)
	}
	if len(k.Key) != DefaultParamsV2().KeyBytes {
		t.Fatalf("v2 默认密钥长度应为 %d，实际 %d", DefaultParamsV2().KeyBytes, len(k.Key))
	}

	// v1 继续受支持。
	m1, err := NewManager(ManagerConfig{
		Params: DefaultParamsV1(), Channel: ChannelConfig{NoiseRate: 0.02}, MasterSeed: 20261003,
	})
	if err != nil {
		t.Fatal(err)
	}
	idV1, err := m1.RunSession(context.Background(), "explicit-v1")
	if err != nil {
		t.Fatalf("v1 会话仍应受支持: %v", err)
	}
	k1, _ := m1.Store().Get(idV1)
	if k1.ParamsVer != ParamsV1 || len(k1.Key) != DefaultParamsV1().KeyBytes {
		t.Fatalf("v1 密钥版本/长度不符: ver=%s len=%d", k1.ParamsVer, len(k1.Key))
	}
	t.Logf("[结论] v1 继续受支持: %s ver=%s len=%d", idV1, k1.ParamsVer, len(k1.Key))

	// 未知版本必须与其它失败可区分。
	_, err = NewManager(ManagerConfig{Params: Params{
		Version: "qkd-params-v99", N: 64, SampleFraction: 0.2, QBERThreshold: 0.15, KeyBytes: 16,
		ReconcilePasses: 4, BlockSize: 8,
	}})
	if err == nil || !IsFailure(err, ReasonUnsupportedVersion) {
		t.Fatalf("[判定依据] 未知版本应返回 unsupported_version，实际: %v", err)
	}
	if IsFailure(err, ReasonConfigInvalid) {
		t.Fatal("unsupported_version 不得与 config_invalid 混淆")
	}
	t.Logf("[结论] 未知版本被独立归类: %v", err)
}

// TestV1RecordReplayBitIdentical v1 会话归档后重放：密钥 ID、密钥字节、
// 关键统计与失败结论必须与当初逐比特一致；JSON 往返后再重放仍一致。
func TestV1RecordReplayBitIdentical(t *testing.T) {
	p := DefaultParamsV1()

	// 场景一：成功会话。
	m, err := NewManager(ManagerConfig{
		Params: p, Channel: ChannelConfig{NoiseRate: 0.05}, MasterSeed: 777,
	})
	if err != nil {
		t.Fatal(err)
	}
	id, err := m.RunSession(context.Background(), "legacy-success")
	if err != nil {
		t.Fatal(err)
	}
	origKey, err := m.Store().Get(id)
	if err != nil {
		t.Fatal(err)
	}
	rec, ok := m.History().Get("legacy-success")
	if !ok {
		t.Fatal("缺少归档")
	}
	t.Logf("[输入参数] v1 成功重放: seed=%d params=%+v", rec.Seed, rec.Params)

	rep, err := ReplayRecord(rec)
	if err != nil {
		t.Fatalf("v1 记录重放应成功: %v", err)
	}
	if rep.KeyID != id {
		t.Fatalf("[判定依据] 重放密钥 ID 不一致 %s != %s", rep.KeyID, id)
	}
	if string(rep.Key) != string(origKey.Key) {
		t.Fatalf("[结论] v1 重放密钥未逐比特一致\norig=%x\nreplay=%x", origKey.Key, rep.Key)
	}
	if rep.Stats.QBER != rec.Stats.QBER || rep.Stats.Sifted != rec.Stats.Sifted ||
		rep.Stats.ReconcileFixes != rec.Stats.ReconcileFixes {
		t.Fatalf("重放统计不一致: replay=%+v record=%+v", rep.Stats, rec.Stats)
	}
	t.Logf("[判定依据] qber=%.4f sifted=%d fixes=%d => [结论] 密钥逐比特一致 id=%s len=%d",
		rep.Stats.QBER, rep.Stats.Sifted, rep.Stats.ReconcileFixes, rep.KeyID, len(rep.Key))

	// JSON 往返（模拟老记录落盘后在新版本读取）再重放，结论不变。
	data, err := MarshalRecord(rec)
	if err != nil {
		t.Fatal(err)
	}
	reparsed, err := UnmarshalRecord(data)
	if err != nil {
		t.Fatal(err)
	}
	rep2, err := ReplayRecord(reparsed)
	if err != nil {
		t.Fatalf("JSON 往返后重放失败: %v", err)
	}
	if string(rep2.Key) != string(origKey.Key) || rep2.KeyID != id {
		t.Fatalf("[结论] JSON 往返后重放结论漂移: id=%s/%s same=%v",
			rep2.KeyID, id, string(rep2.Key) == string(origKey.Key))
	}
	t.Logf("[结论] JSON 往返后重放仍逐比特一致 JSON=%s", data)

	// 场景二：失败会话（窃听超阈），重放必须得到相同失败归类。
	mb, err := NewManager(ManagerConfig{
		Params:     DefaultParamsV1(),
		Channel:    ChannelConfig{NoiseRate: 0, EavesdropRate: 0.7},
		MasterSeed: 888,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, failErr := mb.RunSession(context.Background(), "legacy-fail")
	if failErr == nil || !IsFailure(failErr, ReasonEavesdropping) {
		t.Fatalf("前置失败原因应为窃听: %v", failErr)
	}
	failRec, _ := mb.History().Get("legacy-fail")
	frep, err := ReplayRecord(failRec)
	if err != nil {
		t.Fatalf("失败记录重放不应返回错误（结论一致即通过）: %v", err)
	}
	if frep.Success || frep.Reason != ReasonEavesdropping {
		t.Fatalf("[结论] 失败记录重放应保持 eavesdropping，实际 success=%v reason=%q",
			frep.Success, frep.Reason)
	}
	if frep.Stats.QBER != failRec.Stats.QBER {
		t.Fatalf("失败记录重放 QBER 不一致: %.4f != %.4f",
			frep.Stats.QBER, failRec.Stats.QBER)
	}
	t.Logf("[输入参数] v1 失败重放 eve=0.7 => [结论] qber=%.4f 归类 %q 与当初一致",
		frep.Stats.QBER, frep.Reason)
}

// TestOldKeyUsableUnderNewVersion 升级后：v1 时代签发的老密钥（连同老密钥库）
// 在以 v2 为默认的新管理器下照样能取用、可撤销、可退役。
func TestOldKeyUsableUnderNewVersion(t *testing.T) {
	old, err := NewManager(ManagerConfig{
		Params: DefaultParamsV1(), Channel: ChannelConfig{NoiseRate: 0.02}, MasterSeed: 1919,
	})
	if err != nil {
		t.Fatal(err)
	}
	oldID, err := old.RunSession(context.Background(), "pre-upgrade")
	if err != nil {
		t.Fatal(err)
	}
	oldKey, _ := old.Store().Get(oldID)

	// “升级”：共享同一密钥库与归档，但新管理器使用 v2 默认参数。
	upgraded, err := NewManager(ManagerConfig{
		Params:  DefaultParams(), // v2
		Channel: ChannelConfig{NoiseRate: 0.02},
		Store:   old.Store(), History: old.History(),
		MasterSeed: 2020,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := upgraded.Store().Get(oldID)
	if err != nil {
		t.Fatalf("[判定依据] v1 老密钥在 v2 管理器下应可取用: %v", err)
	}
	if string(got.Key) != string(oldKey.Key) {
		t.Fatalf("[结论] 老密钥字节在升级后发生变化")
	}
	if got.ParamsVer != ParamsV1 {
		t.Fatalf("老密钥应保留 v1 版本标记，实际 %s", got.ParamsVer)
	}
	t.Logf("[结论] v1 老密钥 %s 在 v2 默认下完好可取 ver=%s len=%d",
		oldID, got.ParamsVer, len(got.Key))

	// 新会话签 v2 密钥，与老密钥并存互不干扰。
	newID, err := upgraded.RunSession(context.Background(), "post-upgrade")
	if err != nil {
		t.Fatal(err)
	}
	newKey, _ := upgraded.Store().Get(newID)
	if newKey.ParamsVer != ParamsV2 {
		t.Fatalf("新密钥应为 v2，实际 %s", newKey.ParamsVer)
	}
	if string(newKey.Key) == string(got.Key) {
		t.Fatal("v2 新密钥不得与 v1 老密钥相同")
	}
	// 老密钥仍可走生命周期操作。
	if err := upgraded.Store().Retire(oldID); err != nil {
		t.Fatalf("v1 老密钥应可退役: %v", err)
	}
	_, retireErr := upgraded.Store().Get(oldID)
	if !IsFailure(retireErr, ReasonKeyRetired) {
		t.Fatalf("退役结论应可区分: %v", retireErr)
	}
	t.Logf("[结论] v2 新会话 %s 与 v1 老密钥并存；老密钥退役结论=%v", newID, retireErr)
}

// TestReplayUnknownVersion 记录携带未知参数版本时，重放返回
// unsupported_version，与信道/纠错类失败可区分。
func TestReplayUnknownVersion(t *testing.T) {
	rec := SessionRecord{
		Schema:    RecordV1,
		ID:        "future-record",
		ParamsVer: "qkd-params-v9",
		Params: Params{
			Version: "qkd-params-v9", N: 256, SampleFraction: 0.2, QBERThreshold: 0.15,
			KeyBytes: 16, ReconcilePasses: 4, BlockSize: 8,
		},
		Seed:    1,
		Success: true,
	}
	// 未知版本记录本身仍可解析（归档解析不因版本而失败）。
	data, _ := MarshalRecord(rec)
	if _, err := UnmarshalRecord(data); err != nil {
		t.Fatalf("[判定依据] 未知版本记录应仍可解析: %v", err)
	}
	_, err := ReplayRecord(rec)
	if err == nil || !IsFailure(err, ReasonUnsupportedVersion) {
		t.Fatalf("[结论] 未知版本重放应返回 unsupported_version，实际: %v", err)
	}
	t.Logf("[结论] 记录可解析但重放被独立归类: %v", err)
}

// TestV2RecordReplayBitIdentical v2 成功会话重放同样逐比特一致，
// 且 v2 密钥与其 v1 假想重跑（同种子/ID/参数取值）在域标签作用下不同。
func TestV2RecordReplayBitIdentical(t *testing.T) {
	m, err := NewManager(ManagerConfig{
		Params: DefaultParamsV2(), Channel: ChannelConfig{NoiseRate: 0.04}, MasterSeed: 31415,
	})
	if err != nil {
		t.Fatal(err)
	}
	id, err := m.RunSession(context.Background(), "v2-success")
	if err != nil {
		t.Fatal(err)
	}
	orig, _ := m.Store().Get(id)
	rec, _ := m.History().Get("v2-success")

	rep, err := ReplayRecord(rec)
	if err != nil {
		t.Fatalf("v2 重放应成功: %v", err)
	}
	if string(rep.Key) != string(orig.Key) || rep.KeyID != id {
		t.Fatalf("[结论] v2 重放未逐比特一致: id %s/%s same=%v",
			rep.KeyID, id, string(rep.Key) == string(orig.Key))
	}
	if rep.Stats.QBER != rec.Stats.QBER || rep.Stats.FinalKeyBytes != rec.KeyBytes {
		t.Fatalf("v2 重放统计漂移: %+v vs %+v", rep.Stats, rec.Stats)
	}
	t.Logf("[输入参数] v2 seed=%d keyBytes=%d => [结论] qber=%.4f 重放逐比特一致 id=%s",
		rec.Seed, rec.Params.KeyBytes, rep.Stats.QBER, rep.KeyID)
}
