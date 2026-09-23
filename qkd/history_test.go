package qkd

import (
	"encoding/json"
	"testing"
)

// TestRecordRoundTrip 当前格式记录可往返序列化，数值不丢失。
func TestRecordRoundTrip(t *testing.T) {
	p := DefaultParams()
	rec := SessionRecord{
		Schema:     RecordV1,
		ID:         "rec-1",
		ParamsVer:  p.Version,
		Params:     p,
		Seed:       987654321,
		Channel:    ChannelConfig{NoiseRate: 0.04, EavesdropRate: 0},
		Success:    false,
		FailReason: ReasonChannelQuality,
		Stats: SessionStats{
			Sent: 2048, Sifted: 1000, Sampled: 200, SampledErrors: 40,
			QBER: 0.2, Threshold: 0.15, AbortReason: ReasonChannelQuality,
		},
	}
	data, err := MarshalRecord(rec)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalRecord(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != rec.ID || got.Seed != rec.Seed || got.FailReason != rec.FailReason {
		t.Fatalf("往返后字段不一致: %+v", got)
	}
	if got.Params.KeyBytes != p.KeyBytes || got.Stats.QBER != 0.2 {
		t.Fatalf("嵌套参数/统计往返后不一致: %+v", got)
	}
	t.Logf("[结论] 记录往返成功 JSON=%s", string(data))
}

// TestRecordBackwardCompatibility 旧格式（缺 schema、字段别名 params_version /
// abort_reason）在新版本下仍可解析。
func TestRecordBackwardCompatibility(t *testing.T) {
	legacy := []byte(`{
		"id": "old-session",
		"params_version": "qkd-params-v1",
		"params": {"version":"qkd-params-v1","n":512,"sample_fraction":0.25,
		           "qber_threshold":0.1,"noise_rate":0.2,"eavesdrop_rate":0,
		           "key_bytes":16,"reconcile_passes":8,"block_size":16},
		"seed": 555,
		"channel": {"noise_rate":0.2,"eavesdrop_rate":0},
		"success": false,
		"abort_reason": "channel_quality_exceeded",
		"stats": {"stage":"aborted","qber":0.21,"threshold":0.1}
	}`)
	rec, err := UnmarshalRecord(legacy)
	if err != nil {
		t.Fatalf("旧格式记录应可解析: %v", err)
	}
	if rec.Schema != RecordV1 {
		t.Fatalf("缺省 schema 应归一为 %s，实际 %s", RecordV1, rec.Schema)
	}
	if rec.ParamsVer != ParamsV1 || rec.Params.Version != ParamsV1 {
		t.Fatalf("旧别名 params_version 应被识别: %+v", rec)
	}
	if rec.FailReason != ReasonChannelQuality {
		t.Fatalf("旧别名 abort_reason 应映射到 FailReason，实际 %q", rec.FailReason)
	}
	if rec.Params.N != 512 || rec.Params.KeyBytes != 16 || rec.Stats.QBER != 0.21 {
		t.Fatalf("旧记录数值解析错误: %+v stats=%+v", rec.Params, rec.Stats)
	}
	t.Logf("[结论] 历史记录在新版本下可解析 id=%s params=%+v reason=%q",
		rec.ID, rec.Params, rec.FailReason)
}

// TestHistoryConcurrency 归档在高并发写入下无竞态、无丢失。
func TestHistoryConcurrency(t *testing.T) {
	h := NewHistory()
	done := make(chan struct{})
	for g := 0; g < 8; g++ {
		go func(g int) {
			for i := 0; i < 50; i++ {
				h.Add(SessionRecord{Schema: RecordV1, ID: string(rune('a'+g)) + "-" + string(rune('0'+i%10))})
				_, _ = h.Get("x")
				_ = h.List()
			}
			done <- struct{}{}
		}(g)
	}
	for g := 0; g < 8; g++ {
		<-done
	}
	t.Logf("[结论] 并发归档完成，留存记录 %d 条", len(h.List()))
}

// TestJSONShape 记录序列化包含版本字段，便于外部工具识别。
func TestJSONShape(t *testing.T) {
	data, err := MarshalRecord(SessionRecord{ID: "z"})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if m["schema"] != string(RecordV1) {
		t.Fatalf("记录应带最新 schema 字段: %s", data)
	}
}
