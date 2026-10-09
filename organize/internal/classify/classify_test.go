package classify

import "testing"

// Type 已知扩展名走索引:jpg→images,pdf→documents,mp3→music。
func TestClassify_KnownExtensions(t *testing.T) {
	cases := map[string]string{
		"/tmp/photo.jpg": "images",
		"/tmp/paper.pdf": "documents",
		"/tmp/song.mp3":  "music",
		"/tmp/clip.mp4":  "videos",
		"/tmp/data.zip":  "archives",
		"/tmp/main.go":   "code",
	}
	for path, want := range cases {
		got, err := Type(path)
		if err != nil {
			t.Fatalf("Type(%q) 错误: %v", path, err)
		}
		if got != want {
			t.Errorf("Type(%q) = %q, want %q", path, got, want)
		}
	}
}

// Type 未知扩展名:扩展名查表未命中且 mime.TypeByExtension 也无已知顶级类型 → "other"。
func TestClassify_UnknownExtension(t *testing.T) {
	got, err := Type("/tmp/notes.zzzunknown")
	if err != nil {
		t.Fatalf("Type 错误: %v", err)
	}
	if got != "other" {
		t.Errorf("Type(未知扩展名) = %q, want other", got)
	}
}

// Type 无扩展名:空扩展名直接走 "other" 兜底,不查 mime,不查索引。
func TestClassify_NoExtension(t *testing.T) {
	got, err := Type("/tmp/Makefile")
	if err != nil {
		t.Fatalf("Type 错误: %v", err)
	}
	if got != "other" {
		t.Errorf("Type(无扩展名) = %q, want other", got)
	}
}
