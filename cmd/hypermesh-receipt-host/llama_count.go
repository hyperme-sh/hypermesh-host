package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
)

func (h host) runtimeJSON(ctx context.Context, path string, payload any, result any) error {
	method := http.MethodGet
	var data []byte
	var err error
	if payload != nil {
		method = http.MethodPost
		data, err = json.Marshal(payload)
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, h.runtime+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("runtime request refused")
	}
	data, err = bounded(resp.Body)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, result)
}

// Ask the serving model to render the actual chat template and parse its
// special tokens, including the generation prompt and model-specific BOS.
func (h host) llamaCount(w http.ResponseWriter, r *http.Request, body []byte) {
	var chat struct {
		Model    string `json:"model"`
		Messages []struct {
			Role    string  `json:"role"`
			Content *string `json:"content"`
		} `json:"messages"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if dec.Decode(&chat) != nil || chat.Model != h.model || len(chat.Messages) == 0 {
		http.Error(w, "llama.cpp counting supports plain text chat", 400)
		return
	}
	for _, m := range chat.Messages {
		if m.Content == nil || (m.Role != "system" && m.Role != "user" && m.Role != "assistant") {
			http.Error(w, "unsupported chat message", 400)
			return
		}
	}
	var props struct {
		Model    string `json:"model_alias"`
		Settings struct {
			Context int `json:"n_ctx"`
		} `json:"default_generation_settings"`
	}
	var rendered struct {
		Prompt *string `json:"prompt"`
	}
	var result struct {
		Tokens *[]int `json:"tokens"`
	}
	ctx := r.Context()
	if h.runtimeJSON(ctx, "/props", nil, &props) != nil || props.Settings.Context < 1 || props.Model != h.model ||
		h.runtimeJSON(ctx, "/apply-template", chat, &rendered) != nil || rendered.Prompt == nil ||
		h.runtimeJSON(ctx, "/tokenize", map[string]any{"content": *rendered.Prompt, "add_special": true, "parse_special": true}, &result) != nil || result.Tokens == nil {
		http.Error(w, "serving model tokenizer unavailable", 502)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"count": len(*result.Tokens), "max_model_len": props.Settings.Context})
}
