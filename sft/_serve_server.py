
import argparse, json, os, sys, torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--adapter", required=True)
    ap.add_argument("--base-model", default="Qwen/Qwen2.5-7B-Instruct")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()

    tok = AutoTokenizer.from_pretrained(args.base_model, trust_remote_code=True)
    if tok.pad_token is None: tok.pad_token = tok.eos_token
    base = AutoModelForCausalLM.from_pretrained(args.base_model, dtype=torch.bfloat16, device_map="cuda:0", trust_remote_code=True)
    model = PeftModel.from_pretrained(base, args.adapter)
    model = model.merge_and_unload()
    model.eval()

    from fastapi import FastAPI
    from pydantic import BaseModel
    import uvicorn
    app = FastAPI()

    class Msg(BaseModel):
        role: str
        content: str = ""

    class ChatReq(BaseModel):
        model: str = "default"
        messages: list[Msg]
        temperature: float = 0.0
        max_tokens: int = 4096
        stream: bool = False
        tools: list | None = None

    @app.post("/v1/chat/completions")
    def chat(req: ChatReq):
        msgs = [{"role": m.role, "content": m.content} for m in req.messages]
        text = tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
        inputs = tok(text, return_tensors="pt").to("cuda:0")
        with torch.no_grad():
            out = model.generate(**inputs, max_new_tokens=req.max_tokens, temperature=max(req.temperature,0.01), do_sample=req.temperature>0, pad_token_id=tok.pad_token_id)
        resp = tok.decode(out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True)
        return {"id":"0","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":resp},"finish_reason":"stop"}],"usage":{"prompt_tokens":0,"completion_tokens":0,"total_tokens":0}}

    @app.get("/v1/models")
    def models(): return {"data":[{"id":"qwen25-7b-lora","object":"model","owned_by":"local"}]}

    uvicorn.run(app, host="0.0.0.0", port=args.port)

if __name__ == "__main__":
    main()
