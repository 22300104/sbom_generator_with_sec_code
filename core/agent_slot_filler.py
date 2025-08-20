import os
import json
import re
from typing import Dict, Optional

from openai import OpenAI
from anthropic import Anthropic


class AgentSlotFiller:
    def __init__(self):
        self.openai_client = None
        self.anthropic_client = None
        if os.getenv("OPENAI_API_KEY"):
            self.openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        if os.getenv("ANTHROPIC_API_KEY"):
            self.anthropic_client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

    def parse_to_slots(self, text: str) -> Dict[str, Optional[str]]:
        prompt = self._build_prompt(text)
        raw = None
        if self.anthropic_client:
            try:
                model = os.getenv("ANTHROPIC_MODEL", "claude-3-opus-20240229")
                resp = self.anthropic_client.messages.create(
                    model=model,
                    max_tokens=500,
                    temperature=0,
                    messages=[{"role": "user", "content": prompt}],
                )
                raw = resp.content[0].text if resp and resp.content else None
            except Exception:
                raw = None
        if raw is None and self.openai_client:
            try:
                model = os.getenv("OPENAI_MODEL", "gpt-4-turbo-preview")
                kwargs = {
                    "model": model,
                    "messages": [
                        {"role": "system", "content": "Return JSON only."},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0,
                    "max_tokens": 400,
                }
                if "gpt-4" in model:
                    kwargs["response_format"] = {"type": "json_object"}
                resp = self.openai_client.chat.completions.create(**kwargs)
                raw = resp.choices[0].message.content
            except Exception:
                raw = None
        if raw is None:
            return self._regex_fallback(text)
        return self._parse_json_safely(raw)

    def _build_prompt(self, text: str) -> str:
        return (
            "다음 사용자의 요청에서 GitHub 분석 슬롯을 추출하고 JSON만 반환하세요.\n"
            "입력: \n" + text + "\n\n"
            "반환 형식(JSON만):\n"
            "{\n"
            "  \"repo\": \"https://github.com/owner/repo 또는 owner/repo\",\n"
            "  \"base\": \"기준 브랜치 (branch 비교 시)\",\n"
            "  \"compare\": \"비교 브랜치 (branch 비교 시)\",\n"
            "  \"scope\": \"diff 또는 full (branch/PR 분석 시)\",\n"
            "  \"analysis\": \"full | branch | pr\",\n"
            "  \"pr_number\": \"숫자 (PR 분석 시)\"\n"
            "}"
        )

    def _parse_json_safely(self, text: str) -> Dict[str, Optional[str]]:
        s = text.strip()
        if s.startswith("```"):
            i = s.find("\n")
            s = s[i + 1 :] if i != -1 else s
            if s.endswith("```"):
                s = s[:-3]
        m = re.search(r"\{[\s\S]*\}$", s)
        if m:
            s = m.group(0)
        try:
            data = json.loads(s)
        except Exception:
            return self._empty()
        return {
            "repo": data.get("repo"),
            "base": data.get("base"),
            "compare": data.get("compare"),
            "scope": data.get("scope"),
            "analysis": data.get("analysis"),
            "pr_number": data.get("pr_number"),
        }

    def _regex_fallback(self, text: str) -> Dict[str, Optional[str]]:
        repo = None
        m = re.search(r"github\.com/([\w.-]+)/([\w.-]+)", text, re.I)
        if m:
            repo = f"https://github.com/{m.group(1)}/{m.group(2)}"
        else:
            m2 = re.search(r"\b([\w.-]+)/([\w.-]+)\b", text)
            if m2:
                repo = f"https://github.com/{m2.group(1)}/{m2.group(2)}"
        # 분석 타입
        analysis = None
        pr_number = None
        if re.search(r"\bpr\b|pull\s*request", text, re.I):
            analysis = "pr"
            mpr = re.search(r"#?(\d{1,6})", text)
            if mpr:
                pr_number = mpr.group(1)
        elif re.search(r"브랜치|branch|compare", text, re.I):
            analysis = "branch"
        elif re.search(r"전체|full\s*repo|all\s*files", text, re.I):
            analysis = "full"
        else:
            analysis = None
        bb = None
        m = re.search(r"base[:=\s]+([\w\-/]+)", text, re.I)
        if m:
            bb = m.group(1)
        cb = None
        m = re.search(r"compare[:=\s]+([\w\-/]+)", text, re.I)
        if m:
            cb = m.group(1)
        scope = None
        if re.search(r"diff\s*only|변경사항만|diff", text, re.I):
            scope = "diff"
        elif re.search(r"full|전체", text, re.I):
            scope = "full"
        return {"repo": repo, "base": bb, "compare": cb, "scope": scope, "analysis": analysis, "pr_number": pr_number}

    def _empty(self) -> Dict[str, Optional[str]]:
        return {"repo": None, "base": None, "compare": None, "scope": None, "analysis": None, "pr_number": None}


