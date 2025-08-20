"""
GitHub MCP 어댑터

가능하면 MCP 서버를 통해 작업하고, 가용하지 않으면 GitHub REST API로 폴백한다.
"""
import os
import base64
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import requests


class MCPGithubClient:
    """GitHub MCP 연동 클라이언트 (폴백 포함)"""

    def __init__(self, server_url: Optional[str] = None, github_token: Optional[str] = None):
        self.server_url = server_url or os.getenv("MCP_GITHUB_SERVER_URL")
        self.github_token = github_token or os.getenv("GITHUB_TOKEN")
        self.connected = False

        self._headers = {"Accept": "application/vnd.github.v3+json"}
        if self.github_token:
            self._headers["Authorization"] = f"token {self.github_token}"

    def connect(self) -> bool:
        """MCP 서버에 연결 시도. 현재는 REST 폴백 중심으로 동작하며, 서버 URL이 있다면 가용성만 체크한다."""
        if self.server_url:
            try:
                # MCP 서버 헬스체크가 표준화되어 있지 않으므로 간단한 핑만 시도 (실패해도 폴백 동작)
                _ = requests.get(self.server_url, timeout=2)
                self.connected = True
            except Exception:
                self.connected = False
        else:
            self.connected = False
        return self.connected

    # --- 선택적: MCP 기능 래핑 (현재는 REST 폴백을 기본으로 제공) ---

    def create_pull_request(
        self,
        owner: str,
        repo: str,
        base_branch: str,
        compare_branch: str,
        title: str,
        body: str = "",
        draft: bool = False,
    ) -> Dict:
        """PR 생성. 우선 MCP 사용을 고려하되, 기본은 GitHub REST API.

        Returns:
            { success, url?, number?, error? }
        """
        # MCP 경로(미구현) → 필요 시 확장
        # if self.connected:
        #     try:
        #         ...
        #     except Exception as e:
        #         return {"success": False, "error": str(e)}

        if not self.github_token:
            return {"success": False, "error": "GITHUB_TOKEN이 필요합니다"}

        try:
            api = f"https://api.github.com/repos/{owner}/{repo}/pulls"
            payload = {
                "title": title,
                "head": compare_branch,
                "base": base_branch,
                "body": body or "",
                "draft": draft,
            }
            resp = requests.post(api, json=payload, headers=self._headers, timeout=15)
            if resp.status_code in (200, 201):
                data = resp.json()
                return {
                    "success": True,
                    "url": data.get("html_url"),
                    "number": data.get("number"),
                }
            else:
                try:
                    err = resp.json()
                except Exception:
                    err = {"message": resp.text}
                return {"success": False, "error": f"{resp.status_code}: {err.get('message', 'PR 생성 실패')}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # --------- 고급: 스냅샷 브랜치 생성 후 파일 업로드 → PR 생성 ---------

    def _get_ref_sha(self, owner: str, repo: str, branch: str) -> Optional[str]:
        try:
            url = f"https://api.github.com/repos/{owner}/{repo}/git/ref/heads/{branch}"
            resp = requests.get(url, headers=self._headers, timeout=15)
            if resp.status_code == 200:
                return resp.json().get('object', {}).get('sha')
        except Exception:
            pass
        return None

    def _create_branch(self, owner: str, repo: str, new_branch: str, from_sha: str) -> Dict:
        try:
            url = f"https://api.github.com/repos/{owner}/{repo}/git/refs"
            payload = {"ref": f"refs/heads/{new_branch}", "sha": from_sha}
            resp = requests.post(url, json=payload, headers=self._headers, timeout=15)
            if resp.status_code in (200, 201):
                return {"success": True}
            else:
                try:
                    err = resp.json()
                except Exception:
                    err = {"message": resp.text}
                return {"success": False, "error": f"{resp.status_code}: {err.get('message', '브랜치 생성 실패')}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _get_file_sha(self, owner: str, repo: str, path: str, branch: str) -> Optional[str]:
        try:
            url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
            resp = requests.get(url, headers=self._headers, params={"ref": branch}, timeout=15)
            if resp.status_code == 200:
                return resp.json().get('sha')
        except Exception:
            pass
        return None

    def _upsert_file(self, owner: str, repo: str, path: str, content: str, message: str, branch: str) -> Dict:
        try:
            url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
            sha = self._get_file_sha(owner, repo, path, branch)
            payload = {
                "message": message,
                "content": base64.b64encode(content.encode('utf-8')).decode('utf-8'),
                "branch": branch,
            }
            if sha:
                payload["sha"] = sha
            resp = requests.put(url, json=payload, headers=self._headers, timeout=20)
            if resp.status_code in (200, 201):
                return {"success": True}
            else:
                try:
                    err = resp.json()
                except Exception:
                    err = {"message": resp.text}
                return {"success": False, "error": f"{resp.status_code}: {err.get('message', '파일 업로드 실패')}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def create_snapshot_branch_and_pr(
        self,
        owner: str,
        repo: str,
        base_branch: str,
        title: str,
        body: str,
        files: Dict[str, str],  # path -> content
        draft: bool = True,
    ) -> Dict:
        """분석된 파일 스냅샷을 새 브랜치에 커밋하고 PR 생성.

        files: { "path/to/file.py": "<content>" }
        """
        if not self.github_token:
            return {"success": False, "error": "GITHUB_TOKEN이 필요합니다"}

        base_sha = self._get_ref_sha(owner, repo, base_branch)
        if not base_sha:
            return {"success": False, "error": f"기준 브랜치 조회 실패: {base_branch}"}

        new_branch = f"security-analysis-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        created = self._create_branch(owner, repo, new_branch, base_sha)
        if not created.get('success'):
            return created

        commit_msg = f"chore(security): analysis snapshot ({len(files)} files)"
        for path, content in files.items():
            up = self._upsert_file(owner, repo, path, content, commit_msg, new_branch)
            if not up.get('success'):
                return up

        return self.create_pull_request(owner, repo, base_branch, new_branch, title, body, draft)


