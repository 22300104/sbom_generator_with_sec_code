# core/github_branch_analyzer.py
"""
GitHub 브랜치 비교 및 diff 기반 보안 분석 모듈
Pull Request 전 브랜치 간 변경사항만 선택적으로 검사
"""
import os
import re
import json
import tempfile
import shutil
from typing import Dict, List, Optional, Tuple, Set
from pathlib import Path
import requests
from datetime import datetime
import base64
import urllib.parse
import urllib.parse

try:
    import git
    from git import Repo
    GIT_AVAILABLE = True
except ImportError:
    GIT_AVAILABLE = False
    print("⚠️ GitPython이 설치되지 않았습니다. pip install GitPython")


class GitHubBranchAnalyzer:
    """GitHub 브랜치 비교 및 diff 분석기"""
    
    def __init__(self, github_token: Optional[str] = None):
        """
        Args:
            github_token: GitHub API 토큰 (private repo 접근용, 선택사항)
        """
        self.github_token = github_token or os.getenv("GITHUB_TOKEN")
        self.api_base = "https://api.github.com"
        self.headers = {
            "Accept": "application/vnd.github.v3+json"
        }
        if self.github_token:
            self.headers["Authorization"] = f"token {self.github_token}"
        
        self.temp_dir = None
        self.repo_path = None
        
    def get_branches(self, repo_url: str) -> Dict[str, List[Dict]]:
        """
        레포지토리의 모든 브랜치 목록 가져오기
        
        Args:
            repo_url: GitHub 레포지토리 URL
            
        Returns:
            브랜치 정보 딕셔너리
        """
        try:
            # URL에서 owner/repo 추출
            owner, repo = self._parse_github_url(repo_url)
            if not owner or not repo:
                return {"success": False, "error": "Invalid GitHub URL", "branches": []}
            
            # GitHub API로 브랜치 목록 가져오기
            api_url = f"{self.api_base}/repos/{owner}/{repo}/branches"
            
            branches = []
            page = 1
            
            while True:
                response = requests.get(
                    api_url,
                    headers=self.headers,
                    params={"page": page, "per_page": 100}
                )
                
                if response.status_code == 404:
                    return {"success": False, "error": "Repository not found", "branches": []}
                elif response.status_code == 403:
                    return {"success": False, "error": "API rate limit exceeded", "branches": []}
                elif response.status_code != 200:
                    return {"success": False, "error": f"API error: {response.status_code}", "branches": []}
                
                page_branches = response.json()
                if not page_branches:
                    break
                    
                for branch in page_branches:
                    branches.append({
                        "name": branch["name"],
                        "sha": branch["commit"]["sha"],
                        "protected": branch.get("protected", False),
                        "commit_url": branch["commit"]["url"],
                        "commit_date": self._get_commit_date(branch["commit"]["url"])
                    })
                
                # 다음 페이지 확인
                if len(page_branches) < 100:
                    break
                page += 1
            
            # 날짜순 정렬 (최신 먼저)
            branches.sort(key=lambda x: x["commit_date"] if x["commit_date"] else "", reverse=True)
            
            # 기본 브랜치 찾기
            default_branch = self._get_default_branch(owner, repo)
            
            return {
                "success": True,
                "owner": owner,
                "repo": repo,
                "default_branch": default_branch,
                "branches": branches,
                "total": len(branches)
            }
            
        except Exception as e:
            return {"success": False, "error": str(e), "branches": []}
    
    def get_branch_diff(self, repo_url: str, base_branch: str, compare_branch: str) -> Dict:
        """
        두 브랜치 간 diff 가져오기
        
        Args:
            repo_url: GitHub 레포지토리 URL
            base_branch: 기준 브랜치 (예: main)
            compare_branch: 비교 브랜치 (예: feature/new-feature)
            
        Returns:
            diff 정보
        """
        try:
            owner, repo = self._parse_github_url(repo_url)
            if not owner or not repo:
                return {"success": False, "error": "Invalid GitHub URL"}
            
            # GitHub API로 비교 (브랜치명 URL 인코딩: feature/foo 등 슬래시 포함 케이스 대응)
            base_enc = urllib.parse.quote(base_branch, safe='')
            compare_enc = urllib.parse.quote(compare_branch, safe='')
            api_url = f"{self.api_base}/repos/{owner}/{repo}/compare/{base_enc}...{compare_enc}"
            
            response = requests.get(api_url, headers=self.headers)
            
            if response.status_code != 200:
                return {
                    "success": False, 
                    "error": f"Failed to get diff: {response.status_code}"
                }
            
            data = response.json()
            
            # 파일별 변경사항 정리
            files_changed = []
            total_additions = 0
            total_deletions = 0
            
            for file in data.get("files", []):
                # Python 파일만 필터링 (선택사항)
                if file["filename"].endswith(".py"):
                    file_info = {
                        "filename": file["filename"],
                        "status": file["status"],  # added, modified, removed, renamed
                        "additions": file["additions"],
                        "deletions": file["deletions"],
                        "changes": file["changes"],
                        "patch": file.get("patch", ""),  # diff 내용
                        "blob_url": file.get("blob_url", ""),
                        "raw_url": file.get("raw_url", ""),
                        "contents_url": file.get("contents_url", "")
                    }
                    
                    # 추가/수정된 라인만 추출
                    if file.get("patch"):
                        file_info["added_lines"] = self._extract_added_lines(file["patch"])
                        file_info["removed_lines"] = self._extract_removed_lines(file["patch"])
                    
                    files_changed.append(file_info)
                    total_additions += file["additions"]
                    total_deletions += file["deletions"]
            
            return {
                "success": True,
                "base_branch": base_branch,
                "compare_branch": compare_branch,
                "ahead_by": data.get("ahead_by", 0),
                "behind_by": data.get("behind_by", 0),
                "total_commits": data.get("total_commits", 0),
                "files_changed": files_changed,
                "total_files": len(files_changed),
                "total_additions": total_additions,
                "total_deletions": total_deletions,
                "mergeable": data.get("mergeable_state", "unknown"),
                "commits": self._extract_commit_info(data.get("commits", []))
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}

    def list_pull_requests(self, repo_url: str, state: str = "open") -> Dict:
        """
        PR 목록 조회 (기본: 오픈 상태 = 미병합 PR)

        Args:
            repo_url: GitHub 레포지토리 URL 또는 owner/repo 문자열 포함 URL
            state: open | closed | all

        Returns:
            { success, owner, repo, pull_requests: [ {number, title, user, created_at, updated_at, head, base} ], total }
        """
        try:
            owner, repo = self._parse_github_url(repo_url)
            if not owner or not repo:
                return {"success": False, "error": "Invalid GitHub URL", "pull_requests": []}

            api_url = f"{self.api_base}/repos/{owner}/{repo}/pulls"

            pulls = []
            page = 1
            while True:
                resp = requests.get(
                    api_url,
                    headers=self.headers,
                    params={"state": state, "page": page, "per_page": 100},
                )
                if resp.status_code != 200:
                    return {"success": False, "error": f"API error: {resp.status_code}", "pull_requests": []}

                page_items = resp.json() or []
                if not page_items:
                    break

                for pr in page_items:
                    pulls.append({
                        "number": pr.get("number"),
                        "title": pr.get("title", ""),
                        "user": (pr.get("user") or {}).get("login"),
                        "created_at": pr.get("created_at"),
                        "updated_at": pr.get("updated_at"),
                        "head": {
                            "ref": (pr.get("head") or {}).get("ref"),
                            "sha": (pr.get("head") or {}).get("sha"),
                            "repo": ((pr.get("head") or {}).get("repo") or {}).get("full_name"),
                        },
                        "base": {
                            "ref": (pr.get("base") or {}).get("ref"),
                            "sha": (pr.get("base") or {}).get("sha"),
                            "repo": ((pr.get("base") or {}).get("repo") or {}).get("full_name"),
                        },
                        "draft": pr.get("draft", False),
                        "mergeable": None,
                    })

                if len(page_items) < 100:
                    break
                page += 1

            # 최신 업데이트 순으로 정렬
            pulls.sort(key=lambda x: x.get("updated_at") or "", reverse=True)

            return {
                "success": True,
                "owner": owner,
                "repo": repo,
                "pull_requests": pulls,
                "total": len(pulls),
            }
        except Exception as e:
            return {"success": False, "error": str(e), "pull_requests": []}

    def get_pull_request_diff_code(self, repo_url: str, pull_number: int) -> Dict:
        """
        특정 PR의 변경 파일 목록과 코드 수집

        - 추가된 라인만 결합한 코드와 변경 파일의 전체 내용을 모두 제공
        - 전체 내용은 added/modified/renamed 파일에 대해서만 시도

        Returns:
            { success, file_analysis, combined_added_code, combined_full_code, base_ref, head_ref }
        """
        try:
            owner, repo = self._parse_github_url(repo_url)
            if not owner or not repo:
                return {"success": False, "error": "Invalid GitHub URL"}

            # PR 메타 정보 (base/head 브랜치명 확보)
            pr_url = f"{self.api_base}/repos/{owner}/{repo}/pulls/{pull_number}"
            pr_resp = requests.get(pr_url, headers=self.headers)
            if pr_resp.status_code != 200:
                return {"success": False, "error": f"PR fetch failed: {pr_resp.status_code}"}
            pr_data = pr_resp.json()
            base_ref = (pr_data.get("base") or {}).get("ref")
            head_ref = (pr_data.get("head") or {}).get("ref")

            # 파일 변경 목록 (pagination 대응)
            files_url = f"{self.api_base}/repos/{owner}/{repo}/pulls/{pull_number}/files"
            all_files = []
            page = 1
            while True:
                resp = requests.get(files_url, headers=self.headers, params={"page": page, "per_page": 100})
                if resp.status_code != 200:
                    return {"success": False, "error": f"Failed to get PR files: {resp.status_code}"}
                items = resp.json() or []
                if not items:
                    break
                all_files.extend(items)
                if len(items) < 100:
                    break
                page += 1

            file_analysis: List[Dict] = []
            combined_added_code_parts: List[str] = []
            combined_full_code_parts: List[str] = []

            for f in all_files:
                filename = f.get("filename", "")
                # Python 파일만 대상으로 제한
                if not filename.endswith('.py'):
                    continue
                status = f.get("status", "")
                additions = f.get("additions", 0)
                deletions = f.get("deletions", 0)
                patch = f.get("patch", "") or ""
                raw_url = f.get("raw_url") or ""
                contents_url = f.get("contents_url") or ""

                info = {
                    "filename": filename,
                    "status": status,
                    "additions": additions,
                    "deletions": deletions,
                }

                # 추가된 라인만 추출
                if patch:
                    info["added_lines"] = self._extract_added_lines(patch)
                    info["removed_lines"] = self._extract_removed_lines(patch)
                    if info["added_lines"]:
                        added_code = "\n".join(info["added_lines"]).strip()
                        if added_code:
                            info["added_code"] = added_code
                            combined_added_code_parts.append(f"# ===== File: {filename} =====\n{added_code}\n")

                # 변경/추가된 파일의 전체 내용 수집 시도
                if status in ["added", "modified", "renamed"]:
                    full_content = None
                    if raw_url:
                        full_content = self._get_file_content_raw(raw_url)
                    # contents_url 템플릿은 ?ref=sha 포함이므로 그대로 호출 시도
                    if full_content is None and contents_url:
                        try:
                            c_resp = requests.get(contents_url, headers=self.headers)
                            if c_resp.status_code == 200:
                                data = c_resp.json()
                                if data.get("encoding") == "base64":
                                    full_content = base64.b64decode(data.get("content", "")).decode("utf-8", errors="ignore")
                                elif data.get("download_url"):
                                    full_content = self._get_file_content_raw(data.get("download_url"))
                        except Exception:
                            full_content = None

                    if full_content:
                        info["full_content"] = full_content
                        combined_full_code_parts.append(f"# ===== File: {filename} =====\n{full_content}\n")

                file_analysis.append(info)

            return {
                "success": True,
                "file_analysis": file_analysis,
                "combined_added_code": "\n".join(combined_added_code_parts),
                "combined_full_code": "\n".join(combined_full_code_parts),
                "base_ref": base_ref,
                "head_ref": head_ref,
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_diff_code_only(self, repo_url: str, base_branch: str, compare_branch: str, 
                          selected_files: Optional[List[str]] = None) -> Dict:
        """
        선택된 파일들의 diff 코드만 추출
        
        Args:
            repo_url: GitHub 레포지토리 URL
            base_branch: 기준 브랜치
            compare_branch: 비교 브랜치
            selected_files: 분석할 파일 목록 (None이면 모든 변경 파일)
            
        Returns:
            diff 코드와 분석 정보
        """
        # 먼저 diff 가져오기
        diff_result = self.get_branch_diff(repo_url, base_branch, compare_branch)
        
        if not diff_result["success"]:
            return diff_result
        
        # 선택된 파일 필터링
        files_to_analyze = []
        if selected_files:
            for file_info in diff_result["files_changed"]:
                if file_info["filename"] in selected_files:
                    files_to_analyze.append(file_info)
        else:
            files_to_analyze = diff_result["files_changed"]
        
        # 추가/수정된 코드만 추출
        combined_added_code = []
        combined_full_code = []
        file_analysis = []
        
        for file_info in files_to_analyze:
            file_data = {
                "filename": file_info["filename"],
                "status": file_info["status"],
                "additions": file_info["additions"],
                "deletions": file_info["deletions"]
            }
            
            # 추가된 라인만 결합
            if "added_lines" in file_info and file_info["added_lines"]:
                added_code = "\n".join(file_info["added_lines"])
                file_data["added_code"] = added_code
                combined_added_code.append(f"# ===== File: {file_info['filename']} =====\n{added_code}\n")
            
            # 전체 파일 내용 가져오기 (필요시) - renamed 포함, 실패 시 raw_url 폴백
            if file_info["status"] in ["added", "modified", "renamed"]:
                full_content = self._get_file_content(repo_url, compare_branch, file_info["filename"])
                if not full_content and file_info.get("raw_url"):
                    full_content = self._get_file_content_raw(file_info["raw_url"])
                if full_content:
                    file_data["full_content"] = full_content
                    combined_full_code.append(f"# ===== File: {file_info['filename']} =====\n{full_content}\n")
            
            file_analysis.append(file_data)
        
        return {
            "success": True,
            "base_branch": base_branch,
            "compare_branch": compare_branch,
            "files_analyzed": len(file_analysis),
            "file_analysis": file_analysis,
            "combined_added_code": "\n".join(combined_added_code),  # 추가된 코드만
            "combined_full_code": "\n".join(combined_full_code),    # 전체 코드
            "summary": {
                "total_additions": sum(f["additions"] for f in file_analysis),
                "total_deletions": sum(f["deletions"] for f in file_analysis),
                "added_files": sum(1 for f in file_analysis if f["status"] == "added"),
                "modified_files": sum(1 for f in file_analysis if f["status"] == "modified"),
                "removed_files": sum(1 for f in file_analysis if f["status"] == "removed")
            }
        }
    
    def analyze_branch_security(self, repo_url: str, base_branch: str, compare_branch: str,
                               analyze_mode: str = "diff_only") -> Dict:
        """
        브랜치의 보안 분석 수행
        
        Args:
            repo_url: GitHub 레포지토리 URL
            base_branch: 기준 브랜치
            compare_branch: 비교 브랜치
            analyze_mode: "diff_only" (변경사항만) 또는 "full" (전체 파일)
            
        Returns:
            보안 분석 결과
        """
        # diff 코드 가져오기
        code_result = self.get_diff_code_only(repo_url, base_branch, compare_branch)
        
        if not code_result["success"]:
            return code_result
        
        # 분석할 코드 선택
        if analyze_mode == "diff_only":
            code_to_analyze = code_result["combined_added_code"]
            analysis_scope = "변경된 코드만 분석"
        else:
            code_to_analyze = code_result["combined_full_code"]
            analysis_scope = "변경된 파일 전체 분석"
        
        # 코드가 없으면
        if not code_to_analyze.strip():
            return {
                "success": True,
                "base_branch": base_branch,
                "compare_branch": compare_branch,
                "analysis_scope": analysis_scope,
                "files_analyzed": 0,
                "message": "분석할 Python 코드 변경사항이 없습니다",
                "security_issues": [],
                "summary": code_result.get("summary", {}),
                "recommendation": "✅ 변경사항이 없어 머지 가능합니다."
            }
        
        # 여기서 실제 보안 분석 수행 (기존 모듈 활용)
        try:
            from core.improved_llm_analyzer import ImprovedSecurityAnalyzer
            
            analyzer = ImprovedSecurityAnalyzer()
            security_result = analyzer.analyze_security(code_to_analyze)
            
            return {
                "success": True,
                "base_branch": base_branch,
                "compare_branch": compare_branch,
                "analysis_scope": analysis_scope,
                "files_analyzed": code_result["files_analyzed"],
                "summary": code_result["summary"],
                "security_analysis": security_result,
                "recommendation": self._generate_pr_recommendation(security_result)
            }
            
        except ImportError:
            # 보안 분석 모듈이 없는 경우 기본 분석
            return {
                "success": True,
                "base_branch": base_branch,
                "compare_branch": compare_branch,
                "analysis_scope": analysis_scope,
                "files_analyzed": code_result["files_analyzed"],
                "summary": code_result["summary"],
                "code_to_analyze": code_to_analyze,
                "message": "보안 분석 모듈을 로드할 수 없습니다. 코드만 추출했습니다."
            }
    
    def _parse_github_url(self, url: str) -> Tuple[Optional[str], Optional[str]]:
        """GitHub URL에서 owner와 repo 추출"""
        patterns = [
            r'github\.com[/:]([^/]+)/([^/\.]+)',
            r'github\.com/([^/]+)/([^/]+)/.*'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, url)
            if match:
                owner, repo = match.groups()[:2]
                # .git 제거
                repo = repo.replace('.git', '')
                return owner, repo
        
        return None, None
    
    def _get_default_branch(self, owner: str, repo: str) -> Optional[str]:
        """기본 브랜치 이름 가져오기"""
        try:
            api_url = f"{self.api_base}/repos/{owner}/{repo}"
            response = requests.get(api_url, headers=self.headers)
            
            if response.status_code == 200:
                return response.json().get("default_branch", "main")
        except:
            pass
        
        return "main"
    
    def _get_commit_date(self, commit_url: str) -> Optional[str]:
        """커밋 날짜 가져오기"""
        try:
            response = requests.get(commit_url, headers=self.headers)
            if response.status_code == 200:
                commit_data = response.json()
                return commit_data.get("commit", {}).get("author", {}).get("date")
        except:
            pass
        return None
    
    def _extract_added_lines(self, patch: str) -> List[str]:
        """diff에서 추가된 라인만 추출"""
        added_lines = []
        for line in patch.split('\n'):
            # +로 시작하는 라인 (+++는 제외)
            if line.startswith('+') and not line.startswith('+++'):
                added_lines.append(line[1:])  # + 기호 제거
        return added_lines
    
    def _extract_removed_lines(self, patch: str) -> List[str]:
        """diff에서 제거된 라인만 추출"""
        removed_lines = []
        for line in patch.split('\n'):
            # -로 시작하는 라인 (---는 제외)
            if line.startswith('-') and not line.startswith('---'):
                removed_lines.append(line[1:])  # - 기호 제거
        return removed_lines
    
    def _extract_commit_info(self, commits: List[Dict]) -> List[Dict]:
        """커밋 정보 추출"""
        commit_info = []
        for commit in commits[:10]:  # 최근 10개만
            commit_info.append({
                "sha": commit["sha"][:7],
                "message": commit["commit"]["message"].split('\n')[0],  # 첫 줄만
                "author": commit["commit"]["author"]["name"],
                "date": commit["commit"]["author"]["date"]
            })
        return commit_info
    
    def _get_file_content(self, repo_url: str, branch: str, filepath: str) -> Optional[str]:
        """특정 브랜치의 파일 내용 가져오기"""
        try:
            owner, repo = self._parse_github_url(repo_url)
            if not owner or not repo:
                return None
            
            # GitHub API로 파일 내용 가져오기
            encoded_path = urllib.parse.quote(filepath.lstrip('/'), safe='/')
            api_url = f"{self.api_base}/repos/{owner}/{repo}/contents/{encoded_path}"
            params = {"ref": branch}
            
            response = requests.get(api_url, headers=self.headers, params=params)
            
            if response.status_code == 200:
                data = response.json()
                # base64 디코딩
                if data.get("encoding") == "base64":
                    content = base64.b64decode(data["content"]).decode('utf-8', errors='ignore')
                    return content
                # download_url 폴백
                download_url = data.get('download_url')
                if download_url:
                    raw = self._get_file_content_raw(download_url)
                    if raw is not None:
                        return raw
            else:
                # 404/403 등일 때 raw 경로 폴백
                raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{urllib.parse.quote(branch, safe='')}/{encoded_path}"
                raw = self._get_file_content_raw(raw_url)
                if raw is not None:
                    return raw
            
        except Exception as e:
            print(f"파일 내용 가져오기 실패: {e}")
        
        return None

    def _get_file_content_raw(self, raw_url: str) -> Optional[str]:
        """raw_url로 파일 내용 가져오기 (대용량/특수 케이스 폴백)"""
        try:
            # raw.githubusercontent.com 도메인에서도 Authorization 헤더가 동작하는 경우가 있어 그대로 전달
            resp = requests.get(raw_url, headers=self.headers)
            if resp.status_code == 200:
                return resp.text
        except Exception as e:
            print(f"raw_url 콘텐츠 가져오기 실패: {e}")
        return None
    
    def _generate_pr_recommendation(self, security_result: Dict) -> str:
        """PR 머지 추천 생성"""
        if not security_result.get("vulnerabilities"):
            return "✅ 보안 이슈가 발견되지 않았습니다. 머지 가능합니다."
        
        critical = sum(1 for v in security_result["vulnerabilities"] 
                      if v.get("severity") == "CRITICAL")
        high = sum(1 for v in security_result["vulnerabilities"] 
                  if v.get("severity") == "HIGH")
        
        if critical > 0:
            return f"🚫 {critical}개의 심각한 보안 이슈가 발견되었습니다. 수정 후 머지하세요."
        elif high > 0:
            return f"⚠️ {high}개의 높은 위험도 이슈가 발견되었습니다. 검토 후 머지하세요."
        else:
            return "⚠️ 경미한 보안 이슈가 발견되었습니다. 검토 후 머지 가능합니다."
    
    def cleanup(self):
        """임시 파일 정리"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
            except:
                pass


class BranchDiffSelector:
    """브랜치 diff 파일 선택 헬퍼"""
    
    @staticmethod
    def filter_by_status(files: List[Dict], statuses: List[str]) -> List[Dict]:
        """
        상태별 파일 필터링
        
        Args:
            files: 파일 목록
            statuses: ["added", "modified", "removed"]
        """
        return [f for f in files if f.get("status") in statuses]
    
    @staticmethod
    def filter_by_size(files: List[Dict], max_changes: int = 500) -> List[Dict]:
        """변경 크기별 필터링"""
        return [f for f in files if f.get("changes", 0) <= max_changes]
    
    @staticmethod
    def filter_by_pattern(files: List[Dict], patterns: List[str]) -> List[Dict]:
        """파일 패턴별 필터링"""
        filtered = []
        for file in files:
            filename = file.get("filename", "")
            for pattern in patterns:
                if pattern in filename:
                    filtered.append(file)
                    break
        return filtered
    
    @staticmethod
    def get_security_critical_files(files: List[Dict]) -> List[Dict]:
        """보안상 중요한 파일만 선택"""
        critical_patterns = [
            'auth', 'login', 'security', 'password', 'token',
            'api', 'admin', 'config', 'settings', 'env',
            'database', 'db', 'sql', 'orm',
            'middleware', 'permission', 'role'
        ]
        
        critical_files = []
        for file in files:
            filename = file.get("filename", "").lower()
            for pattern in critical_patterns:
                if pattern in filename:
                    critical_files.append(file)
                    break
        
        return critical_files