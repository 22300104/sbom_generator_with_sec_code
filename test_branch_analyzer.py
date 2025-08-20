# test_branch_analyzer.py
"""
GitHub 브랜치 분석기 테스트 코드
"""
import os
import json
from pathlib import Path
from dotenv import load_dotenv

# .env 로드
load_dotenv()

# 프로젝트 경로 설정
import sys
sys.path.insert(0, str(Path(__file__).parent))

from core.github_branch_analyzer import GitHubBranchAnalyzer, BranchDiffSelector


def test_get_branches():
    """브랜치 목록 가져오기 테스트"""
    print("\n" + "="*80)
    print("🌿 테스트 1: 브랜치 목록 가져오기")
    print("="*80)
    
    analyzer = GitHubBranchAnalyzer()
    
    # 테스트할 공개 레포지토리들
    test_repos = [
        "https://github.com/python/cpython",  # 큰 프로젝트
        "https://github.com/pallets/flask",   # 중간 프로젝트
    ]
    
    for repo_url in test_repos:
        print(f"\n📦 레포지토리: {repo_url}")
        result = analyzer.get_branches(repo_url)
        
        if result["success"]:
            print(f"✅ 성공: {result['total']}개 브랜치 발견")
            print(f"   - Owner: {result['owner']}")
            print(f"   - Repo: {result['repo']}")
            print(f"   - 기본 브랜치: {result['default_branch']}")
            
            # 상위 5개 브랜치 출력
            print("   - 최근 브랜치 (상위 5개):")
            for branch in result["branches"][:5]:
                date = branch["commit_date"][:10] if branch["commit_date"] else "Unknown"
                protected = "🔒" if branch["protected"] else ""
                print(f"     • {branch['name']:<30} {date} {protected}")
        else:
            print(f"❌ 실패: {result['error']}")
    
    return analyzer


def test_branch_diff():
    """브랜치 diff 비교 테스트"""
    print("\n" + "="*80)
    print("🔍 테스트 2: 브랜치 간 Diff 비교")
    print("="*80)
    
    analyzer = GitHubBranchAnalyzer()
    
    # Flask 프로젝트로 테스트 (작은 변경사항이 있을 가능성이 높음)
    repo_url = "https://github.com/pallets/flask"
    
    # 먼저 브랜치 목록 가져오기
    branches_result = analyzer.get_branches(repo_url)
    
    if not branches_result["success"]:
        print("❌ 브랜치 목록을 가져올 수 없습니다")
        return
    
    # 기본 브랜치와 다른 브랜치 비교
    base_branch = branches_result["default_branch"]
    branches = branches_result["branches"]
    
    # 기본 브랜치가 아닌 첫 번째 브랜치 찾기
    compare_branch = None
    for branch in branches:
        if branch["name"] != base_branch:
            compare_branch = branch["name"]
            break
    
    if not compare_branch:
        print("비교할 브랜치가 없습니다")
        # 테스트용 가상 브랜치로 시도
        compare_branch = "2.3.x"  # Flask의 일반적인 브랜치
    
    print(f"\n📊 비교: {base_branch} ← {compare_branch}")
    
    diff_result = analyzer.get_branch_diff(repo_url, base_branch, compare_branch)
    
    if diff_result["success"]:
        print(f"✅ Diff 분석 성공")
        print(f"   - 커밋 차이: {diff_result['ahead_by']} ahead, {diff_result['behind_by']} behind")
        print(f"   - 변경된 Python 파일: {diff_result['total_files']}개")
        print(f"   - 추가: +{diff_result['total_additions']}, 삭제: -{diff_result['total_deletions']}")
        
        # 변경된 파일 목록 (상위 5개)
        if diff_result["files_changed"]:
            print("\n   변경된 파일 (상위 5개):")
            for file in diff_result["files_changed"][:5]:
                status_emoji = {
                    "added": "✨",
                    "modified": "📝",
                    "removed": "🗑️",
                    "renamed": "📛"
                }.get(file["status"], "❓")
                
                print(f"     {status_emoji} {file['filename']}")
                print(f"        +{file['additions']} -{file['deletions']}")
                
                # 추가된 코드 일부 보기
                if "added_lines" in file and file["added_lines"]:
                    print(f"        추가된 라인 예시: {file['added_lines'][0][:50]}...")
        
        # 최근 커밋 정보
        if diff_result.get("commits"):
            print("\n   최근 커밋:")
            for commit in diff_result["commits"][:3]:
                print(f"     • {commit['sha']} - {commit['message'][:50]}")
                print(f"       by {commit['author']} on {commit['date'][:10]}")
    else:
        print(f"❌ Diff 분석 실패: {diff_result['error']}")
    
    return analyzer, diff_result


def test_diff_code_extraction():
    """Diff 코드 추출 테스트"""
    print("\n" + "="*80)
    print("📝 테스트 3: Diff 코드 추출 및 선택")
    print("="*80)
    
    analyzer = GitHubBranchAnalyzer()
    
    # 작은 프로젝트로 테스트
    repo_url = "https://github.com/pallets/flask"
    base_branch = "main"
    compare_branch = "2.3.x"  # 또는 실제 존재하는 브랜치
    
    print(f"📊 {base_branch} ← {compare_branch} 코드 추출")
    
    # 전체 diff 코드 가져오기
    code_result = analyzer.get_diff_code_only(repo_url, base_branch, compare_branch)
    
    if code_result["success"]:
        print(f"✅ 코드 추출 성공")
        print(f"   - 분석된 파일: {code_result['files_analyzed']}개")
        print(f"   - 추가된 파일: {code_result['summary']['added_files']}")
        print(f"   - 수정된 파일: {code_result['summary']['modified_files']}")
        print(f"   - 추가된 라인: +{code_result['summary']['total_additions']}")
        print(f"   - 삭제된 라인: -{code_result['summary']['total_deletions']}")
        
        # 추가된 코드 크기
        added_code_size = len(code_result["combined_added_code"])
        full_code_size = len(code_result["combined_full_code"])
        
        print(f"\n   코드 크기:")
        print(f"   - 추가된 코드만: {added_code_size:,} 문자")
        print(f"   - 전체 파일 코드: {full_code_size:,} 문자")
        
        # 코드 샘플 출력
        if code_result["combined_added_code"]:
            print("\n   추가된 코드 샘플 (처음 500자):")
            print("   " + "-"*50)
            sample = code_result["combined_added_code"][:500]
            for line in sample.split('\n')[:10]:
                print(f"   {line}")
            print("   " + "-"*50)
        
        # 파일별 분석 정보
        if code_result["file_analysis"]:
            print("\n   파일별 상세 분석 (상위 3개):")
            for file_data in code_result["file_analysis"][:3]:
                print(f"\n   📄 {file_data['filename']}")
                print(f"      상태: {file_data['status']}")
                print(f"      변경: +{file_data['additions']} -{file_data['deletions']}")
                if "added_code" in file_data:
                    code_preview = file_data["added_code"][:100]
                    print(f"      코드: {code_preview}...")
    else:
        print(f"❌ 코드 추출 실패: {code_result.get('error')}")
    
    return code_result


def test_file_selection():
    """파일 선택 기능 테스트"""
    print("\n" + "="*80)
    print("📂 테스트 4: Diff 파일 선택 기능")
    print("="*80)
    
    # 임시 테스트 데이터
    test_files = [
        {"filename": "app/auth.py", "status": "modified", "changes": 50, "additions": 30, "deletions": 20},
        {"filename": "app/models.py", "status": "modified", "changes": 100, "additions": 80, "deletions": 20},
        {"filename": "tests/test_auth.py", "status": "added", "changes": 200, "additions": 200, "deletions": 0},
        {"filename": "config.py", "status": "modified", "changes": 10, "additions": 5, "deletions": 5},
        {"filename": "utils/helpers.py", "status": "modified", "changes": 1000, "additions": 500, "deletions": 500},
        {"filename": "README.md", "status": "modified", "changes": 5, "additions": 3, "deletions": 2},
    ]
    
    selector = BranchDiffSelector()
    
    # 1. 상태별 필터링
    print("\n1️⃣ 수정된 파일만 선택:")
    modified_files = selector.filter_by_status(test_files, ["modified"])
    for f in modified_files:
        print(f"   • {f['filename']}")
    
    # 2. 크기별 필터링
    print("\n2️⃣ 작은 변경사항만 선택 (100줄 이하):")
    small_files = selector.filter_by_size(test_files, max_changes=100)
    for f in small_files:
        print(f"   • {f['filename']} ({f['changes']} changes)")
    
    # 3. 보안 중요 파일만
    print("\n3️⃣ 보안상 중요한 파일만 선택:")
    critical_files = selector.get_security_critical_files(test_files)
    for f in critical_files:
        print(f"   • {f['filename']} ⚠️")
    
    # 4. 패턴별 필터링
    print("\n4️⃣ 특정 패턴 파일 선택 (app/, config):")
    pattern_files = selector.filter_by_pattern(test_files, ["app/", "config"])
    for f in pattern_files:
        print(f"   • {f['filename']}")


def test_security_analysis():
    """브랜치 보안 분석 테스트"""
    print("\n" + "="*80)
    print("🔒 테스트 5: 브랜치 보안 분석")
    print("="*80)
    
    analyzer = GitHubBranchAnalyzer()
    
    # 테스트용 레포 (작은 프로젝트 권장)
    repo_url = "https://github.com/pallets/flask"
    base_branch = "main"
    compare_branch = "2.3.x"
    
    print(f"🔍 보안 분석: {base_branch} ← {compare_branch}")
    print("   (변경된 코드만 분석)")
    
    # Diff만 분석
    result = analyzer.analyze_branch_security(
        repo_url, 
        base_branch, 
        compare_branch,
        analyze_mode="diff_only"
    )
    
    if result["success"]:
        print(f"\n✅ 분석 완료")
        print(f"   - 분석 범위: {result['analysis_scope']}")
        print(f"   - 분석된 파일: {result['files_analyzed']}개")
        
        if "security_analysis" in result:
            security = result["security_analysis"]
            
            if security.get("vulnerabilities"):
                print(f"\n   🚨 보안 이슈 발견: {len(security['vulnerabilities'])}개")
                
                for vuln in security["vulnerabilities"][:3]:  # 상위 3개만
                    print(f"\n   [{vuln.get('severity', 'UNKNOWN')}] {vuln.get('type', 'Unknown')}")
                    print(f"      위치: {vuln.get('location', {}).get('file', 'unknown')}")
                    print(f"      설명: {vuln.get('description', '')[:100]}...")
            else:
                print("\n   ✅ 보안 이슈가 발견되지 않았습니다")
            
            if security.get("security_score") is not None:
                score = security["security_score"]
                print(f"\n   📊 보안 점수: {score}/100")
        
        # PR 추천사항
        if "recommendation" in result:
            print(f"\n   💡 추천: {result['recommendation']}")
    else:
        print(f"❌ 분석 실패: {result.get('error', 'Unknown error')}")


def test_private_repo():
    """Private 레포지토리 테스트 (토큰 필요)"""
    print("\n" + "="*80)
    print("🔐 테스트 6: Private 레포지토리 접근")
    print("="*80)
    
    github_token = os.getenv("GITHUB_TOKEN")
    
    if not github_token:
        print("⚠️ GITHUB_TOKEN이 설정되지 않았습니다.")
        print("   Private 레포 테스트를 건너뜁니다.")
        print("\n   토큰 설정 방법:")
        print("   1. GitHub Settings → Developer settings → Personal access tokens")
        print("   2. Generate new token (repo 권한 필요)")
        print("   3. .env 파일에 GITHUB_TOKEN=your_token 추가")
        return
    
    analyzer = GitHubBranchAnalyzer(github_token=github_token)
    
    # Private 레포 URL (자신의 private 레포로 변경)
    private_repo = "https://github.com/your-username/your-private-repo"
    
    print(f"🔍 Private 레포 접근 시도: {private_repo}")
    result = analyzer.get_branches(private_repo)
    
    if result["success"]:
        print(f"✅ 접근 성공: {result['total']}개 브랜치")
    else:
        print(f"❌ 접근 실패: {result['error']}")


def run_all_tests():
    """모든 테스트 실행"""
    print("\n" + "🚀 GitHub 브랜치 분석기 종합 테스트 " + "="*40)
    
    tests = [
        ("브랜치 목록 가져오기", test_get_branches),
        ("브랜치 Diff 비교", test_branch_diff),
        ("Diff 코드 추출", test_diff_code_extraction),
        ("파일 선택 기능", test_file_selection),
        ("보안 분석", test_security_analysis),
        ("Private 레포 접근", test_private_repo)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            print(f"\n\n{'='*80}")
            print(f"🧪 {test_name} 테스트")
            print('='*80)
            test_func()
            results.append((test_name, "✅ 성공"))
        except Exception as e:
            print(f"\n❌ 테스트 실패: {e}")
            results.append((test_name, f"❌ 실패: {str(e)[:50]}"))
    
    # 결과 요약
    print("\n\n" + "="*80)
    print("📊 테스트 결과 요약")
    print("="*80)
    
    for test_name, result in results:
        print(f"  {test_name}: {result}")
    
    success_count = sum(1 for _, r in results if "✅" in r)
    total_count = len(results)
    
    print(f"\n총 {total_count}개 중 {success_count}개 성공")
    
    if success_count == total_count:
        print("🎉 모든 테스트 통과!")
    else:
        print(f"⚠️ {total_count - success_count}개 테스트 실패")


def interactive_test():
    """대화형 테스트 모드"""
    print("\n" + "="*80)
    print("🎮 대화형 브랜치 분석 테스트")
    print("="*80)
    
    analyzer = GitHubBranchAnalyzer()
    
    # 레포 입력
    repo_url = input("\nGitHub 레포지토리 URL 입력 (엔터: 기본값 사용): ").strip()
    if not repo_url:
        repo_url = "https://github.com/pallets/flask"
        print(f"기본값 사용: {repo_url}")
    
    # 브랜치 목록 가져오기
    print("\n브랜치 목록을 가져오는 중...")
    branches_result = analyzer.get_branches(repo_url)
    
    if not branches_result["success"]:
        print(f"❌ 실패: {branches_result['error']}")
        return
    
    # 브랜치 선택
    print(f"\n사용 가능한 브랜치 ({branches_result['total']}개):")
    for i, branch in enumerate(branches_result["branches"][:10], 1):
        print(f"  {i}. {branch['name']}")
    
    print(f"\n기본 브랜치: {branches_result['default_branch']}")
    
    base_branch = input("기준 브랜치 (엔터: 기본 브랜치): ").strip()
    if not base_branch:
        base_branch = branches_result["default_branch"]
    
    compare_branch = input("비교할 브랜치: ").strip()
    if not compare_branch:
        print("비교할 브랜치를 입력해주세요")
        return
    
    # Diff 가져오기
    print(f"\n{base_branch} ← {compare_branch} 비교 중...")
    diff_result = analyzer.get_branch_diff(repo_url, base_branch, compare_branch)
    
    if not diff_result["success"]:
        print(f"❌ 실패: {diff_result['error']}")
        return
    
    print(f"\n✅ 변경사항:")
    print(f"  - 파일: {diff_result['total_files']}개")
    print(f"  - 추가: +{diff_result['total_additions']}")
    print(f"  - 삭제: -{diff_result['total_deletions']}")
    
    # 파일 선택
    if diff_result["files_changed"]:
        print("\n변경된 파일:")
        for i, file in enumerate(diff_result["files_changed"], 1):
            print(f"  {i}. {file['filename']} (+{file['additions']} -{file['deletions']})")
        
        selection = input("\n분석할 파일 번호 (콤마 구분, 엔터: 전체): ").strip()
        
        selected_files = None
        if selection:
            try:
                indices = [int(x.strip()) - 1 for x in selection.split(',')]
                selected_files = [diff_result["files_changed"][i]["filename"] 
                                for i in indices if 0 <= i < len(diff_result["files_changed"])]
            except:
                print("잘못된 입력입니다. 전체 파일을 분석합니다.")
        
        # 분석 모드 선택
        mode = input("\n분석 모드 (1: 변경사항만, 2: 전체 파일) [기본: 1]: ").strip()
        analyze_mode = "full" if mode == "2" else "diff_only"
        
        # 보안 분석
        print("\n🔍 보안 분석 중...")
        result = analyzer.analyze_branch_security(
            repo_url, 
            base_branch, 
            compare_branch,
            analyze_mode=analyze_mode
        )
        
        if result["success"]:
            print(f"\n✅ 분석 완료")
            
            if "security_analysis" in result:
                security = result["security_analysis"]
                if security.get("vulnerabilities"):
                    print(f"\n🚨 {len(security['vulnerabilities'])}개 보안 이슈 발견")
                else:
                    print("\n✅ 보안 이슈 없음")
                
                if security.get("security_score") is not None:
                    print(f"📊 보안 점수: {security['security_score']}/100")
            
            if "recommendation" in result:
                print(f"\n💡 {result['recommendation']}")
        else:
            print(f"❌ 분석 실패: {result.get('error')}")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="GitHub 브랜치 분석기 테스트")
    parser.add_argument('--test', type=int, help='특정 테스트만 실행 (1-6)')
    parser.add_argument('--all', action='store_true', help='모든 테스트 실행')
    parser.add_argument('--interactive', action='store_true', help='대화형 모드')
    
    args = parser.parse_args()
    
    if args.interactive:
        interactive_test()
    elif args.test:
        if args.test == 1:
            test_get_branches()
        elif args.test == 2:
            test_branch_diff()
        elif args.test == 3:
            test_diff_code_extraction()
        elif args.test == 4:
            test_file_selection()
        elif args.test == 5:
            test_security_analysis()
        elif args.test == 6:
            test_private_repo()
        else:
            print("❌ 잘못된 테스트 번호입니다. 1-6 중 선택하세요.")
    else:
        run_all_tests()