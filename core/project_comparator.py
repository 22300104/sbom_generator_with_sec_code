"""
프로젝트 비교 분석 모듈
여러 프로젝트의 보안 수준을 비교
"""
import json
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import hashlib
from pathlib import Path


class ProjectComparator:
    """프로젝트 간 보안 수준 비교"""
    
    def __init__(self):
        self.projects = {}
        self.comparison_results = {}
    
    def add_project(self, name: str, analysis_results: Dict, metadata: Dict = None):
        """비교할 프로젝트 추가"""
        project_id = hashlib.md5(name.encode()).hexdigest()[:8]
        
        self.projects[project_id] = {
            'name': name,
            'analyzed_at': datetime.now().isoformat(),
            'metadata': metadata or {},
            'results': analysis_results,
            'metrics': self._calculate_metrics(analysis_results)
        }
        
        return project_id
    
    def _calculate_metrics(self, results: Dict) -> Dict:
        """프로젝트 메트릭 계산"""
        metrics = {
            'security_score': 0,
            'vulnerabilities': {
                'total': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            },
            'dependencies': {
                'total': 0,
                'vulnerable': 0,
                'outdated': 0
            },
            'code_quality': {
                'lines': 0,
                'files': 0,
                'test_coverage': False,
                'documentation': False
            },
            'compliance': {
                'has_security_policy': False,
                'has_dependency_check': False,
                'uses_secure_defaults': False
            }
        }
        
        # 보안 점수
        if 'security' in results:
            metrics['security_score'] = results['security'].get('security_score', 0)
            
            # 취약점 카운트
            vulns = results['security'].get('code_vulnerabilities', [])
            metrics['vulnerabilities']['total'] = len(vulns)
            
            for vuln in vulns:
                severity = vuln.get('severity', 'MEDIUM').lower()
                if severity in metrics['vulnerabilities']:
                    metrics['vulnerabilities'][severity] += 1
        
        # 의존성 메트릭
        if 'dependencies' in results:
            deps = results['dependencies']
            metrics['dependencies']['total'] = deps.get('summary', {}).get('external_packages', 0)
        
        # 알려진 취약점
        if 'vulnerabilities' in results:
            vuln_stats = results['vulnerabilities'].get('statistics', {})
            metrics['dependencies']['vulnerable'] = len(
                results['vulnerabilities'].get('direct_vulnerabilities', {})
            )
        
        # 코드 품질
        if 'project_data' in results:
            stats = results['project_data'].get('statistics', {})
            metrics['code_quality']['lines'] = stats.get('total_lines', 0)
            metrics['code_quality']['files'] = stats.get('total_files', 0)
        
        # 구조 분석
        if 'structure' in results:
            patterns = results['structure'].get('patterns', [])
            metrics['code_quality']['test_coverage'] = any('테스트' in p for p in patterns)
            metrics['compliance']['has_security_policy'] = any('인증' in p or '미들웨어' in p for p in patterns)
        
        return metrics
    
    def compare_projects(self, project_ids: List[str] = None) -> Dict:
        """프로젝트들 비교"""
        
        if not project_ids:
            project_ids = list(self.projects.keys())
        
        if len(project_ids) < 2:
            return {'error': '비교하려면 최소 2개의 프로젝트가 필요합니다'}
        
        comparison = {
            'projects': [],
            'rankings': {},
            'insights': [],
            'recommendations': []
        }
        
        # 각 프로젝트 정보 수집
        for pid in project_ids:
            if pid in self.projects:
                project = self.projects[pid]
                comparison['projects'].append({
                    'id': pid,
                    'name': project['name'],
                    'metrics': project['metrics']
                })
        
        # 랭킹 계산
        comparison['rankings'] = self._calculate_rankings(comparison['projects'])
        
        # 인사이트 생성
        comparison['insights'] = self._generate_insights(comparison['projects'])
        
        # 권장사항 생성
        comparison['recommendations'] = self._generate_recommendations(comparison['projects'])
        
        self.comparison_results = comparison
        return comparison
    
    def _calculate_rankings(self, projects: List[Dict]) -> Dict:
        """각 메트릭별 순위 계산"""
        rankings = {
            'security_score': [],
            'vulnerability_count': [],
            'dependency_health': [],
            'code_quality': [],
            'overall': []
        }
        
        # 보안 점수 순위
        projects_sorted = sorted(
            projects, 
            key=lambda x: x['metrics']['security_score'], 
            reverse=True
        )
        rankings['security_score'] = [
            {'name': p['name'], 'score': p['metrics']['security_score']} 
            for p in projects_sorted
        ]
        
        # 취약점 수 순위 (적을수록 좋음)
        projects_sorted = sorted(
            projects, 
            key=lambda x: x['metrics']['vulnerabilities']['total']
        )
        rankings['vulnerability_count'] = [
            {'name': p['name'], 'count': p['metrics']['vulnerabilities']['total']} 
            for p in projects_sorted
        ]
        
        # 의존성 건강도
        for project in projects:
            total_deps = project['metrics']['dependencies']['total']
            vulnerable_deps = project['metrics']['dependencies']['vulnerable']
            health_score = 100 - (vulnerable_deps / max(total_deps, 1) * 100) if total_deps > 0 else 100
            project['dependency_health'] = health_score
        
        projects_sorted = sorted(
            projects, 
            key=lambda x: x.get('dependency_health', 0) if x.get('dependency_health') is not None else 0, 
            reverse=True
        )
        rankings['dependency_health'] = [
            {
                'name': p['name'], 
                'health': f"{p.get('dependency_health', 0):.1f}%" if p.get('dependency_health') is not None else "N/A"
            } 
            for p in projects_sorted
        ]
        
        # 전체 순위 (가중 평균)
        for project in projects:
            dep_health = project.get('dependency_health', 0) if project.get('dependency_health') is not None else 0
            overall_score = (
                project['metrics']['security_score'] * 0.4 +
                (100 - min(project['metrics']['vulnerabilities']['total'] * 5, 100)) * 0.3 +
                dep_health * 0.2 +
                (10 if project['metrics']['code_quality']['test_coverage'] else 0)
            )
            project['overall_score'] = overall_score
        
        projects_sorted = sorted(
            projects, 
            key=lambda x: x.get('overall_score', 0) if x.get('overall_score') is not None else 0, 
            reverse=True
        )
        rankings['overall'] = [
            {
                'name': p['name'], 
                'score': f"{p.get('overall_score', 0):.1f}" if p.get('overall_score') is not None else "0.0"
            } 
            for p in projects_sorted
        ]
        
        return rankings
    
    def _generate_insights(self, projects: List[Dict]) -> List[str]:
        """비교 인사이트 생성"""
        insights = []
        
        # 최고/최저 보안 점수
        scores = [p['metrics']['security_score'] for p in projects]
        if scores:
            best = max(scores)
            worst = min(scores)
            best_project = next(p for p in projects if p['metrics']['security_score'] == best)
            worst_project = next(p for p in projects if p['metrics']['security_score'] == worst)
            
            insights.append(
                f"🏆 {best_project['name']}이(가) 가장 높은 보안 점수({best}/100)를 기록했습니다."
            )
            
            if best != worst:
                insights.append(
                    f"⚠️ {worst_project['name']}은(는) 보안 개선이 필요합니다 (점수: {worst}/100)."
                )
        
        # 취약점 분석
        total_vulns = sum(p['metrics']['vulnerabilities']['total'] for p in projects)
        critical_vulns = sum(p['metrics']['vulnerabilities']['critical'] for p in projects)
        
        if total_vulns > 0:
            insights.append(f"📊 전체 프로젝트에서 총 {total_vulns}개의 취약점이 발견되었습니다.")
            
            if critical_vulns > 0:
                insights.append(f"🚨 {critical_vulns}개의 치명적 취약점이 즉시 수정이 필요합니다.")
        
        # 의존성 분석
        total_deps = sum(p['metrics']['dependencies']['total'] for p in projects)
        vulnerable_deps = sum(p['metrics']['dependencies']['vulnerable'] for p in projects)
        
        if vulnerable_deps > 0 and total_deps > 0:
            vuln_ratio = (vulnerable_deps / total_deps) * 100
            insights.append(
                f"📦 전체 의존성의 {vuln_ratio:.1f}%에서 알려진 취약점이 발견되었습니다."
            )
        
        # 테스트 커버리지
        with_tests = sum(1 for p in projects if p['metrics']['code_quality']['test_coverage'])
        if with_tests < len(projects):
            insights.append(
                f"🧪 {len(projects) - with_tests}개 프로젝트에 테스트 코드가 없습니다."
            )
        
        return insights
    
    def _generate_recommendations(self, projects: List[Dict]) -> List[Dict]:
        """프로젝트별 개선 권장사항"""
        recommendations = []
        
        for project in projects:
            project_recs = {
                'name': project['name'],
                'priority_actions': [],
                'improvements': []
            }
            
            metrics = project['metrics']
            
            # 우선 조치사항
            if metrics['vulnerabilities']['critical'] > 0:
                project_recs['priority_actions'].append(
                    f"🔴 {metrics['vulnerabilities']['critical']}개의 치명적 취약점 즉시 수정"
                )
            
            if metrics['vulnerabilities']['high'] > 0:
                project_recs['priority_actions'].append(
                    f"🟠 {metrics['vulnerabilities']['high']}개의 높은 위험 취약점 수정"
                )
            
            if metrics['dependencies']['vulnerable'] > 0:
                project_recs['priority_actions'].append(
                    f"📦 {metrics['dependencies']['vulnerable']}개의 취약한 패키지 업데이트"
                )
            
            # 개선사항
            if metrics['security_score'] < 70:
                project_recs['improvements'].append("보안 코드 리뷰 실시")
            
            if not metrics['code_quality']['test_coverage']:
                project_recs['improvements'].append("단위 테스트 및 보안 테스트 추가")
            
            if not metrics['compliance']['has_security_policy']:
                project_recs['improvements'].append("보안 정책 및 인증 모듈 구현")
            
            if metrics['dependencies']['total'] > 50:
                project_recs['improvements'].append("의존성 최소화 검토")
            
            recommendations.append(project_recs)
        
        return recommendations
    
    def generate_comparison_report(self) -> str:
        """비교 보고서 생성"""
        if not self.comparison_results:
            return "비교 결과가 없습니다."
        
        report = []
        report.append("# 프로젝트 보안 비교 분석 보고서\n")
        report.append(f"생성 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # 프로젝트 목록
        report.append("## 분석 대상 프로젝트\n")
        for project in self.comparison_results['projects']:
            report.append(f"- {project['name']}\n")
        report.append("\n")
        
        # 순위
        report.append("## 프로젝트 순위\n\n")
        
        rankings = self.comparison_results['rankings']
        
        report.append("### 🏆 전체 순위\n")
        for i, item in enumerate(rankings['overall'], 1):
            report.append(f"{i}. {item['name']} (점수: {item['score']})\n")
        report.append("\n")
        
        report.append("### 📊 보안 점수\n")
        for item in rankings['security_score']:
            report.append(f"- {item['name']}: {item['score']}/100\n")
        report.append("\n")
        
        report.append("### 🛡️ 취약점 수 (적을수록 좋음)\n")
        for item in rankings['vulnerability_count']:
            report.append(f"- {item['name']}: {item['count']}개\n")
        report.append("\n")
        
        # 인사이트
        report.append("## 주요 발견사항\n")
        for insight in self.comparison_results['insights']:
            report.append(f"- {insight}\n")
        report.append("\n")
        
        # 권장사항
        report.append("## 프로젝트별 권장사항\n")
        for rec in self.comparison_results['recommendations']:
            report.append(f"\n### {rec['name']}\n")
            
            if rec['priority_actions']:
                report.append("**우선 조치사항:**\n")
                for action in rec['priority_actions']:
                    report.append(f"- {action}\n")
            
            if rec['improvements']:
                report.append("\n**개선사항:**\n")
                for improvement in rec['improvements']:
                    report.append(f"- {improvement}\n")
        
        return ''.join(report)
    
    def export_comparison(self, format: str = 'json') -> str:
        """비교 결과 내보내기"""
        if format == 'json':
            return json.dumps(self.comparison_results, indent=2, default=str)
        elif format == 'markdown':
            return self.generate_comparison_report()
        else:
            raise ValueError(f"Unsupported format: {format}")


# 테스트
if __name__ == "__main__":
    comparator = ProjectComparator()
    
    # 테스트 데이터
    project1_results = {
        'security': {
            'security_score': 85,
            'code_vulnerabilities': [
                {'severity': 'HIGH'},
                {'severity': 'MEDIUM'}
            ]
        },
        'dependencies': {
            'summary': {'external_packages': 15}
        }
    }
    
    project2_results = {
        'security': {
            'security_score': 65,
            'code_vulnerabilities': [
                {'severity': 'CRITICAL'},
                {'severity': 'HIGH'},
                {'severity': 'HIGH'},
                {'severity': 'MEDIUM'}
            ]
        },
        'dependencies': {
            'summary': {'external_packages': 25}
        }
    }
    
    # 프로젝트 추가
    id1 = comparator.add_project("Safe Project", project1_results)
    id2 = comparator.add_project("Risky Project", project2_results)
    
    # 비교
    comparison = comparator.compare_projects()
    
    # 보고서 생성
    report = comparator.generate_comparison_report()
    print(report)