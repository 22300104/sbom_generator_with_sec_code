"""
분석 히스토리 관리 모듈
분석 결과를 저장하고 시간에 따른 변화 추적
"""
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import hashlib


class AnalysisHistory:
    """분석 결과 히스토리 관리"""
    
    def __init__(self, db_path: str = "data/analysis_history.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(exist_ok=True)
        self._init_database()
    
    def _init_database(self):
        """데이터베이스 초기화"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 분석 히스토리 테이블
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analysis_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_name TEXT NOT NULL,
                project_type TEXT,  -- 'github', 'upload', 'direct'
                project_url TEXT,
                analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                security_score INTEGER,
                vulnerability_count INTEGER,
                critical_count INTEGER,
                high_count INTEGER,
                package_count INTEGER,
                file_count INTEGER,
                line_count INTEGER,
                analysis_results TEXT,  -- JSON
                metadata TEXT  -- JSON
            )
        """)
        
        # 취약점 추적 테이블
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerability_tracking (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id INTEGER,
                vulnerability_type TEXT,
                severity TEXT,
                location TEXT,
                status TEXT DEFAULT 'open',  -- 'open', 'fixed', 'ignored'
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                fixed_at TIMESTAMP,
                FOREIGN KEY (analysis_id) REFERENCES analysis_history(id)
            )
        """)
        
        # 인덱스 생성
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_project_name 
            ON analysis_history(project_name)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_analyzed_at 
            ON analysis_history(analyzed_at)
        """)
        
        conn.commit()
        conn.close()
    
    def save_analysis(self, 
                     project_name: str,
                     analysis_results: Dict,
                     project_type: str = 'direct',
                     project_url: str = None) -> int:
        """분석 결과 저장"""
        
        # 메트릭 추출
        metrics = self._extract_metrics(analysis_results)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO analysis_history (
                project_name, project_type, project_url,
                security_score, vulnerability_count,
                critical_count, high_count,
                package_count, file_count, line_count,
                analysis_results, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            project_name,
            project_type,
            project_url,
            metrics['security_score'],
            metrics['vulnerability_count'],
            metrics['critical_count'],
            metrics['high_count'],
            metrics['package_count'],
            metrics['file_count'],
            metrics['line_count'],
            json.dumps(analysis_results),
            json.dumps(metrics['metadata'])
        ))
        
        analysis_id = cursor.lastrowid
        
        # 취약점 추적
        if 'security' in analysis_results:
            vulns = analysis_results['security'].get('code_vulnerabilities', [])
            for vuln in vulns:
                cursor.execute("""
                    INSERT INTO vulnerability_tracking (
                        analysis_id, vulnerability_type, severity, location
                    ) VALUES (?, ?, ?, ?)
                """, (
                    analysis_id,
                    vuln.get('type', 'Unknown'),
                    vuln.get('severity', 'MEDIUM'),
                    json.dumps(vuln.get('line_numbers', []))
                ))
        
        conn.commit()
        conn.close()
        
        return analysis_id
    
    def _extract_metrics(self, results: Dict) -> Dict:
        """결과에서 메트릭 추출"""
        metrics = {
            'security_score': 0,
            'vulnerability_count': 0,
            'critical_count': 0,
            'high_count': 0,
            'package_count': 0,
            'file_count': 0,
            'line_count': 0,
            'metadata': {}
        }
        
        # 보안 점수 및 취약점
        if 'security' in results:
            security = results['security']
            metrics['security_score'] = security.get('security_score', 0)
            
            vulns = security.get('code_vulnerabilities', [])
            metrics['vulnerability_count'] = len(vulns)
            
            for vuln in vulns:
                severity = vuln.get('severity', 'MEDIUM')
                if severity == 'CRITICAL':
                    metrics['critical_count'] += 1
                elif severity == 'HIGH':
                    metrics['high_count'] += 1
        
        # 패키지 수
        if 'dependencies' in results:
            deps = results['dependencies']
            metrics['package_count'] = deps.get('summary', {}).get('external_packages', 0)
        
        # 파일 및 라인 수
        if 'project_data' in results:
            stats = results['project_data'].get('statistics', {})
            metrics['file_count'] = stats.get('total_files', 0)
            metrics['line_count'] = stats.get('total_lines', 0)
        
        # 메타데이터
        metrics['metadata'] = {
            'analysis_time': results.get('analysis_time', 0),
            'frameworks': results.get('structure', {}).get('frameworks', [])
        }
        
        return metrics
    
    def get_project_history(self, project_name: str, limit: int = 10) -> List[Dict]:
        """프로젝트의 분석 히스토리 조회"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM analysis_history
            WHERE project_name = ?
            ORDER BY analyzed_at DESC
            LIMIT ?
        """, (project_name, limit))
        
        columns = [desc[0] for desc in cursor.description]
        results = []
        
        for row in cursor.fetchall():
            result = dict(zip(columns, row))
            # JSON 필드 파싱
            if result['analysis_results']:
                result['analysis_results'] = json.loads(result['analysis_results'])
            if result['metadata']:
                result['metadata'] = json.loads(result['metadata'])
            results.append(result)
        
        conn.close()
        return results
    
    def get_recent_analyses(self, days: int = 7, limit: int = 20) -> List[Dict]:
        """최근 분석 조회"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cutoff_date = datetime.now() - timedelta(days=days)
        
        cursor.execute("""
            SELECT id, project_name, project_type, analyzed_at,
                   security_score, vulnerability_count, critical_count
            FROM analysis_history
            WHERE analyzed_at >= ?
            ORDER BY analyzed_at DESC
            LIMIT ?
        """, (cutoff_date.isoformat(), limit))
        
        columns = [desc[0] for desc in cursor.description]
        results = []
        
        for row in cursor.fetchall():
            results.append(dict(zip(columns, row)))
        
        conn.close()
        return results
    
    def get_vulnerability_trends(self, project_name: str = None) -> Dict:
        """취약점 추세 분석"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if project_name:
            # 특정 프로젝트의 추세
            cursor.execute("""
                SELECT DATE(analyzed_at) as date,
                       AVG(security_score) as avg_score,
                       SUM(vulnerability_count) as total_vulns,
                       SUM(critical_count) as critical_vulns
                FROM analysis_history
                WHERE project_name = ?
                GROUP BY DATE(analyzed_at)
                ORDER BY date
            """, (project_name,))
        else:
            # 전체 추세
            cursor.execute("""
                SELECT DATE(analyzed_at) as date,
                       AVG(security_score) as avg_score,
                       SUM(vulnerability_count) as total_vulns,
                       SUM(critical_count) as critical_vulns,
                       COUNT(DISTINCT project_name) as project_count
                FROM analysis_history
                GROUP BY DATE(analyzed_at)
                ORDER BY date
            """)
        
        columns = [desc[0] for desc in cursor.description]
        trends = []
        
        for row in cursor.fetchall():
            trends.append(dict(zip(columns, row)))
        
        conn.close()
        
        return {
            'trends': trends,
            'summary': self._calculate_trend_summary(trends)
        }
    
    def _calculate_trend_summary(self, trends: List[Dict]) -> Dict:
        """추세 요약 계산"""
        if not trends:
            return {}
        
        # 최근 vs 이전 비교
        if len(trends) >= 2:
            latest = trends[-1]
            previous = trends[-2]
            
            score_change = latest['avg_score'] - previous['avg_score']
            vuln_change = latest['total_vulns'] - previous['total_vulns']
            
            return {
                'score_trend': 'improving' if score_change > 0 else 'declining',
                'score_change': score_change,
                'vuln_trend': 'decreasing' if vuln_change < 0 else 'increasing',
                'vuln_change': vuln_change
            }
        
        return {}
    
    def compare_analyses(self, analysis_id1: int, analysis_id2: int) -> Dict:
        """두 분석 결과 비교"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM analysis_history
            WHERE id IN (?, ?)
        """, (analysis_id1, analysis_id2))
        
        columns = [desc[0] for desc in cursor.description]
        analyses = []
        
        for row in cursor.fetchall():
            result = dict(zip(columns, row))
            if result['analysis_results']:
                result['analysis_results'] = json.loads(result['analysis_results'])
            analyses.append(result)
        
        conn.close()
        
        if len(analyses) != 2:
            return {'error': '분석 결과를 찾을 수 없습니다'}
        
        # 비교 결과 생성
        comparison = {
            'analysis1': analyses[0],
            'analysis2': analyses[1],
            'changes': {
                'security_score': analyses[1]['security_score'] - analyses[0]['security_score'],
                'vulnerability_count': analyses[1]['vulnerability_count'] - analyses[0]['vulnerability_count'],
                'critical_count': analyses[1]['critical_count'] - analyses[0]['critical_count'],
                'package_count': analyses[1]['package_count'] - analyses[0]['package_count']
            },
            'improvements': [],
            'regressions': []
        }
        
        # 개선/악화 항목 분석
        if comparison['changes']['security_score'] > 0:
            comparison['improvements'].append(
                f"보안 점수 {abs(comparison['changes']['security_score'])}점 향상"
            )
        elif comparison['changes']['security_score'] < 0:
            comparison['regressions'].append(
                f"보안 점수 {abs(comparison['changes']['security_score'])}점 하락"
            )
        
        if comparison['changes']['vulnerability_count'] < 0:
            comparison['improvements'].append(
                f"취약점 {abs(comparison['changes']['vulnerability_count'])}개 감소"
            )
        elif comparison['changes']['vulnerability_count'] > 0:
            comparison['regressions'].append(
                f"취약점 {abs(comparison['changes']['vulnerability_count'])}개 증가"
            )
        
        return comparison
    
    def get_statistics(self) -> Dict:
        """전체 통계"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 전체 통계
        cursor.execute("""
            SELECT 
                COUNT(DISTINCT project_name) as total_projects,
                COUNT(*) as total_analyses,
                AVG(security_score) as avg_security_score,
                SUM(vulnerability_count) as total_vulnerabilities,
                SUM(critical_count) as total_critical,
                MAX(analyzed_at) as last_analysis
            FROM analysis_history
        """)
        
        row = cursor.fetchone()
        if row:
            stats = dict(zip([desc[0] for desc in cursor.description], row))
            # None 값 처리
            for key in stats:
                if stats[key] is None:
                    if key in ['total_projects', 'total_analyses', 'total_vulnerabilities', 'total_critical']:
                        stats[key] = 0
                    elif key == 'avg_security_score':
                        stats[key] = 0.0
        else:
            stats = {
                'total_projects': 0,
                'total_analyses': 0,
                'avg_security_score': 0.0,
                'total_vulnerabilities': 0,
                'total_critical': 0,
                'last_analysis': None
            }
        
        # 프로젝트 타입별 통계
        cursor.execute("""
            SELECT project_type, COUNT(*) as count
            FROM analysis_history
            GROUP BY project_type
        """)
        
        stats['by_type'] = {}
        for row in cursor.fetchall():
            stats['by_type'][row[0]] = row[1]
        
        # 심각도별 취약점 분포
        cursor.execute("""
            SELECT severity, COUNT(*) as count
            FROM vulnerability_tracking
            WHERE status = 'open'
            GROUP BY severity
        """)
        
        stats['open_vulnerabilities'] = {}
        for row in cursor.fetchall():
            stats['open_vulnerabilities'][row[0]] = row[1]
        
        conn.close()
        return stats
    
    def cleanup_old_records(self, days: int = 90):
        """오래된 기록 정리"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cutoff_date = datetime.now() - timedelta(days=days)
        
        # 오래된 분석 삭제
        cursor.execute("""
            DELETE FROM analysis_history
            WHERE analyzed_at < ?
        """, (cutoff_date.isoformat(),))
        
        deleted_count = cursor.rowcount
        
        # 연관된 취약점 기록도 자동 삭제 (CASCADE 없으면)
        cursor.execute("""
            DELETE FROM vulnerability_tracking
            WHERE analysis_id NOT IN (SELECT id FROM analysis_history)
        """)
        
        conn.commit()
        conn.close()
        
        return deleted_count


# 테스트
if __name__ == "__main__":
    history = AnalysisHistory("test_history.db")
    
    # 테스트 데이터 저장
    test_results = {
        'security': {
            'security_score': 75,
            'code_vulnerabilities': [
                {'type': 'SQL Injection', 'severity': 'HIGH', 'line_numbers': [10]},
                {'type': 'XSS', 'severity': 'MEDIUM', 'line_numbers': [25]}
            ]
        },
        'dependencies': {
            'summary': {'external_packages': 20}
        },
        'project_data': {
            'statistics': {
                'total_files': 15,
                'total_lines': 1500
            }
        }
    }
    
    # 분석 저장
    analysis_id = history.save_analysis(
        "TestProject",
        test_results,
        project_type="github",
        project_url="https://github.com/test/repo"
    )
    
    print(f"Saved analysis ID: {analysis_id}")
    
    # 히스토리 조회
    project_history = history.get_project_history("TestProject")
    print(f"Project history: {len(project_history)} records")
    
    # 통계
    stats = history.get_statistics()
    print(f"Statistics: {stats}")