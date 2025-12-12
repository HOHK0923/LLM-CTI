#!/usr/bin/env python3
"""
RAG-based Security Log Analyzer
Uses vector database and LLM to analyze attack patterns
"""

import json
import os
from typing import List, Dict, Any, Optional
from datetime import datetime
import hashlib


class VectorStore:
    """Simple in-memory vector store for attack patterns"""

    def __init__(self):
        self.documents = []
        self.embeddings = []

    def add_document(self, doc: Dict[str, Any], embedding: List[float] = None):
        """Add a document to the vector store"""
        self.documents.append(doc)
        # In production, use actual embeddings from models like sentence-transformers
        # For now, create a simple hash-based representation
        if embedding is None:
            embedding = self._create_simple_embedding(doc)
        self.embeddings.append(embedding)

    def _create_simple_embedding(self, doc: Dict) -> List[float]:
        """Create a simple text-based embedding (placeholder for real embeddings)"""
        # In production, use sentence-transformers or OpenAI embeddings
        text = json.dumps(doc, ensure_ascii=False)
        hash_val = int(hashlib.md5(text.encode()).hexdigest(), 16)

        # Create a simple 128-dimensional vector
        embedding = []
        for i in range(128):
            embedding.append(float((hash_val >> i) & 1))

        return embedding

    def search(self, query: str, top_k: int = 5) -> List[Dict]:
        """Search for similar documents"""
        # Simple keyword-based search (in production, use vector similarity)
        query_lower = query.lower()
        results = []

        for doc in self.documents:
            score = 0
            doc_text = json.dumps(doc, ensure_ascii=False).lower()

            # Simple keyword matching
            for word in query_lower.split():
                if word in doc_text:
                    score += 1

            if score > 0:
                results.append({'document': doc, 'score': score})

        # Sort by score and return top_k
        results.sort(key=lambda x: x['score'], reverse=True)
        return results[:top_k]


class RAGAnalyzer:
    """RAG-based attack pattern analyzer"""

    def __init__(self, knowledge_base_path: Optional[str] = None):
        self.vector_store = VectorStore()
        self.attack_knowledge = self._load_attack_knowledge()

        if knowledge_base_path and os.path.exists(knowledge_base_path):
            self.load_knowledge_base(knowledge_base_path)

    def _load_attack_knowledge(self) -> Dict[str, Dict]:
        """Load built-in attack pattern knowledge"""
        return {
            'SQL_INJECTION': {
                'description': 'SQL Injection은 악의적인 SQL 쿼리를 삽입하여 데이터베이스를 조작하는 공격입니다.',
                'severity': 'CRITICAL',
                'common_payloads': ["' OR '1'='1", "UNION SELECT", "'; DROP TABLE", "AND SLEEP"],
                'indicators': ['single quote', 'union', 'select', 'information_schema', 'sleep'],
                'mitigation': [
                    'Prepared Statements 사용',
                    'Input Validation 강화',
                    'WAF 규칙 활성화',
                    '최소 권한 원칙 적용'
                ]
            },
            'XSS': {
                'description': 'Cross-Site Scripting은 악의적인 스크립트를 웹 페이지에 삽입하는 공격입니다.',
                'severity': 'HIGH',
                'common_payloads': ['<script>', 'onerror=', 'javascript:', 'onload='],
                'indicators': ['script tag', 'event handler', 'javascript protocol'],
                'mitigation': [
                    'Output Encoding 적용',
                    'Content Security Policy 설정',
                    'HttpOnly 쿠키 플래그 사용',
                    'Input Sanitization'
                ]
            },
            'COMMAND_INJECTION': {
                'description': 'Command Injection은 시스템 명령어를 삽입하여 서버를 제어하는 공격입니다.',
                'severity': 'CRITICAL',
                'common_payloads': ['|', '&&', ';', '`', '$()'],
                'indicators': ['shell metacharacters', 'system commands', 'pipe', 'semicolon'],
                'mitigation': [
                    '명령어 실행 기능 제거',
                    'Whitelist 기반 Input Validation',
                    '시스템 명령어 직접 호출 금지',
                    '샌드박스 환경 사용'
                ]
            },
            'FILE_INCLUSION': {
                'description': 'File Inclusion은 서버의 파일을 포함시켜 민감한 정보를 탈취하는 공격입니다.',
                'severity': 'HIGH',
                'common_payloads': ['../../', '/etc/passwd', 'php://input', 'http://'],
                'indicators': ['directory traversal', 'file path', 'protocol wrapper'],
                'mitigation': [
                    '파일 경로 화이트리스트 사용',
                    'basename() 함수로 경로 정규화',
                    '원격 파일 포함 비활성화',
                    '파일 접근 권한 최소화'
                ]
            },
            'BRUTE_FORCE': {
                'description': 'Brute Force는 여러 조합을 시도하여 인증을 우회하는 공격입니다.',
                'severity': 'MEDIUM',
                'common_payloads': ['password123', 'admin', '123456'],
                'indicators': ['multiple failed attempts', 'rapid requests', 'password list'],
                'mitigation': [
                    'Rate Limiting 적용',
                    'CAPTCHA 구현',
                    'Account Lockout 정책',
                    '2FA/MFA 도입'
                ]
            }
        }

    def load_knowledge_base(self, file_path: str):
        """Load attack patterns into vector store"""
        print(f"Loading knowledge base from: {file_path}")

        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        training_data = data.get('training_data', [])

        for example in training_data:
            self.vector_store.add_document(example)

        print(f"Loaded {len(training_data)} examples into vector store")

    def analyze_attack(self, attack_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze an attack using RAG approach"""

        # Extract attack information
        attack_types = attack_data.get('attack_types', [])
        timeline = attack_data.get('timeline', '')
        risk_score = attack_data.get('risk_score', 0)

        # Retrieve relevant context from vector store
        query = f"{' '.join(attack_types)} {timeline}"
        similar_cases = self.vector_store.search(query, top_k=3)

        # Generate analysis based on knowledge base and similar cases
        analysis = {
            'attack_summary': self._generate_summary(attack_data),
            'attack_details': self._analyze_details(attack_data),
            'similar_cases': similar_cases,
            'recommendations': self._generate_recommendations(attack_data),
            'threat_intelligence': self._gather_threat_intel(attack_types)
        }

        return analysis

    def _generate_summary(self, attack_data: Dict) -> str:
        """Generate attack summary"""
        attack_types = attack_data.get('attack_types', [])
        session_id = attack_data.get('session_id', 'UNKNOWN')
        source_ip = attack_data.get('source_ip', 'UNKNOWN')
        total_attempts = attack_data.get('total_attempts', 0)
        successful = attack_data.get('successful_attacks', 0)
        stage = attack_data.get('attack_stage', 'UNKNOWN')

        summary = f"""
**공격 요약**

세션 {session_id}에서 IP {source_ip}로부터 {', '.join(attack_types)} 공격이 탐지되었습니다.
총 {total_attempts}회 시도 중 {successful}회가 성공하였으며, 현재 공격 단계는 {stage}입니다.
"""
        return summary.strip()

    def _analyze_details(self, attack_data: Dict) -> List[Dict]:
        """Analyze attack details"""
        attack_types = attack_data.get('attack_types', [])
        events = attack_data.get('events', [])

        details = []

        for attack_type in attack_types:
            if attack_type in self.attack_knowledge:
                knowledge = self.attack_knowledge[attack_type]

                # Find events of this type
                type_events = [e for e in events if e.get('attack_type') == attack_type]

                details.append({
                    'attack_type': attack_type,
                    'description': knowledge['description'],
                    'severity': knowledge['severity'],
                    'attempt_count': len(type_events),
                    'success_count': sum(1 for e in type_events if e.get('success')),
                    'mitigation': knowledge['mitigation']
                })

        return details

    def _generate_recommendations(self, attack_data: Dict) -> List[str]:
        """Generate detailed recommendations"""
        recommendations = []
        attack_types = attack_data.get('attack_types', [])
        risk_score = attack_data.get('risk_score', 0)
        stage = attack_data.get('attack_stage', '')

        # General recommendations based on risk score
        if risk_score >= 8:
            recommendations.append('🚨 [긴급] 즉시 IP 차단 및 SOC 팀 에스컬레이션 필요')
            recommendations.append('🔒 영향받은 시스템 즉시 격리 검토')
            recommendations.append('📋 포렌식 분석을 위한 로그 보존')

        elif risk_score >= 5:
            recommendations.append('⚠️  [높음] Rate Limiting 및 모니터링 강화')
            recommendations.append('🔍 추가 공격 시도 모니터링')

        # Specific recommendations based on attack type
        for attack_type in attack_types:
            if attack_type in self.attack_knowledge:
                knowledge = self.attack_knowledge[attack_type]
                for mitigation in knowledge['mitigation']:
                    recommendations.append(f'• [{attack_type}] {mitigation}')

        # Stage-specific recommendations
        if stage == 'RECONNAISSANCE':
            recommendations.append('🔭 정찰 단계: 추가 공격 예상, 방어 태세 강화')
        elif stage == 'EXPLOITATION':
            recommendations.append('💥 공격 진행 중: 즉각적인 대응 필요')
        elif stage == 'DATA_EXFILTRATION':
            recommendations.append('📤 데이터 유출 시도: 네트워크 트래픽 분석 및 차단')

        return recommendations

    def _gather_threat_intel(self, attack_types: List[str]) -> Dict[str, Any]:
        """Gather threat intelligence"""
        intel = {
            'attack_patterns': [],
            'known_techniques': [],
            'references': []
        }

        for attack_type in attack_types:
            if attack_type in self.attack_knowledge:
                knowledge = self.attack_knowledge[attack_type]
                intel['attack_patterns'].append({
                    'type': attack_type,
                    'severity': knowledge['severity'],
                    'indicators': knowledge['indicators']
                })

                # Add MITRE ATT&CK references
                mitre_mapping = {
                    'SQL_INJECTION': 'T1190 - Exploit Public-Facing Application',
                    'XSS': 'T1059 - Command and Scripting Interpreter',
                    'COMMAND_INJECTION': 'T1059.004 - Unix Shell',
                    'FILE_INCLUSION': 'T1083 - File and Directory Discovery',
                    'BRUTE_FORCE': 'T1110 - Brute Force'
                }

                if attack_type in mitre_mapping:
                    intel['known_techniques'].append(mitre_mapping[attack_type])

        return intel

    def generate_report(self, attack_data: Dict, output_file: str):
        """Generate comprehensive analysis report"""
        analysis = self.analyze_attack(attack_data)

        report = {
            'timestamp': datetime.now().isoformat(),
            'attack_data': attack_data,
            'analysis': analysis
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

        print(f"Analysis report saved to: {output_file}")

        return report


def main():
    import sys

    if len(sys.argv) < 3:
        print("Usage: python rag_analyzer.py <training_dataset> <analysis_input> [output_report]")
        print("Example: python rag_analyzer.py ../../data/datasets/training.json attack_session.json report.json")
        sys.exit(1)

    knowledge_base = sys.argv[1]
    input_file = sys.argv[2]
    output_file = sys.argv[3] if len(sys.argv) > 3 else 'analysis_report.json'

    # Initialize RAG analyzer
    analyzer = RAGAnalyzer(knowledge_base)

    # Load attack data
    with open(input_file, 'r', encoding='utf-8') as f:
        attack_data = json.load(f)

    # Generate analysis
    analyzer.generate_report(attack_data, output_file)


if __name__ == '__main__':
    main()
