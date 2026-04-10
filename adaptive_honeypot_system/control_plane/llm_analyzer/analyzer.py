"""
LLM Analyzer - Extract attack semantics from aggregated logs

Input: Pre-aggregated data from Elasticsearch (5-second windows)
Output: Semantic state vector for RL Agent

Returns:
- attack_category: injection | bruteforce | enumeration | malformed
- web_subtype_scores: [sqli, cmdi, ssti, ssrf] confidence scores
- evasion_score: likelihood of evasion techniques (encoding, obfuscation)
- llm_confidence: overall confidence in analysis
"""

import json
import logging
from typing import Optional, Dict, List
from datetime import datetime

logger = logging.getLogger(__name__)

class LLMAnalyzer:
    """Semantic analysis using LLM API (Gemini/GPT)"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.mock_mode = not api_key  # Use mock analysis if no API key
    
    def analyze(self, aggregated_log: Dict) -> Dict:
        """
        Analyze aggregated log window
        
        Args:
            aggregated_log: {
                "ip": "192.168.1.100",
                "session_id": "abc123",
                "protocol": "http",
                "request_count": 15,
                "failed_attempts": 8,
                "payloads": ["' OR '1'='1", "SELECT FROM users", ...],
                "paths": ["/api/articles/1", "/api/articles/search", ...],
                "time_window": 5
            }
        
        Returns:
            {
                "attack_category": "injection",
                "web_subtype_scores": [0.85, 0.08, 0.05, 0.02],
                "evasion_score": 0.12,
                "llm_confidence": 0.91,
                "reasoning": "SQL keywords + error messages indicate SQLi"
            }
        """
        
        if self.mock_mode:
            return self._mock_analysis(aggregated_log)
        
        # Real LLM API call would go here
        # For now, implement basic pattern matching + mock confidence
        return self._pattern_analysis(aggregated_log)
    
    def _pattern_analysis(self, log: Dict) -> Dict:
        """Pattern-based analysis (fallback if LLM unavailable)"""
        
        payloads = log.get("payloads", [])
        paths = log.get("paths", [])
        protocol = log.get("protocol", "http")
        failed_attempts = log.get("failed_attempts", 0)
        
        # Count patterns
        sqli_count = sum(1 for p in payloads if self._check_sqli(p))
        cmdi_count = sum(1 for p in payloads if self._check_cmdi(p))
        ssti_count = sum(1 for p in payloads if self._check_ssti(p))
        ssrf_count = sum(1 for p in payloads if self._check_ssrf(p))
        
        path_diversity = len(set(paths))
        request_count = log.get("request_count", 1)
        
        # Determine primary category
        if sqli_count > 0 or cmdi_count > 0 or ssti_count > 0 or ssrf_count > 0:
            category = "injection"
        elif failed_attempts > request_count * 0.5:  # >50% fail rate
            category = "bruteforce"
        elif path_diversity > request_count * 0.6:
            category = "enumeration"
        else:
            category = "malformed"
        
        # Calculate scores
        total = max(1, sqli_count + cmdi_count + ssti_count + ssrf_count)
        scores = [
            sqli_count / total if total > 0 else 0,
            cmdi_count / total if total > 0 else 0,
            ssti_count / total if total > 0 else 0,
            ssrf_count / total if total > 0 else 0,
        ]
        
        # Evasion detection
        evasion = sum(1 for p in payloads if self._check_evasion(p)) / max(1, len(payloads))
        
        # Confidence based on pattern strength
        confidence = min(0.95, 0.5 + (sqli_count / max(1, request_count)))
        
        return {
            "attack_category": category,
            "web_subtype_scores": scores,
            "evasion_score": evasion,
            "llm_confidence": confidence,
            "reasoning": f"{category.title()} detected: {sqli_count} SQLi, {cmdi_count} CMDi, {ssti_count} SSTI, {ssrf_count} SSRF"
        }
    
    def _mock_analysis(self, log: Dict) -> Dict:
        """Mock analysis for demonstration"""
        protocol = log.get("protocol", "http")
        
        if protocol == "http":
            return {
                "attack_category": "injection",
                "web_subtype_scores": [0.72, 0.15, 0.08, 0.05],
                "evasion_score": 0.22,
                "llm_confidence": 0.88,
                "reasoning": "[MOCK] SQL injection with moderate evasion detected"
            }
        else:
            return {
                "attack_category": "bruteforce",
                "web_subtype_scores": [0.0, 0.0, 0.0, 0.0],
                "evasion_score": 0.05,
                "llm_confidence": 0.94,
                "reasoning": f"[MOCK] Bruteforce auth on {protocol}"
            }
    
    @staticmethod
    def _check_sqli(payload: str) -> bool:
        keywords = ["union", "select", "insert", "delete", "drop", "update", "--", "/*", "*/", "'", "\""]
        return any(kw.lower() in str(payload).lower() for kw in keywords)
    
    @staticmethod
    def _check_cmdi(payload: str) -> bool:
        keywords = ["whoami", "id", "cat", "ls", "cmd", "powershell", "bash", ";", "|", "&", "$", "`"]
        return any(kw.lower() in str(payload).lower() for kw in keywords)
    
    @staticmethod
    def _check_ssti(payload: str) -> bool:
        patterns = ["{{", "}}", "{%", "%}", "${", "<%", "%>"]
        return any(pat in str(payload) for pat in patterns)
    
    @staticmethod
    def _check_ssrf(payload: str) -> bool:
        keywords = ["file://", "gopher://", "dict://", "ldap://", "127.0.0.1", "localhost", "169.254.169.254"]
        return any(kw.lower() in str(payload).lower() for kw in keywords)
    
    @staticmethod
    def _check_evasion(payload: str) -> bool:
        """Detect obfuscation/encoding attempts"""
        techniques = ["0x", "char(", "hex(", "concat(", "%", "url-encoded", "unicode"]
        return any(t in str(payload).lower() for t in techniques)

# Global instance
analyzer = LLMAnalyzer()
