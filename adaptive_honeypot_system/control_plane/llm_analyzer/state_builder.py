"""
State Builder - Combine rule-based + LLM features into unified state vector

State Vector (20D):
- Protocol (4D one-hot)
- Session metrics (3D)
- Payload signals (2D)
- LLM semantic (10D)
- Routing state (2D)
"""

import numpy as np
from typing import Dict, List, Tuple
from datetime import datetime, timedelta

class StateBuilder:
    """Build 20D state vector for RL Agent"""
    
    # Max session duration for normalization
    MAX_SESSION_AGE_SEC = 600
    
    # Anomaly thresholds per protocol
    INTERACTION_RATE_BASELINE = {
        "http": 5.0,      # req/sec
        "ssh": 0.5,       # cmd/sec
        "ftp": 0.3,       # cmd/sec
        "smtp": 0.2       # cmd/sec
    }
    
    # Protocol to index mapping
    PROTOCOL_TO_IDX = {
        "http": 0,
        "ssh": 1,
        "ftp": 2,
        "smtp": 3
    }
    
    ATTACK_CATEGORY_TO_IDX = {
        "injection": 0,
        "bruteforce": 1,
        "enumeration": 2,
        "malformed": 3
    }
    
    def __init__(self):
        self.rolling_history = {}  # Track per-session/IP state history
    
    def build(self, 
              protocol: str,
              metrics: Dict,
              llm_output: Dict,
              routing_state: Dict) -> np.ndarray:
        """
        Build state vector
        
        Args:
            protocol: 'http', 'ssh', 'ftp', 'smtp'
            metrics: {
                'session_id'/'ip': identifier,
                'session_age_sec': float,
                'request_count': int,
                'failed_attempts': int,
                'payload_size_bytes': int,
                'unique_targets': int
            }
            llm_output: output from LLMAnalyzer.analyze()
            routing_state: {
                'current_route': 0/1 (0=normal, 1=honeypot),
                'prev_attack_category': str (for shift detection)
            }
        
        Returns:
            np.ndarray of shape (20,)
        """
        
        # 1. Protocol one-hot (4D)
        protocol_onehot = self._protocol_onehot(protocol)
        
        # 2. Session metrics (3D)
        session_age_norm = min(1.0, metrics.get('session_age_sec', 0) / self.MAX_SESSION_AGE_SEC)
        
        baseline_rate = self.INTERACTION_RATE_BASELINE.get(protocol, 1.0)
        actual_rate = metrics.get('request_count', 1) / max(1, metrics.get('time_window_sec', 1))
        interaction_rate_norm = min(1.0, actual_rate / baseline_rate)
        
        failed_attempts_norm = min(1.0, metrics.get('failed_attempts', 0) / max(1, metrics.get('request_count', 1)))
        
        # 3. Payload signals (2D)
        payload_size_anomaly = self._size_anomaly(
            metrics.get('payload_size_bytes', 128),
            protocol
        )
        
        probe_diversity = metrics.get('unique_targets', 1) / max(1, metrics.get('request_count', 1))
        probe_diversity_norm = min(1.0, probe_diversity * 2)  # Scale for visibility
        
        # 4. LLM semantic (4 fields, 10D after expansion)
        attack_category_onehot = self._category_onehot(llm_output.get('attack_category', 'malformed'))
        web_subtype_scores = llm_output.get('web_subtype_scores', [0, 0, 0, 0])
        evasion_score = llm_output.get('evasion_score', 0.0)
        llm_confidence = llm_output.get('llm_confidence', 0.5)
        
        # Scale LLM features by confidence (graceful degradation)
        effective_category = attack_category_onehot * llm_confidence
        effective_subtype = np.array(web_subtype_scores) * llm_confidence
        effective_evasion = evasion_score * llm_confidence
        
        # 5. Routing state (2D)
        current_route = float(routing_state.get('current_route', 0))
        
        # Attack vector shift (cosine-like distance from previous)
        prev_category = routing_state.get('prev_attack_category', llm_output.get('attack_category', 'malformed'))
        attack_vector_shift = 0.0 if prev_category == llm_output.get('attack_category') else 0.5
        
        # Concatenate all features
        state_vector = np.concatenate([
            protocol_onehot,              # 4
            [session_age_norm],           # 1
            [interaction_rate_norm],      # 1
            [failed_attempts_norm],       # 1
            [payload_size_anomaly],       # 1
            [probe_diversity_norm],       # 1
            effective_category,           # 4
            effective_subtype,            # 4
            [effective_evasion],          # 1
            [current_route],              # 1
            [attack_vector_shift],        # 1
        ])
        
        # Store for next window's shift calculation
        session_key = metrics.get('session_id') or metrics.get('ip', 'unknown')
        self.rolling_history[session_key] = llm_output.get('attack_category', 'malformed')
        
        return state_vector.astype(np.float32)
    
    def _protocol_onehot(self, protocol: str) -> np.ndarray:
        idx = self.PROTOCOL_TO_IDX.get(protocol.lower(), 3)
        vec = np.zeros(4)
        vec[idx] = 1.0
        return vec
    
    def _category_onehot(self, category: str) -> np.ndarray:
        idx = self.ATTACK_CATEGORY_TO_IDX.get(category, 3)
        vec = np.zeros(4)
        vec[idx] = 1.0
        return vec
    
    def _size_anomaly(self, size_bytes: int, protocol: str) -> float:
        """Z-score like normalization for payload size"""
        baseline = {
            "http": 200,
            "ssh": 50,
            "ftp": 100,
            "smtp": 150
        }
        base = baseline.get(protocol, 100)
        z_score = abs(size_bytes - base) / max(1, base / 3)
        return min(1.0, z_score / 3)  # Normalize to ~[0, 1]
