"""
RL Agent - Offline Reinforcement Learning for Adaptive Routing

Algorithm: Batch Constrained Q-learning (BCQ)
Input: State vector (20D)
Output: Action (routing decision)

Actions:
- HTTP (protocol_onehot[0] == 1): [0=KEEP_NORMAL, 1=WEB_POT, 2=SQLi_POT, 3=SSTI_POT, 4=CMDi_POT, 5=SSRF_POT (if applicable)]
- SSH/FTP/SMTP: [0=KEEP_NORMAL, 1=HONEYPOT]
"""

import numpy as np
import torch
import torch.nn as nn
from typing import Tuple, Optional
import logging

logger = logging.getLogger(__name__)

class QNetwork(nn.Module):
    """Deep Q-Network with action masking support"""
    
    def __init__(self, state_dim: int = 20, action_dim: int = 6, hidden_dim: int = 128):
        super().__init__()
        self.state_dim = state_dim
        self.action_dim = action_dim
        
        self.net = nn.Sequential(
            nn.Linear(state_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, action_dim)
        )
    
    def forward(self, state: torch.Tensor) -> torch.Tensor:
        return self.net(state)

class BCQAgent:
    """Batch Constrained Q-learning Agent for offline RL"""
    
    def __init__(self, state_dim: int = 20, action_dim: int = 6, device: str = "cpu"):
        self.state_dim = state_dim
        self.action_dim = action_dim
        self.device = torch.device(device)
        
        self.q_network = QNetwork(state_dim, action_dim).to(self.device)
        self.target_network = QNetwork(state_dim, action_dim).to(self.device)
        self.target_network.load_state_dict(self.q_network.state_dict())
        
        self.optimizer = torch.optim.Adam(self.q_network.parameters(), lr=1e-3)
        self.criterion = nn.SmoothL1Loss()
        
        # BCQ parameters
        self.threshold = 0.1  # Action masking threshold
        self.gamma = 0.99     # Discount factor
        self.tau = 0.005      # Target network update rate
    
    def get_action(self, 
                   state: np.ndarray,
                   protocol: str = "http",
                   current_route: int = 0) -> Tuple[int, float]:
        """
        Select action with masking
        
        Args:
            state: 20D state vector
            protocol: 'http', 'ssh', 'ftp', 'smtp'
            current_route: 0=normal, 1=honeypot (avoid re-routing)
        
        Returns:
            (action_idx, q_value)
        """
        
        state_tensor = torch.FloatTensor(state).unsqueeze(0).to(self.device)
        
        with torch.no_grad():
            q_values = self.q_network(state_tensor)[0].cpu().numpy()
        
        # Create action mask
        mask = self._get_action_mask(protocol, current_route)
        
        # Apply mask: set masked actions to very negative value
        masked_q_values = q_values.copy()
        masked_q_values[mask == 0] = -np.inf
        
        # Select best valid action
        action = np.argmax(masked_q_values)
        
        # Fallback if all masked (shouldn't happen)
        if np.isinf(masked_q_values[action]):
            action = np.where(mask)[0][0]
        
        q_value = float(q_values[action])
        
        return action, q_value
    
    def _get_action_mask(self, protocol: str, current_route: int) -> np.ndarray:
        """
        Generate valid action mask based on protocol and current routing state
        
        Action space:
        [0] = KEEP_NORMAL
        [1] = WEB_POT (generic, used as fallback)
        [2] = SQLi_POT (Web only)
        [3] = SSTI_POT (Web only)
        [4] = CMDi_POT (Web only)
        [5] = SSRF_POT (Web only)
        
        For SSH/FTP/SMTP: only [0, 1] are valid
        """
        
        mask = np.ones(self.action_dim, dtype=int)
        
        if protocol.lower() == "http":
            # All actions available for HTTP
            pass
        else:
            # L4 protocols (SSH, FTP, SMTP)
            mask[[2, 3, 4, 5]] = 0  # Only KEEP_NORMAL and HONEYPOT
        
        # Avoid re-routing if already in honeypot
        if current_route == 1:
            # Disable honeypot actions, keep only KEEP_NORMAL
            mask[[1, 2, 3, 4, 5]] = 0
        
        return mask
    
    def train_step(self, batch: dict) -> float:
        """
        Single offline training step
        
        Args:
            batch: {
                'states': (B, 20),
                'actions': (B,),
                'rewards': (B,),
                'next_states': (B, 20),
                'dones': (B,)
            }
        
        Returns:
            loss value
        """
        
        states = torch.FloatTensor(batch['states']).to(self.device)
        actions = torch.LongTensor(batch['actions']).to(self.device)
        rewards = torch.FloatTensor(batch['rewards']).to(self.device)
        next_states = torch.FloatTensor(batch['next_states']).to(self.device)
        dones = torch.FloatTensor(batch['dones']).to(self.device)
        
        # Current Q-values
        q_values = self.q_network(states)
        q_values = q_values.gather(1, actions.unsqueeze(1)).squeeze(1)
        
        # Target Q-values
        with torch.no_grad():
            next_q_values = self.target_network(next_states).max(dim=1)[0]
            target_q_values = rewards + (1 - dones) * self.gamma * next_q_values
        
        # Loss
        loss = self.criterion(q_values, target_q_values)
        
        # Backward pass
        self.optimizer.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(self.q_network.parameters(), max_norm=1.0)
        self.optimizer.step()
        
        # Soft update target network
        self._soft_update()
        
        return loss.item()
    
    def _soft_update(self):
        """Soft update target network"""
        for target_param, param in zip(self.target_network.parameters(), self.q_network.parameters()):
            target_param.data.copy_(
                self.tau * param.data + (1.0 - self.tau) * target_param.data
            )
    
    def save(self, path: str):
        """Save model weights"""
        torch.save(self.q_network.state_dict(), path)
        logger.info(f"Model saved to {path}")
    
    def load(self, path: str):
        """Load model weights"""
        self.q_network.load_state_dict(torch.load(path, weights_only=True))
        self.target_network.load_state_dict(self.q_network.state_dict())
        logger.info(f"Model loaded from {path}")


# Global agent instance
agent = None

def initialize_agent(state_dim: int = 20, action_dim: int = 6, device: str = "cpu"):
    """Initialize global agent"""
    global agent
    agent = BCQAgent(state_dim, action_dim, device)
    logger.info(f"Agent initialized: state_dim={state_dim}, action_dim={action_dim}, device={device}")
    return agent

def get_agent() -> BCQAgent:
    """Get global agent instance"""
    global agent
    if agent is None:
        agent = initialize_agent()
    return agent
