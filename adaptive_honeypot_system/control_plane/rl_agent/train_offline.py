"""
Train offline RL model using batch data

This script loads offline training data (recorded from logs/simulation)
and trains the BCQ agent using batch RL.
"""

import numpy as np
import torch
from agent import BCQAgent
import json
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def load_offline_dataset(data_path: str) -> dict:
    """Load pre-collected offline data"""
    with open(data_path, 'r') as f:
        data = json.load(f)
    
    # Convert lists to numpy arrays
    return {
        'states': np.array(data['states'], dtype=np.float32),
        'actions': np.array(data['actions'], dtype=np.int64),
        'rewards': np.array(data['rewards'], dtype=np.float32),
        'next_states': np.array(data['next_states'], dtype=np.float32),
        'dones': np.array(data['dones'], dtype=np.float32),
    }

def train(agent: BCQAgent, dataset: dict, epochs: int = 100, batch_size: int = 32):
    """Train agent on offline dataset"""
    
    n_samples = len(dataset['states'])
    losses = []
    
    for epoch in range(epochs):
        # Shuffle indices
        indices = np.random.permutation(n_samples)
        epoch_losses = []
        
        for i in range(0, n_samples, batch_size):
            batch_indices = indices[i:i+batch_size]
            batch = {
                'states': dataset['states'][batch_indices],
                'actions': dataset['actions'][batch_indices],
                'rewards': dataset['rewards'][batch_indices],
                'next_states': dataset['next_states'][batch_indices],
                'dones': dataset['dones'][batch_indices],
            }
            
            loss = agent.train_step(batch)
            epoch_losses.append(loss)
        
        avg_loss = np.mean(epoch_losses)
        losses.append(avg_loss)
        
        if (epoch + 1) % 10 == 0:
            logger.info(f"Epoch {epoch+1}/{epochs} - Loss: {avg_loss:.4f}")
    
    return losses

if __name__ == "__main__":
    # Initialize agent
    agent = BCQAgent(state_dim=20, action_dim=6, device="cpu")
    
    # Load offline data
    dataset_path = Path(__file__).parent / "offline_data.json"
    if not dataset_path.exists():
        logger.error(f"Dataset not found at {dataset_path}")
        logger.info("Generate offline_data.json with sample trajectories first")
        exit(1)
    
    logger.info(f"Loading dataset from {dataset_path}")
    dataset = load_offline_dataset(str(dataset_path))
    logger.info(f"Dataset: {len(dataset['states'])} samples")
    
    # Train
    logger.info("Starting training...")
    losses = train(agent, dataset, epochs=100, batch_size=32)
    
    # Save model
    model_path = Path(__file__).parent / "model_weights.pth"
    agent.save(str(model_path))
    
    logger.info(f"Training complete. Model saved to {model_path}")
