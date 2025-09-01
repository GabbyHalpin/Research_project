#!/usr/bin/env python3
"""
Pickle File Merger for Shadow WF Processing

This script merges individual simulation pickle files into final training datasets
with proper train/validation/test splits and consistent labeling.

Author: Claude
Date: 2025
"""

import pickle
import argparse
import numpy as np
from pathlib import Path
from collections import defaultdict
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PickleMerger:
    def __init__(self, input_dir: str, output_dir: str):
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        self.global_url_to_label = {}
        self.global_label_to_url = {}
        self.current_global_label = 0
        
    def merge_simulations_by_scale(self):
        """Merge simulation files grouped by network scale"""
        
        # Find all pickle files
        x_files = list(self.input_dir.glob("X_*.pkl"))
        
        if not x_files:
            logger.error(f"No X_*.pkl files found in {self.input_dir}")
            return
        
        logger.info(f"Found {len(x_files)} simulation files to merge")
        
        # Group files by network scale
        scale_groups = defaultdict(list)
        
        for x_file in x_files:
            sim_name = x_file.name[2:-4]  # Remove 'X_' and '.pkl'
            
            # Determine scale from simulation name
            sim_lower = sim_name.lower()
            if "0.005" in sim_lower or "005" in sim_lower:
                scale_groups["0.5%"].append(sim_name)
            elif "0.01" in sim_lower or ("01" in sim_lower and "001" not in sim_lower):
                scale_groups["1%"].append(sim_name)
            elif "0.02" in sim_lower or "02" in sim_lower:
                scale_groups["2%"].append(sim_name)
            else:
                scale_groups["unknown"].append(sim_name)
        
        # Process each scale group
        for scale, sim_names in scale_groups.items():
            if not sim_names:
                continue
                
            logger.info(f"Processing scale group: {scale} ({len(sim_names)} simulations)")
            self._merge_scale_group(scale, sim_names)
    
    def _merge_scale_group(self, scale: str, sim_names: list):
        """Merge simulations for a specific scale group"""
        
        # Reset global labels for this scale group
        self.global_url_to_label = {}
        self.global_label_to_url = {}
        self.current_global_label = 0
        
        all_X = []
        all_y = []
        
        # Load and merge all simulations in this scale
        for sim_name in sim_names:
            try:
                # Load data files
                X_file = self.input_dir / f"X_{sim_name}.pkl"
                y_file = self.input_dir / f"y_{sim_name}.pkl"
                labels_file = self.input_dir / f"labels_{sim_name}.pkl"
                
                # Check if all files exist
                if not all([X_file.exists(), y_file.exists(), labels_file.exists()]):
                    logger.warning(f"Missing files for {sim_name}, skipping...")
                    continue
                
                # Load data
                with open(X_file, 'rb') as f:
                    X_sim = pickle.load(f)
                with open(y_file, 'rb') as f:
                    y_sim = pickle.load(f)
                with open(labels_file, 'rb') as f:
                    labels_sim = pickle.load(f)
                
                logger.info(f"Loaded {sim_name}: {len(X_sim)} sequences")
                
                # Remap labels to global label space
                y_sim_remapped = self._remap_labels(y_sim, labels_sim)
                
                all_X.append(X_sim)
                all_y.append(y_sim_remapped)
                
            except Exception as e:
                logger.error(f"Error loading {sim_name}: {e}")
                continue
        
        if not all_X:
            logger.error(f"No valid data found for scale {scale}")
            return
        
        # Combine all data
        X_combined = np.vstack(all_X)
        y_combined = np.hstack(all_y)
        
        logger.info(f"Combined {scale}: {len(X_combined)} total sequences, {len(self.global_url_to_label)} classes")
        
        # Split data
        X_train, X_val, X_test, y_train, y_val, y_test = self._split_data(X_combined, y_combined)
        
        # Save final dataset
        scale_name = scale.replace('%', 'percent')
        output_dir = self.output_dir / f"ClosedWorld_{scale_name}"
        self._save_dataset(X_train, X_val, X_test, y_train, y_val, y_test, 
                          output_dir, f"NoDef_{scale}")
    
    def _remap_labels(self, y_local: np.ndarray, labels_local: dict) -> np.ndarray:
        """Remap local simulation labels to global label space"""
        
        local_label_to_url = labels_local['label_to_url']
        
        # Create mapping from local to global labels
        local_to_global = {}
        
        for local_label, url in local_label_to_url.items():
            if url not in self.global_url_to_label:
                # New URL, assign new global label
                self.global_url_to_label[url] = self.current_global_label
                self.global_label_to_url[self.current_global_label] = url
                global_label = self.current_global_label
                self.current_global_label += 1
            else:
                # Existing URL, use existing global label
                global_label = self.global_url_to_label[url]
            
            local_to_global[local_label] = global_label
        
        # Remap the label array
        y_remapped = np.array([local_to_global[local_label] for local_label in y_local])
        
        return y_remapped
    
    def _split_data(self, X: np.ndarray, y: np.ndarray, 
                   train_ratio: float = 0.7, val_ratio: float = 0.15, test_ratio: float = 0.15):
        """Split data into train/validation/test sets"""
        assert abs(train_ratio + val_ratio + test_ratio - 1.0) < 1e-6, "Ratios must sum to 1"
        
        n_samples = len(X)
        indices = np.random.permutation(n_samples)
        
        train_end = int(train_ratio * n_samples)
        val_end = int((train_ratio + val_ratio) * n_samples)
        
        train_idx = indices[:train_end]
        val_idx = indices[train_end:val_end]
        test_idx = indices[val_end:]
        
        return (X[train_idx], X[val_idx], X[test_idx],
                y[train_idx], y[val_idx], y[test_idx])
    
    def _save_dataset(self, X_train, X_val, X_test, y_train, y_val, y_test,
                     output_dir: Path, dataset_name: str):
        """Save final dataset in required format"""
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Save training data
        with open(output_dir / f"X_train_{dataset_name}.pkl", 'wb') as f:
            pickle.dump(X_train, f)
        with open(output_dir / f"y_train_{dataset_name}.pkl", 'wb') as f:
            pickle.dump(y_train, f)
        
        # Save validation data
        with open(output_dir / f"X_val_{dataset_name}.pkl", 'wb') as f:
            pickle.dump(X_val, f)
        with open(output_dir / f"y_val_{dataset_name}.pkl", 'wb') as f:
            pickle.dump(y_val, f)
        
        # Save test data
        with open(output_dir / f"X_test_{dataset_name}.pkl", 'wb') as f:
            pickle.dump(X_test, f)
        with open(output_dir / f"y_test_{dataset_name}.pkl", 'wb') as f:
            pickle.dump(y_test, f)
        
        # Save label mapping
        with open(output_dir / f"url_labels_{dataset_name}.pkl", 'wb') as f:
            pickle.dump({
                'url_to_label': self.global_url_to_label,
                'label_to_url': self.global_label_to_url
            }, f)
        
        logger.info(f"Saved dataset to {output_dir}")
        logger.info(f"Train: {len(X_train)}, Val: {len(X_val)}, Test: {len(X_test)}")
        logger.info(f"Number of classes: {len(self.global_url_to_label)}")
        
        # Log sample URLs
        sample_urls = list(self.global_label_to_url.values())[:10]
        logger.info(f"Sample URLs: {sample_urls}")
    
    def merge_all_combined(self):
        """Merge all simulations into a single combined dataset"""
        logger.info("Merging all simulations into combined dataset")
        
        # Find all files
        x_files = list(self.input_dir.glob("X_*.pkl"))
        sim_names = [f.name[2:-4] for f in x_files]  # Remove 'X_' and '.pkl'
        
        if not sim_names:
            logger.error(f"No simulation files found in {self.input_dir}")
            return
        
        # Reset global labels
        self.global_url_to_label = {}
        self.global_label_to_url = {}
        self.current_global_label = 0
        
        all_X = []
        all_y = []
        
        # Load and merge all simulations
        for sim_name in sim_names:
            try:
                X_file = self.input_dir / f"X_{sim_name}.pkl"
                y_file = self.input_dir / f"y_{sim_name}.pkl"
                labels_file = self.input_dir / f"labels_{sim_name}.pkl"
                
                if not all([X_file.exists(), y_file.exists(), labels_file.exists()]):
                    logger.warning(f"Missing files for {sim_name}, skipping...")
                    continue
                
                with open(X_file, 'rb') as f:
                    X_sim = pickle.load(f)
                with open(y_file, 'rb') as f:
                    y_sim = pickle.load(f)
                with open(labels_file, 'rb') as f:
                    labels_sim = pickle.load(f)
                
                logger.info(f"Loaded {sim_name}: {len(X_sim)} sequences")
                
                # Remap labels
                y_sim_remapped = self._remap_labels(y_sim, labels_sim)
                
                all_X.append(X_sim)
                all_y.append(y_sim_remapped)
                
            except Exception as e:
                logger.error(f"Error loading {sim_name}: {e}")
                continue
        
        if not all_X:
            logger.error("No valid data found")
            return
        
        # Combine data
        X_combined = np.vstack(all_X)
        y_combined = np.hstack(all_y)
        
        logger.info(f"Combined all: {len(X_combined)} sequences, {len(self.global_url_to_label)} classes")
        
        # Split and save
        X_train, X_val, X_test, y_train, y_val, y_test = self._split_data(X_combined, y_combined)
        
        output_dir = self.output_dir / "ClosedWorld_Combined"
        self._save_dataset(X_train, X_val, X_test, y_train, y_val, y_test,
                          output_dir, "NoDef_Combined")


def main():
    parser = argparse.ArgumentParser(description='Merge Shadow WF pickle files')
    parser.add_argument('input_dir', help='Directory containing individual simulation pickle files')
    parser.add_argument('output_dir', help='Output directory for final datasets')
    parser.add_argument('--combine-all', action='store_true',
                        help='Merge all simulations into single dataset (instead of by scale)')
    parser.add_argument('--seed', type=int, default=42,
                        help='Random seed for reproducibility')
    parser.add_argument('--verbose', action='store_true',
                        help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Set random seed
    np.random.seed(args.seed)
    
    # Initialize merger
    merger = PickleMerger(args.input_dir, args.output_dir)
    
    if args.combine_all:
        merger.merge_all_combined()
    else:
        merger.merge_simulations_by_scale()
    
    logger.info("Merging complete!")


if __name__ == "__main__":
    main()