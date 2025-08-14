#!/usr/bin/env python3
"""
Website Fingerprinting Classifiers Implementation
Based on "Data-Explainable Website Fingerprinting with Network Simulation"

Implements the four WF classifiers from the paper:
1. CUMUL - SVM with cumulative direction features
2. k-Fingerprinting (k-FP) - Random Forest + k-NN
3. Deep Fingerprinting (DF) - CNN on directions  
4. Tik-Tok (TT) - CNN on directional timing
"""

import os
import sys
import json
import numpy as np
import pandas as pd
import pickle
from pathlib import Path
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.svm import SVC
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, classification_report
from sklearn.preprocessing import StandardScaler
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
import matplotlib.pyplot as plt
import seaborn as sns

class CellTraceDataset:
    """Cell trace dataset handler"""
    
    def __init__(self, traces_file, max_cells=5000):
        self.max_cells = max_cells
        self.traces = []
        self.labels = []
        self.websites = []
        
        self.load_traces(traces_file)
        
    def load_traces(self, traces_file):
        """Load cell traces from JSON file"""
        with open(traces_file, 'r') as f:
            data = json.load(f)
            
        for trace_data in data:
            cells = trace_data.get('cells', [])
            website = trace_data.get('website', 'unknown')
            
            # Convert cells to direction/timing format
            # Assuming cells are in format [(timestamp, direction), ...]
            if len(cells) > 0:
                directions = []
                timestamps = []
                
                for cell in cells[:self.max_cells]:
                    if isinstance(cell, (list, tuple)) and len(cell) >= 2:
                        timestamp, direction = cell[0], cell[1]
                        timestamps.append(float(timestamp))
                        directions.append(int(direction))
                    else:
                        # Handle different cell formats
                        directions.append(1 if cell > 0 else -1)
                        timestamps.append(0.0)
                
                # Pad sequences to max_cells
                while len(directions) < self.max_cells:
                    directions.append(0)
                    timestamps.append(0.0)
                    
                self.traces.append({
                    'directions': directions[:self.max_cells],
                    'timestamps': timestamps[:self.max_cells],
                    'original_length': len(cells)
                })
                self.websites.append(website)
                
        print(f"Loaded {len(self.traces)} cell traces")
        
    def create_labels(self, sensitive_pages_file):
        """Create labels based on sensitive pages list"""
        with open(sensitive_pages_file, 'r') as f:
            sensitive_pages = set(line.strip() for line in f)
            
        self.labels = []
        for website in self.websites:
            # Extract page name from URL for matching
            page_name = website.split('/')[-1] if '/' in website else website
            if any(sens_page in website or sens_page in page_name for sens_page in sensitive_pages):
                self.labels.append(1)  # Sensitive
            else:
                self.labels.append(0)  # Benign
                
        print(f"Created labels: {sum(self.labels)} sensitive, {len(self.labels) - sum(self.labels)} benign")

class CUMULClassifier:
    """CUMUL classifier implementation"""
    
    def __init__(self):
        self.scaler = StandardScaler()
        self.model = None
        
    def extract_features(self, traces):
        """Extract cumulative direction features"""
        features = []
        
        for trace in traces:
            directions = trace['directions']
            # Cumulative sum of directions
            cumulative = np.cumsum(directions)
            
            # Resize to 100 elements (paper methodology)
            if len(cumulative) > 100:
                # Downsample
                indices = np.linspace(0, len(cumulative)-1, 100, dtype=int)
                feature_vector = cumulative[indices]
            else:
                # Upsample with interpolation
                feature_vector = np.interp(
                    np.linspace(0, len(cumulative)-1, 100),
                    np.arange(len(cumulative)),
                    cumulative
                )
                
            features.append(feature_vector)
            
        return np.array(features)
        
    def train(self, traces, labels):
        """Train CUMUL classifier"""
        features = self.extract_features(traces)
        features_scaled = self.scaler.fit_transform(features)
        
        # Grid search for optimal parameters
        param_grid = {
            'C': [2**i for i in range(-5, 16)],
            'gamma': [2**i for i in range(-15, 4)]
        }
        
        self.model = GridSearchCV(
            SVC(kernel='rbf', probability=True),
            param_grid,
            cv=3,
            scoring='accuracy',
            n_jobs=-1
        )
        
        self.model.fit(features_scaled, labels)
        print(f"CUMUL best parameters: {self.model.best_params_}")
        
    def predict(self, traces):
        """Predict using CUMUL classifier"""
        features = self.extract_features(traces)
        features_scaled = self.scaler.transform(features)
        return self.model.predict(features_scaled)
        
    def predict_proba(self, traces):
        """Predict probabilities"""
        features = self.extract_features(traces)
        features_scaled = self.scaler.transform(features)
        return self.model.predict_proba(features_scaled)

class KFingerprintingClassifier:
    """k-Fingerprinting classifier implementation"""
    
    def __init__(self, k=5):
        self.k = k
        self.rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.knn_model = KNeighborsClassifier(n_neighbors=k, metric='hamming')
        self.is_multiclass = False
        
    def extract_features(self, traces):
        """Extract timing and statistical features"""
        features = []
        
        for trace in traces:
            directions = np.array(trace['directions'])
            timestamps = np.array(trace['timestamps'])
            
            # Statistical features from paper
            feature_vector = []
            
            # Basic statistics
            feature_vector.extend([
                len(directions),  # Total cells
                np.sum(directions == 1),  # Outgoing cells
                np.sum(directions == -1),  # Incoming cells
                np.sum(directions == 0)   # Padding cells
            ])
            
            # Timing features (if available)
            if len(timestamps) > 1:
                inter_arrival_times = np.diff(timestamps[timestamps > 0])
                if len(inter_arrival_times) > 0:
                    feature_vector.extend([
                        np.mean(inter_arrival_times),
                        np.std(inter_arrival_times),
                        np.min(inter_arrival_times),
                        np.max(inter_arrival_times)
                    ])
                else:
                    feature_vector.extend([0, 0, 0, 0])
            else:
                feature_vector.extend([0, 0, 0, 0])
                
            # Burst statistics
            bursts = self._extract_bursts(directions)
            if len(bursts) > 0:
                burst_lengths = [len(burst) for burst in bursts]
                feature_vector.extend([
                    len(bursts),  # Number of bursts
                    np.mean(burst_lengths),  # Mean burst length
                    np.std(burst_lengths) if len(burst_lengths) > 1 else 0
                ])
            else:
                feature_vector.extend([0, 0, 0])
                
            features.append(feature_vector)
            
        return np.array(features)
        
    def _extract_bursts(self, directions):
        """Extract directional bursts"""
        bursts = []
        current_burst = []
        current_direction = None
        
        for direction in directions:
            if direction == 0:  # Skip padding
                continue
                
            if direction == current_direction:
                current_burst.append(direction)
            else:
                if current_burst:
                    bursts.append(current_burst)
                current_burst = [direction]
                current_direction = direction
                
        if current_burst:
            bursts.append(current_burst)
            
        return bursts
        
    def train(self, traces, labels):
        """Train k-Fingerprinting classifier"""
        features = self.extract_features(traces)
        
        # Check if binary or multiclass
        unique_labels = np.unique(labels)
        self.is_multiclass = len(unique_labels) > 2
        
        if self.is_multiclass:
            # Use only Random Forest for multiclass
            self.rf_model.fit(features, labels)
        else:
            # Use two-step process for binary classification
            self.rf_model.fit(features, labels)
            
            # Extract fingerprints (leaf indices)
            fingerprints = self.rf_model.decision_path(features).toarray()
            self.knn_model.fit(fingerprints, labels)
            self.fingerprints_train = fingerprints
            
    def predict(self, traces):
        """Predict using k-Fingerprinting"""
        features = self.extract_features(traces)
        
        if self.is_multiclass:
            return self.rf_model.predict(features)
        else:
            # Two-step binary classification
            fingerprints = self.rf_model.decision_path(features).toarray()
            return self.knn_model.predict(fingerprints)

class DeepFingerprintingNet(nn.Module):
    """Deep Fingerprinting neural network"""
    
    def __init__(self, input_size=5000, num_classes=2):
        super(DeepFingerprintingNet, self).__init__()
        
        self.conv1 = nn.Conv1d(1, 32, kernel_size=8, padding=4)
        self.bn1 = nn.BatchNorm1d(32)
        self.pool1 = nn.MaxPool1d(8, stride=4)
        self.dropout1 = nn.Dropout(0.1)
        
        self.conv2 = nn.Conv1d(32, 64, kernel_size=8, padding=4)
        self.bn2 = nn.BatchNorm1d(64)
        self.pool2 = nn.MaxPool1d(8, stride=4)
        self.dropout2 = nn.Dropout(0.1)
        
        self.conv3 = nn.Conv1d(64, 128, kernel_size=8, padding=4)
        self.bn3 = nn.BatchNorm1d(128)
        self.pool3 = nn.MaxPool1d(8, stride=4)
        self.dropout3 = nn.Dropout(0.1)
        
        # Calculate the size after convolutions
        self._conv_output_size = self._get_conv_output_size(input_size)
        
        self.fc1 = nn.Linear(self._conv_output_size, 512)
        self.dropout4 = nn.Dropout(0.7)
        self.fc2 = nn.Linear(512, 512)
        self.dropout5 = nn.Dropout(0.5)
        self.fc3 = nn.Linear(512, num_classes)
        
    def _get_conv_output_size(self, input_size):
        """Calculate output size after convolutions"""
        x = torch.randn(1, 1, input_size)
        x = self.pool1(torch.relu(self.bn1(self.conv1(x))))
        x = self.pool2(torch.relu(self.bn2(self.conv2(x))))
        x = self.pool3(torch.relu(self.bn3(self.conv3(x))))
        return x.view(1, -1).size(1)
        
    def forward(self, x):
        x = x.unsqueeze(1)  # Add channel dimension
        
        x = self.dropout1(self.pool1(torch.relu(self.bn1(self.conv1(x)))))
        x = self.dropout2(self.pool2(torch.relu(self.bn2(self.conv2(x)))))
        x = self.dropout3(self.pool3(torch.relu(self.bn3(self.conv3(x)))))
        
        x = x.view(x.size(0), -1)  # Flatten
        
        x = self.dropout4(torch.relu(self.fc1(x)))
        x = self.dropout5(torch.relu(self.fc2(x)))
        x = self.fc3(x)
        
        return x

class DeepFingerprintingClassifier:
    """Deep Fingerprinting classifier implementation"""
    
    def __init__(self, num_classes=2, device=None):
        self.num_classes = num_classes
        self.device = device or torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model = None
        
    def train(self, traces, labels, epochs=100, batch_size=32):
        """Train Deep Fingerprinting classifier"""
        # Prepare data
        X = np.array([trace['directions'] for trace in traces], dtype=np.float32)
        y = np.array(labels, dtype=np.long)
        
        # Create model
        self.model = DeepFingerprintingNet(
            input_size=X.shape[1], 
            num_classes=self.num_classes
        ).to(self.device)
        
        # Create dataset and dataloader
        dataset = torch.utils.data.TensorDataset(
            torch.FloatTensor(X),
            torch.LongTensor(y)
        )
        dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
        
        # Training setup
        criterion = nn.CrossEntropyLoss()
        optimizer = optim.Adam(self.model.parameters(), lr=0.002)
        
        # Training loop
        self.model.train()
        for epoch in range(epochs):
            total_loss = 0
            for batch_x, batch_y in dataloader:
                batch_x, batch_y = batch_x.to(self.device), batch_y.to(self.device)
                
                optimizer.zero_grad()
                outputs = self.model(batch_x)
                loss = criterion(outputs, batch_y)
                loss.backward()
                optimizer.step()
                
                total_loss += loss.item()
                
            if epoch % 10 == 0:
                print(f"DF Epoch {epoch}/{epochs}, Loss: {total_loss/len(dataloader):.4f}")
                
    def predict(self, traces):
        """Predict using Deep Fingerprinting"""
        X = np.array([trace['directions'] for trace in traces], dtype=np.float32)
        X_tensor = torch.FloatTensor(X).to(self.device)
        
        self.model.eval()
        with torch.no_grad():
            outputs = self.model(X_tensor)
            predictions = torch.argmax(outputs, dim=1)
            
        return predictions.cpu().numpy()

class TikTokClassifier(DeepFingerprintingClassifier):
    """Tik-Tok classifier implementation (extends Deep Fingerprinting)"""
    
    def train(self, traces, labels, epochs=100, batch_size=32):
        """Train Tik-Tok classifier using directional timing"""
        # Prepare data with timing information
        X = []
        for trace in traces:
            directions = np.array(trace['directions'])
            timestamps = np.array(trace['timestamps'])
            
            # Create directional timing features (t_i * d_i)
            directional_timing = timestamps * directions
            X.append(directional_timing)
            
        X = np.array(X, dtype=np.float32)
        y = np.array(labels, dtype=np.long)
        
        # Create model
        self.model = DeepFingerprintingNet(
            input_size=X.shape[1],
            num_classes=self.num_classes
        ).to(self.device)
        
        # Create dataset and dataloader
        dataset = torch.utils.data.TensorDataset(
            torch.FloatTensor(X),
            torch.LongTensor(y)
        )
        dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
        
        # Training setup
        criterion = nn.CrossEntropyLoss()
        optimizer = optim.Adam(self.model.parameters(), lr=0.002)
        
        # Training loop
        self.model.train()
        for epoch in range(epochs):
            total_loss = 0
            for batch_x, batch_y in dataloader:
                batch_x, batch_y = batch_x.to(self.device), batch_y.to(self.device)
                
                optimizer.zero_grad()
                outputs = self.model(batch_x)
                loss = criterion(outputs, batch_y)
                loss.backward()
                optimizer.step()
                
                total_loss += loss.item()
                
            if epoch % 10 == 0:
                print(f"TT Epoch {epoch}/{epochs}, Loss: {total_loss/len(dataloader):.4f}")
                
    def predict(self, traces):
        """Predict using Tik-Tok classifier"""
        X = []
        for trace in traces:
            directions = np.array(trace['directions'])
            timestamps = np.array(trace['timestamps'])
            directional_timing = timestamps * directions
            X.append(directional_timing)
            
        X = np.array(X, dtype=np.float32)
        X_tensor = torch.FloatTensor(X).to(self.device)
        
        self.model.eval()
        with torch.no_grad():
            outputs = self.model(X_tensor)
            predictions = torch.argmax(outputs, dim=1)
            
        return predictions.cpu().numpy()

class WFExperimentRunner:
    """Website Fingerprinting experiment runner"""
    
    def __init__(self, data_dir):
        self.data_dir = Path(data_dir)
        self.results = {}
        
    def run_experiments(self):
        """Run WF experiments with all classifiers"""
        print("=== Website Fingerprinting Experiment Runner ===")
        
        # Load data
        traces_file = self.data_dir / "extracted_cell_traces.json"
        if not traces_file.exists():
            print(f"Error: Cell traces file not found: {traces_file}")
            return
            
        dataset = CellTraceDataset(traces_file)
        
        # Create labels
        sensitive_pages_file = "W_alpha_pages.txt"
        if Path(sensitive_pages_file).exists():
            dataset.create_labels(sensitive_pages_file)
        else:
            print("Warning: Sensitive pages file not found, using random labels")
            dataset.labels = np.random.randint(0, 2, len(dataset.traces))
            
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            dataset.traces, dataset.labels, test_size=0.4, 
            random_state=42, stratify=dataset.labels
        )
        
        print(f"Training set: {len(X_train)} traces")
        print(f"Test set: {len(X_test)} traces")
        
        # Initialize classifiers
        classifiers = {
            'CUMUL': CUMULClassifier(),
            'k-FP': KFingerprintingClassifier(),
            'DF': DeepFingerprintingClassifier(num_classes=len(np.unique(dataset.labels))),
            'TT': TikTokClassifier(num_classes=len(np.unique(dataset.labels)))
        }
        
        # Run experiments
        for name, classifier in classifiers.items():
            print(f"\n--- Training {name} ---")
            
            try:
                # Train classifier
                classifier.train(X_train, y_train)
                
                # Make predictions
                y_pred = classifier.predict(X_test)
                
                # Calculate metrics
                accuracy = accuracy_score(y_test, y_pred)
                precision, recall, f1, _ = precision_recall_fscore_support(
                    y_test, y_pred, average='binary' if len(np.unique(dataset.labels)) == 2 else 'weighted'
                )
                
                self.results[name] = {
                    'accuracy': accuracy,
                    'precision': precision,
                    'recall': recall,
                    'f1': f1,
                    'predictions': y_pred.tolist(),
                    'true_labels': y_test
                }
                
                print(f"{name} Results:")
                print(f"  Accuracy: {accuracy:.4f}")
                print(f"  Precision: {precision:.4f}")
                print(f"  Recall: {recall:.4f}")
                print(f"  F1-Score: {f1:.4f}")
                
            except Exception as e:
                print(f"Error training {name}: {e}")
                self.results[name] = {'error': str(e)}
                
        # Save results
        self.save_results()
        self.generate_plots()
        
    def save_results(self):
        """Save experiment results"""
        results_file = self.data_dir / "wf_experiment_results.json"
        
        # Convert numpy arrays to lists for JSON serialization
        serializable_results = {}
        for name, metrics in self.results.items():
            serializable_results[name] = {}
            for key, value in metrics.items():
                if isinstance(value, np.ndarray):
                    serializable_results[name][key] = value.tolist()
                else:
                    serializable_results[name][key] = value
                    
        with open(results_file, 'w') as f:
            json.dump(serializable_results, f, indent=2)
            
        print(f"\nResults saved to {results_file}")
        
    def generate_plots(self):
        """Generate visualization plots"""
        try:
            # Create results comparison plot
            classifiers = []
            accuracies = []
            
            for name, metrics in self.results.items():
                if 'accuracy' in metrics:
                    classifiers.append(name)
                    accuracies.append(metrics['accuracy'])
                    
            if len(classifiers) > 0:
                plt.figure(figsize=(10, 6))
                bars = plt.bar(classifiers, accuracies)
                plt.title('Website Fingerprinting Classifier Comparison')
                plt.ylabel('Accuracy')
                plt.ylim(0, 1)
                
                # Add value labels on bars
                for bar, acc in zip(bars, accuracies):
                    plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
                            f'{acc:.3f}', ha='center', va='bottom')
                            
                plt.tight_layout()
                plt.savefig(self.data_dir / 'classifier_comparison.png', dpi=300, bbox_inches='tight')
                plt.close()
                
                print(f"Plots saved to {self.data_dir}")
                
        except Exception as e:
            print(f"Error generating plots: {e}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Website Fingerprinting Classifier Experiments')
    parser.add_argument('data_dir', nargs='?', default='wf_simulation_data/tornet-0.05-base',
                       help='Directory containing simulation data')
    parser.add_argument('--compare-configs', action='store_true',
                       help='Compare results across multiple configurations')
    parser.add_argument('--classifier', choices=['CUMUL', 'k-FP', 'DF', 'TT'],
                       help='Run only specific classifier')
    
    args = parser.parse_args()
    
    if args.compare_configs:
        print("Configuration comparison not yet implemented")
        # TODO: Implement cross-configuration robustness analysis
    else:
        # Run single configuration experiment
        runner = WFExperimentRunner(args.data_dir)
        runner.run_experiments()

if __name__ == "__main__":
    main()