#!/usr/bin/env python3
"""
Website dataset generator for Website Fingerprinting research
Implements the random walk methodology from the paper to create W_α, W_β, and W_∅ sets.
"""

import os
import random
import requests
import time
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import json
from pathlib import Path

class WikipediaWalkGenerator:
    def __init__(self, zimply_host="localhost", zimply_port=8080):
        self.zimply_base_url = f"http://{zimply_host}:{zimply_port}"
        self.visited_pages = set()
        self.W_alpha = []  # Sensitive pages (98 total)
        self.W_beta = []   # Benign pages  
        self.W_empty = []  # Unlabeled pages
        
    def get_page_links(self, page_url):
        """Extract links from a Wikipedia page served by zimply"""
        try:
            response = requests.get(page_url, timeout=10)
            if response.status_code != 200:
                return []
                
            soup = BeautifulSoup(response.content, 'html.parser')
            links = []
            
            # Find all Wikipedia article links
            for link in soup.find_all('a', href=True):
                href = link['href']
                # Filter for Wikipedia article links (not external, not special pages)
                if (href.startswith('/') and 
                    not href.startswith('/wiki/File:') and
                    not href.startswith('/wiki/Category:') and
                    not href.startswith('/wiki/Template:') and
                    not href.startswith('/wiki/Special:') and
                    ':' not in href.split('/')[-1]):  # Avoid namespace pages
                    
                    full_url = urljoin(self.zimply_base_url, href)
                    links.append(full_url)
                    
            return links[:50]  # Limit to prevent excessive memory usage
            
        except Exception as e:
            print(f"Error fetching links from {page_url}: {e}")
            return []
    
    def random_walk(self, start_url, max_depth, max_pages_per_walk=100):
        """Perform random walk starting from given URL"""
        current_url = start_url
        walk_pages = []
        depth = 0
        
        while depth < max_depth and len(walk_pages) < max_pages_per_walk:
            if current_url in self.visited_pages:
                # Find new starting point
                links = self.get_page_links(current_url)
                if not links:
                    break
                current_url = random.choice(links)
                continue
                
            # Add current page to walk
            walk_pages.append(current_url)
            self.visited_pages.add(current_url)
            
            # Get links from current page
            links = self.get_page_links(current_url)
            if not links:
                break
                
            # Choose random next page
            current_url = random.choice(links)
            depth += 1
            
            # Small delay to be respectful to server
            time.sleep(0.1)
            
        return walk_pages
    
    def generate_sensitive_pages(self, num_walks=10, walk_depth=10):
        """Generate W_α (sensitive pages) using random walks - Paper methodology"""
        print(f"Generating sensitive pages (W_α) with {num_walks} walks of depth {walk_depth}...")
        
        index_url = f"{self.zimply_base_url}/index.html"
        
        for walk_num in range(num_walks):
            print(f"  Walk {walk_num + 1}/{num_walks}")
            
            # Start each walk from index page
            walk_pages = self.random_walk(index_url, walk_depth)
            self.W_alpha.extend(walk_pages)
            
            # Remove duplicates and limit to 98 pages as per paper
            self.W_alpha = list(set(self.W_alpha))
            if len(self.W_alpha) >= 98:
                self.W_alpha = self.W_alpha[:98]
                break
                
        print(f"Generated {len(self.W_alpha)} sensitive pages")
        return self.W_alpha
    
    def generate_benign_unlabeled_pages(self, num_walks=100, walk_depth=1000):
        """Generate W_β and W_∅ (benign and unlabeled pages) - Paper methodology"""
        print(f"Generating benign/unlabeled pages with {num_walks} walks of depth {walk_depth}...")
        
        index_url = f"{self.zimply_base_url}/index.html"
        all_pages = []
        
        for walk_num in range(num_walks):
            if walk_num % 10 == 0:
                print(f"  Walk {walk_num + 1}/{num_walks}")
                
            # Longer walks for broader coverage
            walk_pages = self.random_walk(index_url, walk_depth, max_pages_per_walk=200)
            all_pages.extend(walk_pages)
            
            # Remove duplicates periodically to manage memory
            if walk_num % 20 == 0:
                all_pages = list(set(all_pages))
                
        # Remove duplicates and pages already in W_α
        all_pages = list(set(all_pages))
        all_pages = [page for page in all_pages if page not in self.W_alpha]
        
        # Split into W_β and W_∅
        random.shuffle(all_pages)
        mid_point = len(all_pages) // 2
        self.W_beta = all_pages[:mid_point]
        self.W_empty = all_pages[mid_point:]
        
        print(f"Generated {len(self.W_beta)} benign pages and {len(self.W_empty)} unlabeled pages")
        return self.W_beta, self.W_empty
    
    def save_page_lists(self):
        """Save generated page lists to files"""
        print("Saving page lists...")
        
        # Save W_α (sensitive pages)
        with open("W_alpha_pages.txt", "w") as f:
            f.write("\n".join(self.W_alpha))
            
        # Save W_β (benign pages)  
        with open("W_beta_pages.txt", "w") as f:
            f.write("\n".join(self.W_beta))
            
        # Save W_∅ (unlabeled pages)
        with open("W_empty_pages.txt", "w") as f:
            f.write("\n".join(self.W_empty))
            
        # Save summary statistics
        summary = {
            "sensitive_pages": len(self.W_alpha),
            "benign_pages": len(self.W_beta), 
            "unlabeled_pages": len(self.W_empty),
            "total_unique_pages": len(self.W_alpha) + len(self.W_beta) + len(self.W_empty),
            "total_pages_visited": len(self.visited_pages)
        }
        
        with open("website_generation_summary.json", "w") as f:
            json.dump(summary, f, indent=2)
            
        print("Page lists saved:")
        print(f"  W_α (sensitive): {len(self.W_alpha)} pages")
        print(f"  W_β (benign): {len(self.W_beta)} pages") 
        print(f"  W_∅ (unlabeled): {len(self.W_empty)} pages")
        
    def validate_page_accessibility(self):
        """Validate that generated pages are accessible via zimply"""
        print("Validating page accessibility...")
        
        test_pages = (self.W_alpha[:5] + self.W_beta[:5] + self.W_empty[:5])
        accessible_count = 0
        
        for page_url in test_pages:
            try:
                response = requests.get(page_url, timeout=5)
                if response.status_code == 200:
                    accessible_count += 1
                else:
                    print(f"  Warning: {page_url} returned status {response.status_code}")
            except Exception as e:
                print(f"  Error accessing {page_url}: {e}")
                
        print(f"Validation complete: {accessible_count}/{len(test_pages)} test pages accessible")
        return accessible_count == len(test_pages)

class WikipediaPageURLGenerator:
    """Alternative generator for when zimply is not running - creates realistic Wikipedia URLs"""
    
    def __init__(self):
        # Common Wikipedia article patterns based on actual English Wikipedia
        self.article_patterns = [
            "Geography/", "History/", "Science/", "Technology/", "Arts/", "Culture/",
            "Biography/", "Sports/", "Politics/", "Literature/", "Music/", "Film/"
        ]
        
        self.common_topics = [
            "United_States", "World_War_II", "Climate_change", "Artificial_intelligence",
            "COVID-19_pandemic", "European_Union", "Machine_learning", "Quantum_physics",
            "Renaissance", "Industrial_Revolution", "DNA", "Solar_system", "Democracy",
            "Human_rights", "Internet", "Cryptocurrency", "Space_exploration", "Evolution"
        ]
        
    def generate_realistic_urls(self, num_sensitive=98, num_benign=33859, num_unlabeled=33859):
        """Generate realistic Wikipedia URLs when live crawling isn't possible"""
        
        all_pages = []
        
        # Generate base article names
        for pattern in self.article_patterns:
            for topic in self.common_topics:
                for i in range(50):  # Generate variations
                    article_name = f"{pattern}{topic}_{i}"
                    url = f"http://localhost:8080/wiki/{article_name}"
                    all_pages.append(url)
                    
        # Add more diverse articles
        for i in range(100000):
            article_name = f"Article_{i:06d}"
            url = f"http://localhost:8080/wiki/{article_name}"
            all_pages.append(url)
            
        # Shuffle and split
        random.shuffle(all_pages)
        
        W_alpha = all_pages[:num_sensitive]
        W_beta = all_pages[num_sensitive:num_sensitive + num_benign]
        W_empty = all_pages[num_sensitive + num_benign:num_sensitive + num_benign + num_unlabeled]
        
        return W_alpha, W_beta, W_empty

def main():
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--generate-urls-only":
        # Generate realistic URLs without crawling (for testing)
        print("Generating realistic Wikipedia URLs (no crawling)...")
        generator = WikipediaPageURLGenerator()
        W_alpha, W_beta, W_empty = generator.generate_realistic_urls()
        
        # Save to files
        with open("W_alpha_pages.txt", "w") as f:
            f.write("\n".join(W_alpha))
        with open("W_beta_pages.txt", "w") as f:
            f.write("\n".join(W_beta))
        with open("W_empty_pages.txt", "w") as f:
            f.write("\n".join(W_empty))
            
        print(f"Generated {len(W_alpha)} sensitive, {len(W_beta)} benign, {len(W_empty)} unlabeled URLs")
        
    else:
        # Full random walk generation (requires running zimply server)
        print("Starting Wikipedia random walk generation...")
        print("Note: This requires a running zimply server on localhost:8080")
        
        generator = WikipediaWalkGenerator()
        
        # Check if zimply is accessible
        try:
            response = requests.get(f"{generator.zimply_base_url}/index.html", timeout=5)
            if response.status_code != 200:
                print("Error: Cannot access zimply server. Please ensure zimply is running on localhost:8080")
                print("Alternatively, use --generate-urls-only for testing")
                sys.exit(1)
        except Exception as e:
            print(f"Error: Cannot connect to zimply server: {e}")
            print("Alternatively, use --generate-urls-only for testing")
            sys.exit(1)
            
        # Generate page sets using paper methodology
        generator.generate_sensitive_pages(num_walks=10, walk_depth=10)
        generator.generate_benign_unlabeled_pages(num_walks=100, walk_depth=1000)
        
        # Validate and save
        generator.validate_page_accessibility()
        generator.save_page_lists()
        
        print("\nWebsite generation complete!")
        print("Files created:")
        print("  - W_alpha_pages.txt (sensitive pages)")
        print("  - W_beta_pages.txt (benign pages)")
        print("  - W_empty_pages.txt (unlabeled pages)")
        print("  - website_generation_summary.json")

if __name__ == "__main__":
    main()