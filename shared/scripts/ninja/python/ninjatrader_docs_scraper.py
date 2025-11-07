import requests
from bs4 import BeautifulSoup, Tag
import html2text
import time
from urllib.parse import urljoin, urlparse
import os
import re
from typing import Optional, Set, List, Dict, Union, Any

class NinjaTraderDocsScraper:
    def __init__(self, base_url: str = "https://developer.ninjatrader.com/docs/desktop"):
        self.base_url = base_url
        self.domain = "https://developer.ninjatrader.com"
        self.visited_urls: Set[str] = set()
        self.h2t = html2text.HTML2Text()
        self.h2t.ignore_links = False
        self.h2t.ignore_images = False
        self.h2t.body_width = 0  # Don't wrap lines
        
    def clean_url(self, url: str) -> str:
        """Remove fragments and normalize URL"""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    
    def get_page_content(self, url: str) -> Optional[str]:
        """Fetch and parse a single page"""
        try:
            print(f"Fetching: {url}")
            response = requests.get(url, timeout=30, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            response.raise_for_status()
            return response.text
        except Exception as e:
            print(f"Error fetching {url}: {str(e)}")
            return None
    
    def extract_content(self, html: str, url: str) -> str:
        """Extract the main content from the page"""
        soup = BeautifulSoup(html, 'html.parser')
        
        # Debug: Print page structure
        print(f"\nAnalyzing page structure for: {url}")
        
        # Try multiple content extraction strategies
        content: Optional[Tag] = None
        
        # Strategy 1: Look for main content divs
        content_selectors = [
            'main',
            'article', 
            '.content',
            '.main',
            '.documentation',
            '.doc-content',
            '#content',
            '[role="main"]'
        ]
        
        for selector in content_selectors:
            found = soup.select_one(selector)
            if found and isinstance(found, Tag):
                content = found
                print(f"  Found content with selector: {selector}")
                break
        
        # Strategy 2: Look for the largest text block
        if not content:
            content = self.find_largest_text_block(soup)
            if content:
                print("  Using largest text block strategy")
        
        # Strategy 3: Get body without navigation
        if not content:
            content = self.get_body_without_nav(soup)
            if content:
                print("  Using body without nav strategy")
        
        if not content:
            print("  No content found with any strategy")
            # Last resort: get all text
            body = soup.find('body')
            if body and isinstance(body, Tag):
                content = body
        
        if content and isinstance(content, Tag):
            # Remove unwanted elements
            for element in content.select('nav, header, footer, .nav, .navigation, .sidebar, script, style, .header, .footer'):
                element.decompose()
            
            # Extract text
            text_content = content.get_text(separator='\n', strip=True)
            
            # Only process if there's substantial content
            if len(text_content) > 100:
                # Convert to markdown
                markdown = self.h2t.handle(str(content))
                
                # Get page title
                title_elem = soup.find('title')
                title_text = title_elem.get_text(strip=True) if title_elem and isinstance(title_elem, Tag) else "Untitled"
                
                # Add metadata
                return f"\n\n# {title_text}\n\n**Source:** {url}\n\n{markdown}\n\n---\n\n"
            else:
                print(f"  Page has minimal content ({len(text_content)} chars)")
        
        return ""
    
    def find_largest_text_block(self, soup: BeautifulSoup) -> Optional[Tag]:
        """Find the div with the most text content"""
        max_text_length = 0
        best_div: Optional[Tag] = None
        
        for div in soup.find_all('div'):
            if isinstance(div, Tag):
                text_length = len(div.get_text(strip=True))
                if text_length > max_text_length:
                    max_text_length = text_length
                    best_div = div
        
        return best_div
    
    def get_body_without_nav(self, soup: BeautifulSoup) -> Optional[Tag]:
        """Get body content excluding navigation elements"""
        body = soup.find('body')
        if body and isinstance(body, Tag):
            # Clone the body
            body_copy = BeautifulSoup(str(body), 'html.parser')
            body_elem = body_copy.find('body')
            if body_elem and isinstance(body_elem, Tag):
                # Remove navigation elements
                for nav in body_elem.select('nav, .nav, .navigation, header, footer'):
                    nav.decompose()
                return body_elem
        return None
    
    def find_documentation_links(self, html: str, current_url: str) -> Set[str]:
        """Extract all documentation links from a page"""
        soup = BeautifulSoup(html, 'html.parser')
        links: Set[str] = set()
        
        # Debug: Show what links we're finding
        print(f"\nFinding links on: {current_url}")
        
        # Find all links
        all_links = soup.find_all('a', href=True)
        print(f"  Found {len(all_links)} total links")
        
        for link_elem in all_links:
            if isinstance(link_elem, Tag) and link_elem.get('href'):
                href = str(link_elem.get('href', ''))
                
                # Convert relative URLs to absolute
                absolute_url = urljoin(current_url, href)
                
                # Clean the URL (remove fragments)
                absolute_url = self.clean_url(absolute_url)
                
                # Only include links within the documentation domain
                if absolute_url.startswith(self.domain) and '/docs/' in absolute_url:
                    # Skip certain file types and already visited
                    if not any(absolute_url.endswith(ext) for ext in ['.pdf', '.zip', '.exe', '.dmg', '.png', '.jpg', '.gif']):
                        if absolute_url not in self.visited_urls:
                            links.add(absolute_url)
        
        print(f"  Found {len(links)} new documentation links")
        return links
    
    def analyze_page_structure(self, url: str) -> None:
        """Analyze and print the structure of a page for debugging"""
        print(f"\n{'='*60}")
        print(f"ANALYZING PAGE STRUCTURE: {url}")
        print(f"{'='*60}")
        
        html = self.get_page_content(url)
        if not html:
            print("Failed to fetch page")
            return
        
        soup = BeautifulSoup(html, 'html.parser')
        
        # Print all divs with their classes and IDs
        print("\nMain container elements:")
        for elem in soup.find_all(['div', 'main', 'article', 'section'])[:20]:
            if isinstance(elem, Tag):
                classes = elem.get('class')
                if classes is None:
                    classes = []
                elif not isinstance(classes, list):
                    classes = [str(classes)]
                elem_id = elem.get('id', '')
                text_preview = elem.get_text(strip=True)[:100]
                if classes or elem_id:
                    print(f"  <{elem.name} class='{' '.join(classes)}' id='{elem_id}'> - {len(elem.get_text(strip=True))} chars")
                    if text_preview:
                        print(f"    Preview: {text_preview}...")
    
    def scrape_recursive(self, url: str, output_file: str, max_depth: int = 5, current_depth: int = 0) -> None:
        """Recursively scrape documentation pages"""
        if current_depth > max_depth:
            return
        
        # Clean and check if already visited
        clean_url = self.clean_url(url)
        if clean_url in self.visited_urls:
            return
        
        self.visited_urls.add(clean_url)
        
        # Analyze first page structure (for debugging)
        if len(self.visited_urls) == 1:
            self.analyze_page_structure(clean_url)
        
        # Get page content
        html = self.get_page_content(clean_url)
        if not html:
            return
        
        # Extract and save content
        content = self.extract_content(html, clean_url)
        if content and len(content) > 200:  # Only save if substantial content
            with open(output_file, 'a', encoding='utf-8') as f:
                f.write(content)
            print(f"  ✓ Content extracted and saved")
        else:
            print(f"  ✗ No substantial content found")
        
        # Find and process links
        links = self.find_documentation_links(html, clean_url)
        
        # Process each link
        for link in sorted(links):
            time.sleep(1)  # Be polite to the server
            self.scrape_recursive(link, output_file, max_depth, current_depth + 1)
    
    def scrape_all(self, output_file: str = "ninjatrader_docs.md") -> None:
        """Main method to scrape all documentation"""
        print(f"Starting scrape of {self.base_url}")
        print(f"Output will be saved to: {output_file}")
        
        # Clear/create output file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("# NinjaTrader Desktop SDK Documentation\n\n")
            f.write(f"Scraped from: {self.base_url}\n\n")
            f.write("---\n\n")
        
        # Start recursive scraping
        self.scrape_recursive(self.base_url, output_file)
        
        print(f"\nScraping complete! Processed {len(self.visited_urls)} pages.")
        print(f"Documentation saved to: {output_file}")

def main():
    print("NinjaTrader Documentation Scraper")
    print("=================================\n")
    
    # Create scraper instance
    scraper = NinjaTraderDocsScraper()
    
    # Run the scraper
    scraper.scrape_all("ninjatrader_desktop_sdk_docs.md")
    
    # Show summary
    print("\n" + "="*60)
    print("SCRAPING SUMMARY")
    print("="*60)
    print(f"Total pages processed: {len(scraper.visited_urls)}")
    print(f"Output file: ninjatrader_desktop_sdk_docs.md")
    
    # Check file size
    if os.path.exists("ninjatrader_desktop_sdk_docs.md"):
        size = os.path.getsize("ninjatrader_desktop_sdk_docs.md")
        print(f"File size: {size:,} bytes ({size/1024:.1f} KB)")

if __name__ == "__main__":
    main()