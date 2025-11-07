import requests
from bs4 import BeautifulSoup, Tag
from bs4.element import NavigableString
import json
import time
from urllib.parse import urljoin, urlparse
from typing import Optional, List, Dict, Any, Union

class NinjaTraderAPIScraper:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.base_url = "https://developer.ninjatrader.com"
        self.visited: set[str] = set()
        
    def get_api_endpoints(self) -> None:
        """Try to find API documentation structure"""
        # Common API documentation patterns
        api_urls = [
            "/docs/desktop",
            "/docs/desktop/api",
            "/docs/desktop/reference",
            "/api/desktop",
            "/reference/desktop"
        ]
        
        print("Searching for API documentation structure...")
        
        for path in api_urls:
            url = self.base_url + path
            try:
                resp = self.session.get(url, timeout=10)
                if resp.status_code == 200:
                    print(f"✓ Found content at: {url}")
                    self.analyze_api_page(url, resp.text)
            except Exception as e:
                print(f"✗ No content at: {url} - {str(e)}")
                
    def analyze_api_page(self, url: str, html: str) -> None:
        """Analyze the structure of an API documentation page"""
        soup = BeautifulSoup(html, 'html.parser')
        
        print(f"\nAnalyzing: {url}")
        print("-" * 50)
        
        # Look for API method listings
        # Common patterns in API docs
        patterns: List[tuple[str, str]] = [
            # Method/class listings
            ('a[href*="method"]', "Methods"),
            ('a[href*="class"]', "Classes"),
            ('a[href*="property"]', "Properties"),
            ('a[href*="event"]', "Events"),
            ('a[href*="enum"]', "Enums"),
            
            # Documentation sections
            ('.method', "Method sections"),
            ('.class', "Class sections"),
            ('.api-item', "API items"),
            ('[class*="method"]', "Method elements"),
            ('[class*="class"]', "Class elements"),
            
            # Code blocks
            ('pre', "Code blocks"),
            ('code', "Inline code"),
            ('.code-block', "Code block divs"),
            
            # Navigation/TOC
            ('.toc a', "TOC links"),
            ('.nav a', "Nav links"),
            ('[class*="navigation"] a', "Navigation links"),
            ('[class*="sidebar"] a', "Sidebar links")
        ]
        
        for selector, description in patterns:
            elements = soup.select(selector)
            if elements:
                print(f"\nFound {len(elements)} {description}:")
                for elem in elements[:5]:  # Show first 5
                    text = elem.get_text(strip=True)[:50]
                    if elem.name == 'a' and elem.get('href'):
                        href = elem.get('href', '')
                        print(f"  - {text}... -> {href}")
                    else:
                        print(f"  - {text}...")
                        
    def extract_documentation_content(self, url: str) -> Optional[Dict[str, Any]]:
        """Extract actual documentation content from a page"""
        if url in self.visited:
            return None
            
        self.visited.add(url)
        
        try:
            print(f"\nExtracting content from: {url}")
            resp = self.session.get(url, timeout=10)
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            # Remove script and style elements
            for script in soup(["script", "style"]):
                script.decompose()
                
            # Try to find main content area
            content: Optional[Union[Tag, NavigableString]] = None
            
            # Strategy 1: Look for main content containers
            selectors = [
                'main',
                '[role="main"]',
                '#main-content',
                '.main-content',
                '.content',
                '.documentation',
                'article',
                '.doc-content',
                '.api-content'
            ]
            
            for selector in selectors:
                found = soup.select_one(selector)
                if found and isinstance(found, Tag):
                    content = found
                    break
                    
            # Strategy 2: If no main content found, get the body
            if not content:
                body = soup.find('body')
                if body and isinstance(body, Tag):
                    content = body
                    
            if content and isinstance(content, Tag):
                # Remove navigation elements
                for nav in content.select('nav, header, footer, .nav, .navigation, .header, .footer'):
                    nav.decompose()
                    
                # Extract text
                text = content.get_text(separator='\n', strip=True)
                
                # Extract code examples
                code_blocks: List[str] = []
                for block in content.find_all(['pre', 'code']):
                    if isinstance(block, Tag):
                        code_blocks.append(block.get_text(strip=True))
                
                title_elem = soup.find('title')
                title = title_elem.get_text(strip=True) if title_elem and isinstance(title_elem, Tag) else 'Untitled'
                
                return {
                    'url': url,
                    'title': title,
                    'text': text,
                    'code_examples': code_blocks
                }
                
        except Exception as e:
            print(f"Error extracting {url}: {e}")
            
        return None
        
    def scrape_from_sitemap(self) -> List[str]:
        """Try to find and parse sitemap for documentation URLs"""
        sitemap_urls = [
            "/sitemap.xml",
            "/sitemap_index.xml",
            "/docs/sitemap.xml"
        ]
        
        print("\nLooking for sitemap...")
        
        for sitemap_path in sitemap_urls:
            url = self.base_url + sitemap_path
            try:
                resp = self.session.get(url, timeout=10)
                if resp.status_code == 200:
                    print(f"✓ Found sitemap at: {url}")
                    soup = BeautifulSoup(resp.text, 'xml')
                    
                    urls = soup.find_all('loc')
                    doc_urls = [u.get_text() for u in urls if '/docs/' in u.get_text()]
                    
                    print(f"Found {len(doc_urls)} documentation URLs")
                    return doc_urls
                    
            except Exception as e:
                continue
                
        return []
        
    def save_documentation(self, output_file: str = "ninjatrader_api_docs.json") -> None:
        """Save all collected documentation"""
        print(f"\nSaving documentation to {output_file}")
        
        # First, try to get URLs from sitemap
        doc_urls = self.scrape_from_sitemap()
        
        # If no sitemap, try to crawl from known starting points
        if not doc_urls:
            print("No sitemap found, starting manual crawl...")
            self.get_api_endpoints()
            
        # Extract content from all found URLs
        all_docs: List[Dict[str, Any]] = []
        
        for url in doc_urls[:50]:  # Limit to first 50 for testing
            if '/docs/desktop' in url:
                content = self.extract_documentation_content(url)
                if content and len(content['text']) > 100:
                    all_docs.append(content)
                    print(f"✓ Extracted: {content['title']}")
                    
                time.sleep(0.5)  # Be polite
                
        # Save as JSON for easier processing
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(all_docs, f, indent=2, ensure_ascii=False)
            
        # Also create a markdown version
        md_file = output_file.replace('.json', '.md')
        with open(md_file, 'w', encoding='utf-8') as f:
            f.write("# NinjaTrader Desktop SDK Documentation\n\n")
            
            for doc in all_docs:
                f.write(f"\n## {doc['title']}\n\n")
                f.write(f"**Source:** {doc['url']}\n\n")
                f.write(doc['text'][:1000])  # First 1000 chars
                f.write("\n\n")
                
                if doc['code_examples']:
                    f.write("### Code Examples:\n\n")
                    for code in doc['code_examples'][:3]:  # First 3 examples
                        f.write("```csharp\n")
                        f.write(code)
                        f.write("\n```\n\n")
                        
                f.write("---\n\n")
                
        print(f"\nDocumentation saved to:")
        print(f"  - {output_file} (JSON format)")
        print(f"  - {md_file} (Markdown format)")
        print(f"Total pages extracted: {len(all_docs)}")

def main():
    scraper = NinjaTraderAPIScraper()
    
    # First, analyze the structure
    print("Starting NinjaTrader API documentation analysis...")
    scraper.get_api_endpoints()
    
    # Then scrape and save
    input("\nPress Enter to start scraping...")
    scraper.save_documentation()

if __name__ == "__main__":
    main()