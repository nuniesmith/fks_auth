import time
import json
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from urllib.parse import urljoin, urlparse
from typing import Set, List, Dict, Optional, Any
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class NinjaTraderSeleniumScraper:
    def __init__(self, headless: bool = True):
        self.base_url = "https://developer.ninjatrader.com/docs/desktop"
        self.visited_urls: Set[str] = set()
        self.failed_urls: Set[str] = set()
        self.content_data: List[Dict[str, Any]] = []
        
        # Setup Chrome options
        self.chrome_options = Options()
        if headless:
            self.chrome_options.add_argument("--headless")
        self.chrome_options.add_argument("--no-sandbox")
        self.chrome_options.add_argument("--disable-dev-shm-usage")
        self.chrome_options.add_argument("--disable-gpu")
        self.chrome_options.add_argument("--window-size=1920,1080")
        self.chrome_options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        
        # Initialize driver
        self.driver = None
        
    def start_driver(self):
        """Initialize the Chrome driver"""
        try:
            self.driver = webdriver.Chrome(options=self.chrome_options)
            logger.info("Chrome driver initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Chrome driver: {e}")
            logger.info("Make sure you have Chrome and ChromeDriver installed")
            logger.info("Install ChromeDriver: https://chromedriver.chromium.org/")
            raise
            
    def close_driver(self):
        """Close the Chrome driver"""
        if self.driver:
            self.driver.quit()
            logger.info("Chrome driver closed")
            
    def wait_for_content(self, timeout: int = 10) -> bool:
        """Wait for main content to load"""
        try:
            # Check if driver is initialized
            if self.driver is None:
                logger.error("Driver is not initialized")
                return False
                
            # Wait for common content indicators
            wait = WebDriverWait(self.driver, timeout)
            
            # Try multiple strategies to detect content
            content_selectors = [
                (By.CSS_SELECTOR, "main"),
                (By.CSS_SELECTOR, "article"),
                (By.CSS_SELECTOR, ".documentation"),
                (By.CSS_SELECTOR, ".content"),
                (By.CSS_SELECTOR, "[role='main']"),
                (By.CSS_SELECTOR, ".doc-content"),
                (By.CSS_SELECTOR, "#content")
            ]
            
            for selector in content_selectors:
                try:
                    element = wait.until(EC.presence_of_element_located(selector))
                    if element and len(element.text.strip()) > 100:
                        return True
                except TimeoutException:
                    continue
                    
            # If no specific content area found, check if body has substantial text
            body = self.driver.find_element(By.TAG_NAME, "body")
            if len(body.text.strip()) > 500:
                return True
                
            return False
            
        except Exception as e:
            logger.error(f"Error waiting for content: {e}")
            return False
            
    def extract_page_content(self, url: str) -> Optional[Dict[str, Any]]:
        """Extract content from a single page"""
        try:
            if self.driver is None:
                logger.error("Driver is not initialized")
                return None
                
            logger.info(f"Extracting content from: {url}")
            self.driver.get(url)
            
            # Wait for content to load
            if not self.wait_for_content():
                logger.warning(f"Content did not load properly for: {url}")
                
            # Additional wait for dynamic content
            time.sleep(2)
            
            # Get page title
            title = self.driver.title
            
            # Try to find main content area
            content_text = ""
            code_examples = []
            
            # Strategy 1: Look for specific content containers
            content_selectors = [
                "main",
                "article",
                ".documentation",
                ".content",
                "[role='main']",
                ".doc-content",
                "#content",
                ".main-content"
            ]
            
            for selector in content_selectors:
                try:
                    elements = self.driver.find_elements(By.CSS_SELECTOR, selector)
                    for element in elements:
                        text = element.text.strip()
                        if len(text) > len(content_text):
                            content_text = text
                except:
                    continue
                    
            # If no content found, get body text minus navigation
            if len(content_text) < 100:
                try:
                    body = self.driver.find_element(By.TAG_NAME, "body")
                    # Remove navigation elements
                    nav_elements = self.driver.find_elements(By.CSS_SELECTOR, "nav, header, footer, .nav, .navigation")
                    nav_text = " ".join([elem.text for elem in nav_elements])
                    content_text = body.text
                    for nav in nav_text.split():
                        content_text = content_text.replace(nav, "")
                except:
                    pass
                    
            # Extract code examples
            try:
                code_elements = self.driver.find_elements(By.CSS_SELECTOR, "pre, code, .code-block")
                for code_elem in code_elements:
                    code_text = code_elem.text.strip()
                    if code_text and len(code_text) > 10:
                        code_examples.append(code_text)
            except:
                pass
                
            # Only save if we found substantial content
            if len(content_text) > 100:
                return {
                    "url": url,
                    "title": title,
                    "content": content_text,
                    "code_examples": code_examples,
                    "scraped_at": time.strftime("%Y-%m-%d %H:%M:%S")
                }
            else:
                logger.warning(f"Insufficient content found on {url} ({len(content_text)} chars)")
                return None
                
        except Exception as e:
            logger.error(f"Error extracting content from {url}: {e}")
            self.failed_urls.add(url)
            return None
            
    def find_documentation_links(self) -> Set[str]:
        """Find all documentation links on the current page"""
        links = set()
        
        try:
            # Check if driver is initialized
            if self.driver is None:
                logger.error("Driver is not initialized")
                return links
                
            # Find all links
            link_elements = self.driver.find_elements(By.TAG_NAME, "a")
            current_url = self.driver.current_url
            
            for link_elem in link_elements:
                try:
                    href = link_elem.get_attribute("href")
                    if href:
                        # Convert to absolute URL
                        absolute_url = urljoin(current_url, href)
                        
                        # Filter for documentation links
                        if ("developer.ninjatrader.com/docs" in absolute_url and 
                            not any(absolute_url.endswith(ext) for ext in ['.pdf', '.zip', '.exe', '.png', '.jpg']) and
                            absolute_url not in self.visited_urls):
                            links.add(absolute_url)
                except:
                    continue
                    
            logger.info(f"Found {len(links)} new documentation links")
            
        except Exception as e:
            logger.error(f"Error finding links: {e}")
            
        return links
        
    def scrape_site(self, max_pages: int = 50) -> None:
        """Main scraping method"""
        self.start_driver()
        
        try:
            # Start with base URL
            urls_to_visit = {self.base_url}
            
            while urls_to_visit and len(self.visited_urls) < max_pages:
                url = urls_to_visit.pop()
                
                if url in self.visited_urls:
                    continue
                    
                self.visited_urls.add(url)
                
                # Extract content
                content = self.extract_page_content(url)
                if content:
                    self.content_data.append(content)
                    logger.info(f"✓ Successfully extracted: {content['title']}")
                    
                # Find more links
                new_links = self.find_documentation_links()
                urls_to_visit.update(new_links - self.visited_urls)
                
                # Be polite
                time.sleep(1)
                
            logger.info(f"\nScraping complete!")
            logger.info(f"Pages visited: {len(self.visited_urls)}")
            logger.info(f"Pages with content: {len(self.content_data)}")
            logger.info(f"Failed pages: {len(self.failed_urls)}")
            
        finally:
            self.close_driver()
            
    def save_results(self, output_dir: str = ".") -> None:
        """Save scraped content to files"""
        # Save as JSON
        json_file = f"{output_dir}/ninjatrader_docs.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(self.content_data, f, indent=2, ensure_ascii=False)
        logger.info(f"Saved JSON to: {json_file}")
        
        # Save as Markdown
        md_file = f"{output_dir}/ninjatrader_docs.md"
        with open(md_file, 'w', encoding='utf-8') as f:
            f.write("# NinjaTrader Desktop SDK Documentation\n\n")
            f.write(f"Scraped on: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"Total pages: {len(self.content_data)}\n\n")
            f.write("---\n\n")
            
            # Table of contents
            f.write("## Table of Contents\n\n")
            for i, doc in enumerate(self.content_data, 1):
                f.write(f"{i}. [{doc['title']}](#{i}-{doc['title'].lower().replace(' ', '-')})\n")
            
            f.write("\n---\n\n")
            
            # Content
            for i, doc in enumerate(self.content_data, 1):
                f.write(f"## {i}. {doc['title']}\n\n")
                f.write(f"**URL:** {doc['url']}\n\n")
                f.write(f"**Scraped:** {doc['scraped_at']}\n\n")
                
                # Content preview (first 2000 chars)
                content_preview = doc['content'][:2000]
                if len(doc['content']) > 2000:
                    content_preview += "...\n\n[Content truncated]"
                    
                f.write(content_preview)
                f.write("\n\n")
                
                # Code examples
                if doc['code_examples']:
                    f.write("### Code Examples\n\n")
                    for j, code in enumerate(doc['code_examples'][:3], 1):
                        f.write(f"#### Example {j}\n\n")
                        f.write("```csharp\n")
                        f.write(code)
                        f.write("\n```\n\n")
                        
                f.write("---\n\n")
                
        logger.info(f"Saved Markdown to: {md_file}")
        
        # Save failed URLs for reference
        if self.failed_urls:
            failed_file = f"{output_dir}/ninjatrader_failed_urls.txt"
            with open(failed_file, 'w') as f:
                for url in sorted(self.failed_urls):
                    f.write(f"{url}\n")
            logger.info(f"Saved failed URLs to: {failed_file}")

def main():
    print("NinjaTrader Selenium Documentation Scraper")
    print("=" * 50)
    
    # Check if user wants headless mode
    headless = input("\nRun in headless mode? (y/n, default=y): ").strip().lower() != 'n'
    
    # Max pages to scrape
    max_pages = input("Maximum pages to scrape (default=50): ").strip()
    max_pages = int(max_pages) if max_pages.isdigit() else 50
    
    # Create scraper
    scraper = NinjaTraderSeleniumScraper(headless=headless)
    
    try:
        # Run scraper
        print(f"\nStarting scrape (max {max_pages} pages)...")
        scraper.scrape_site(max_pages=max_pages)
        
        # Save results
        print("\nSaving results...")
        scraper.save_results()
        
        print("\nDone! Check the output files:")
        print("  - ninjatrader_docs.json (structured data)")
        print("  - ninjatrader_docs.md (readable documentation)")
        
    except KeyboardInterrupt:
        print("\n\nScraping interrupted by user")
        if scraper.content_data:
            print("Saving partial results...")
            scraper.save_results()
    except Exception as e:
        print(f"\nError: {e}")
        if scraper.content_data:
            print("Saving partial results...")
            scraper.save_results()

if __name__ == "__main__":
    main()