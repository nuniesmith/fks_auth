// NinjaTrader Documentation Capture Script
// Run this in the browser console while browsing the documentation

// Initialize storage
window.ninjaTraderDocs = window.ninjaTraderDocs || {
    pages: [],
    currentPage: null
};

// Function to extract current page content
function captureCurrentPage() {
    const pageData = {
        url: window.location.href,
        title: document.title,
        timestamp: new Date().toISOString(),
        content: '',
        codeExamples: [],
        headings: []
    };
    
    // Try multiple strategies to find content
    const contentSelectors = [
        'main',
        'article',
        '.documentation',
        '.content',
        '[role="main"]',
        '.doc-content',
        '#content',
        '.main-content',
        // Specific to NinjaTrader site structure
        '.prose',
        '.markdown',
        '[class*="content"]',
        '[class*="doc"]'
    ];
    
    let mainContent = null;
    for (const selector of contentSelectors) {
        const element = document.querySelector(selector);
        if (element && element.textContent.trim().length > 100) {
            mainContent = element;
            break;
        }
    }
    
    // Fallback to body if no specific content area found
    if (!mainContent) {
        mainContent = document.body;
    }
    
    // Clone the content area to manipulate without affecting the page
    const contentClone = mainContent.cloneNode(true);
    
    // Remove navigation, headers, footers
    const removeSelectors = ['nav', 'header', 'footer', '.nav', '.navigation', '.sidebar'];
    removeSelectors.forEach(selector => {
        contentClone.querySelectorAll(selector).forEach(el => el.remove());
    });
    
    // Extract text content
    pageData.content = contentClone.textContent.trim();
    
    // Extract code examples
    mainContent.querySelectorAll('pre, code, .code-block').forEach(codeEl => {
        const code = codeEl.textContent.trim();
        if (code.length > 10) {
            pageData.codeExamples.push(code);
        }
    });
    
    // Extract headings for structure
    mainContent.querySelectorAll('h1, h2, h3, h4, h5, h6').forEach(heading => {
        pageData.headings.push({
            level: heading.tagName,
            text: heading.textContent.trim()
        });
    });
    
    // Add to collection if has substantial content
    if (pageData.content.length > 100) {
        window.ninjaTraderDocs.pages.push(pageData);
        window.ninjaTraderDocs.currentPage = pageData;
        console.log(`✓ Captured: ${pageData.title} (${pageData.content.length} chars)`);
        return pageData;
    } else {
        console.warn(`✗ Insufficient content on ${pageData.title} (${pageData.content.length} chars)`);
        return null;
    }
}

// Function to download collected data
function downloadDocs() {
    const data = window.ninjaTraderDocs.pages;
    
    if (data.length === 0) {
        console.error('No pages captured yet!');
        return;
    }
    
    // Create markdown content
    let markdown = '# NinjaTrader Desktop SDK Documentation\n\n';
    markdown += `Captured on: ${new Date().toISOString()}\n\n`;
    markdown += `Total pages: ${data.length}\n\n`;
    markdown += '---\n\n';
    
    // Table of contents
    markdown += '## Table of Contents\n\n';
    data.forEach((page, i) => {
        markdown += `${i + 1}. [${page.title}](${page.url})\n`;
    });
    markdown += '\n---\n\n';
    
    // Add each page
    data.forEach((page, i) => {
        markdown += `## ${i + 1}. ${page.title}\n\n`;
        markdown += `**URL:** ${page.url}\n\n`;
        markdown += `**Captured:** ${page.timestamp}\n\n`;
        
        // Add headings outline
        if (page.headings.length > 0) {
            markdown += '### Page Structure\n\n';
            page.headings.forEach(h => {
                const indent = '  '.repeat(parseInt(h.level.charAt(1)) - 1);
                markdown += `${indent}- ${h.text}\n`;
            });
            markdown += '\n';
        }
        
        // Add content
        markdown += '### Content\n\n';
        markdown += page.content.substring(0, 5000); // First 5000 chars
        if (page.content.length > 5000) {
            markdown += '\n\n[Content truncated...]\n';
        }
        markdown += '\n\n';
        
        // Add code examples
        if (page.codeExamples.length > 0) {
            markdown += '### Code Examples\n\n';
            page.codeExamples.slice(0, 3).forEach((code, j) => {
                markdown += `#### Example ${j + 1}\n\n`;
                markdown += '```csharp\n';
                markdown += code;
                markdown += '\n```\n\n';
            });
        }
        
        markdown += '---\n\n';
    });
    
    // Download as file
    const blob = new Blob([markdown], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ninjatrader_docs_${new Date().toISOString().split('T')[0]}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    // Also download JSON
    const jsonBlob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const jsonUrl = URL.createObjectURL(jsonBlob);
    const jsonA = document.createElement('a');
    jsonA.href = jsonUrl;
    jsonA.download = `ninjatrader_docs_${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(jsonA);
    jsonA.click();
    document.body.removeChild(jsonA);
    URL.revokeObjectURL(jsonUrl);
    
    console.log(`✓ Downloaded ${data.length} pages as Markdown and JSON`);
}

// Auto-capture when navigating
let lastUrl = window.location.href;
setInterval(() => {
    if (window.location.href !== lastUrl) {
        lastUrl = window.location.href;
        setTimeout(() => {
            captureCurrentPage();
        }, 2000); // Wait for content to load
    }
}, 1000);

// Manual capture commands
window.capturePage = captureCurrentPage;
window.downloadNinjaDocs = downloadDocs;
window.viewCaptured = () => {
    console.table(window.ninjaTraderDocs.pages.map(p => ({
        title: p.title,
        url: p.url,
        contentLength: p.content.length,
        codeExamples: p.codeExamples.length
    })));
};

// Instructions
console.log('%c🥷 NinjaTrader Documentation Capture Script Loaded!', 'color: green; font-size: 16px; font-weight: bold');
console.log('\nCommands:');
console.log('  capturePage()     - Manually capture current page');
console.log('  downloadNinjaDocs() - Download all captured pages');
console.log('  viewCaptured()    - View list of captured pages');
console.log('\nThe script will auto-capture as you browse.');
console.log('Navigate through the documentation and then run downloadNinjaDocs()');

// Initial capture
setTimeout(() => {
    captureCurrentPage();
}, 2000);