#!/usr/bin/env node

const http = require('http');

const testEndpoints = [
    { path: '/api/health', method: 'GET', description: 'Health check' },
    { path: '/api/services', method: 'GET', description: 'FKS services list' },
    { path: '/api/trading-status', method: 'GET', description: 'Trading system status' },
    { path: '/api/services/category/Trading Tools', method: 'GET', description: 'Trading tools category' }
];

function makeRequest(endpoint) {
    return new Promise((resolve, reject) => {
        const options = {
            hostname: 'localhost',
            port: 4000,
            path: endpoint.path,
            method: endpoint.method
        };

        const req = http.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => {
                data += chunk;
            });
            res.on('end', () => {
                resolve({
                    status: res.statusCode,
                    data: data
                });
            });
        });

        req.on('error', (err) => {
            reject(err);
        });

        req.end();
    });
}

async function testAPI() {
    console.log('🧪 Testing FKS API endpoints...\n');
    
    for (const endpoint of testEndpoints) {
        try {
            console.log(`Testing ${endpoint.description}...`);
            const result = await makeRequest(endpoint);
            console.log(`✅ ${endpoint.method} ${endpoint.path} - Status: ${result.status}`);
            
            if (result.status === 200) {
                try {
                    const jsonData = JSON.parse(result.data);
                    if (Array.isArray(jsonData)) {
                        console.log(`   📦 Response: Array with ${jsonData.length} items`);
                        if (jsonData.length > 0) {
                            console.log(`   📋 First item: ${jsonData[0].name || jsonData[0].status || 'Unknown'}`);
                        }
                    } else {
                        console.log(`   📦 Response: ${jsonData.status || jsonData.message || 'Object'}`);
                    }
                } catch (parseError) {
                    console.log(`   📦 Response: ${result.data.substring(0, 100)}...`);
                }
            }
            console.log('');
        } catch (error) {
            console.log(`❌ ${endpoint.method} ${endpoint.path} - Error: ${error.message}`);
            console.log('');
        }
    }
    
    console.log('🎯 API testing complete!');
}

testAPI().catch(console.error);
