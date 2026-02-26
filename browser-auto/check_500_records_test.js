const { chromium } = require('playwright');

(async () => {
    const browser = await chromium.launch({ headless: false });
    const page = await browser.newPage();
    
    // Capture console logs from the page
    page.on('console', msg => {
        console.log('📄 PAGE LOG:', msg.text());
    });
    
    // Listen for console errors
    page.on('console', msg => {
        if (msg.type() === 'error') {
            console.log('❌ Console error:', msg.text());
        }
    });
    
    // Listen for network errors
    page.on('response', response => {
        if (response.status() >= 400) {
            console.log('❌ Network error:', response.status(), response.url());
        }
    });
    
    // Add authentication for all requests
    page.setExtraHTTPHeaders({
        'Authorization': 'Basic ' + Buffer.from('admin:Cowrie@2026!').toString('base64')
    });
    
    try {
        console.log('🌐 Navigating to dashboard...');
        await page.goto('http://admin:Cowrie@2026!@192.168.1.19:3333');
        
        // Wait for page to load
        await page.waitForLoadState('networkidle');
        console.log('✅ Dashboard loaded successfully');
        
        // Check if recent attacks table exists and count rows
        console.log('🔍 Checking recent attacks table...');
        const recentAttacksTable = await page.locator('#recent-attacks');
        
        if (await recentAttacksTable.isVisible()) {
            console.log('✅ Recent attacks table found');
            
            // Count the number of rows in the table
            const rowCount = await recentAttacksTable.locator('tr').count();
            console.log(`📊 Found ${rowCount} rows in recent attacks table`);
            
            // Get all row data
            const rows = await recentAttacksTable.locator('tr').all();
            console.log('📋 Recent attacks data:');
            
            for (let i = 0; i < Math.min(rows.length, 10); i++) {
                const cells = await rows[i].locator('td').allTextContents();
                if (cells.length > 0) {
                    console.log(`   Row ${i + 1}: ${cells.join(' | ')}`);
                }
            }
            
            // Check if we have more than 20 rows (our target)
            if (rowCount > 20) {
                console.log(`🎯 SUCCESS: Found ${rowCount} recent attacks (> 20 target)`);
            } else if (rowCount === 20) {
                console.log(`⚠️  WARNING: Found exactly 20 recent attacks (might be limited)`);
            } else {
                console.log(`❌ ISSUE: Only found ${rowCount} recent attacks (expected more)`);
            }
            
        } else {
            console.log('❌ Recent attacks table not found');
        }
        
        // Check World Attack Map markers
        console.log('🗺️ Checking World Attack Map...');
        const mapContainer = await page.locator('#world-map');
        
        if (await mapContainer.isVisible()) {
            console.log('✅ World map container found');
            
            // Wait for map to initialize
            await page.waitForTimeout(3000);
            
            // Count map markers (leaflet markers)
            const markerCount = await page.evaluate(() => {
                return window.worldMap ? Object.keys(window.worldMap._layers).length : 0;
            });
            
            console.log(`📍 Found ${markerCount} map markers`);
            
            if (markerCount > 20) {
                console.log(`🎯 SUCCESS: Found ${markerCount} map markers (> 20 target)`);
            } else if (markerCount === 20) {
                console.log(`⚠️  WARNING: Found exactly 20 map markers (might be limited)`);
            } else {
                console.log(`❌ ISSUE: Only found ${markerCount} map markers (expected more)`);
            }
            
        } else {
            console.log('❌ World map container not found');
        }
        
        // Check Attack Timeline chart
        console.log('📈 Checking Attack Timeline...');
        const timelineCanvas = await page.locator('#timeline-chart');
        
        if (await timelineCanvas.isVisible()) {
            console.log('✅ Timeline chart found');
            
            // Get chart data
            const chartData = await page.evaluate(() => {
                if (window.timelineChart) {
                    return {
                        labels: window.timelineChart.data.labels.length,
                        dataPoints: window.timelineChart.data.datasets[0].data.length
                    };
                }
                return null;
            });
            
            if (chartData) {
                console.log(`📊 Timeline chart has ${chartData.labels} labels and ${chartData.dataPoints} data points`);
                
                if (chartData.dataPoints > 20) {
                    console.log(`🎯 SUCCESS: Timeline has ${chartData.dataPoints} data points (> 20 target)`);
                } else if (chartData.dataPoints === 20) {
                    console.log(`⚠️  WARNING: Timeline has exactly 20 data points (might be limited)`);
                } else {
                    console.log(`❌ ISSUE: Timeline only has ${chartData.dataPoints} data points (expected more)`);
                }
            } else {
                console.log('❌ Could not retrieve timeline chart data');
            }
            
        } else {
            console.log('❌ Timeline chart not found');
        }
        
        // Check Top Countries chart
        console.log('🌍 Checking Top Countries chart...');
        const countriesChart = await page.$('#countries-chart');
        if (countriesChart) {
            console.log('✅ Top Countries chart found');
        } else {
            console.log('❌ Top Countries chart not found');
            
            // Check if container exists
            const containerCheck = await page.evaluate(() => {
                const container = document.getElementById('top-countries-chart');
                return {
                    containerExists: !!container,
                    containerHTML: container?.innerHTML || 'NOT_FOUND',
                    containerTagName: container?.tagName || 'NOT_FOUND',
                    containerID: container?.id || 'NOT_FOUND',
                    containerClass: container?.className || 'NOT_FOUND',
                    parentElement: container?.parentElement?.tagName || 'NOT_FOUND'
                };
            });
            
            console.log('🔍 Container check:', containerCheck);
            
            // Check all elements with similar IDs
            const allElementsCheck = await page.evaluate(() => {
                const elements = document.querySelectorAll('[id*="countries"], [id*="chart"]');
                return Array.from(elements).map(el => ({
                    id: el.id,
                    tagName: el.tagName,
                    className: el.className,
                    innerHTML: el.innerHTML.substring(0, 100)
                }));
            });
            
            console.log('� All related elements:', allElementsCheck);
        }
        
        // Get API stats to verify backend
        console.log('🔗 Checking API stats...');
        const apiResponse = await page.evaluate(async () => {
            try {
                const response = await fetch('http://192.168.1.19:3333/api/stats', {
                    headers: {
                        'Authorization': 'Basic ' + btoa('admin:Cowrie@2026!')
                    }
                });
                const data = await response.json();
                
                // Check geo data in recent attacks
                if (data.recent_attacks && Array.isArray(data.recent_attacks)) {
                    let withGeo = 0;
                    let withoutGeo = 0;
                    let sampleWithGeo = [];
                    let sampleWithoutGeo = [];
                    
                    data.recent_attacks.slice(0, 100).forEach((attack, index) => {
                        if (attack.latitude && attack.longitude) {
                            withGeo++;
                            if (sampleWithGeo.length < 3) {
                                sampleWithGeo.push({ index, ip: attack.ip, lat: attack.latitude, lng: attack.longitude });
                            }
                        } else {
                            withoutGeo++;
                            if (sampleWithoutGeo.length < 3) {
                                sampleWithoutGeo.push({ index, ip: attack.ip, country: attack.country });
                            }
                        }
                    });
                    
                    return {
                        ...data,
                        geoAnalysis: {
                            totalChecked: data.recent_attacks.length,
                            withGeo,
                            withoutGeo,
                            sampleWithGeo,
                            sampleWithoutGeo
                        }
                    };
                }
                
                return data;
            } catch (error) {
                return { error: error.message };
            }
        });
        
        if (apiResponse.recent_attacks) {
            console.log(`📊 API reports ${apiResponse.recent_attacks.length} recent attacks`);
            
            if (apiResponse.recent_attacks.length > 20) {
                console.log(`🎯 API SUCCESS: Backend has ${apiResponse.recent_attacks.length} recent attacks (> 20 target)`);
            } else if (apiResponse.recent_attacks.length === 20) {
                console.log(`⚠️  API WARNING: Backend has exactly 20 recent attacks (might be limited)`);
            } else {
                console.log(`❌ API ISSUE: Backend only has ${apiResponse.recent_attacks.length} recent attacks (expected more)`);
            }
        } else {
            console.log('❌ Could not get API stats or recent_attacks field missing');
            console.log('API Response:', apiResponse);
        }
        
        console.log('🏁 Test completed');
        
    } catch (error) {
        console.error('❌ Test failed:', error.message);
    } finally {
        await browser.close();
    }
})();
