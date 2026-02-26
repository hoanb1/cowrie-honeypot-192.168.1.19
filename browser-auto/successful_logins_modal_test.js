const { chromium } = require('playwright');

(async () => {
    const browser = await chromium.launch({ headless: false });
    const page = await browser.newPage();
    
    // Listen for console errors
    page.on('console', msg => {
        if (msg.type() === 'error') {
            console.log('� Console error:', msg.text());
        }
    });
    
    // Listen for network errors
    page.on('response', response => {
        if (response.status() >= 400) {
            console.log('🌐 Network error:', response.url(), response.status());
        }
    });
    
    try {
        console.log('�🔍 Navigating to Cowrie Dashboard...');
        
        // Navigate to dashboard with authentication
        await page.goto('http://admin:Cowrie@2026!@192.168.1.19:3333');
        
        // Wait for page to load
        await page.waitForLoadState('networkidle');
        
        console.log('✅ Dashboard loaded successfully');
        
        // Wait for successful logins element to be visible
        await page.waitForSelector('#successful-logins', { timeout: 10000 });
        
        console.log('📊 Checking successful logins element...');
        const successfulLoginsElement = page.locator('#successful-logins');
        const loginsCount = await successfulLoginsElement.textContent();
        console.log(`🔢 Successful logins count: ${loginsCount}`);
        
        // Check if the parent div has onclick handler
        const parentDiv = page.locator('#successful-logins').locator('..');
        const hasOnclick = await parentDiv.evaluate(el => el.hasAttribute('onclick'));
        console.log(`🖱️ Has onclick handler: ${hasOnclick}`);
        
        // Check cursor style
        const cursorStyle = await parentDiv.evaluate(el => {
            return window.getComputedStyle(el).cursor;
        });
        console.log(`🎯 Cursor style: ${cursorStyle}`);
        
        // Check if showSuccessfulLoginsModal function exists
        const functionExists = await page.evaluate(() => {
            return typeof window.showSuccessfulLoginsModal === 'function';
        });
        console.log(`🔧 Function exists: ${functionExists}`);
        
        // Click on successful logins
        console.log('🖱️ Clicking on Successful Logins...');
        await parentDiv.click();
        
        // Wait a bit for potential modal to appear
        await page.waitForTimeout(2000);
        
        // Check if modal exists (even if not visible)
        const modalExists = await page.locator('#successful-logins-modal').count();
        console.log(`📋 Modal exists: ${modalExists > 0}`);
        
        if (modalExists > 0) {
            // Check if modal is visible
            const modalVisible = await page.locator('#successful-logins-modal').isVisible();
            console.log(`👁️ Modal visible: ${modalVisible}`);
            
            if (modalVisible) {
                console.log('✅ Modal appeared successfully');
                
                // Check modal content
                const modalTitle = await page.locator('#successful-logins-modal h3').textContent();
                console.log(`📋 Modal title: ${modalTitle}`);
                
                // Check table headers
                const tableHeaders = await page.locator('#successful-logins-modal th').allTextContents();
                console.log('📊 Table headers:', tableHeaders);
                
                // Check table rows
                const tableRows = await page.locator('#successful-logins-modal tbody tr').count();
                console.log(`📈 Number of login entries: ${tableRows}`);
                
                if (tableRows > 0) {
                    // Get first row data
                    const firstRowData = await page.locator('#successful-logins-modal tbody tr').first().allTextContents();
                    console.log('📋 First row data:', firstRowData);
                    
                    // Check actions column
                    const actionsData = await page.locator('#successful-logins-modal tbody tr').first().locator('td').last().allTextContents();
                    console.log('🔧 Actions data:', actionsData);
                }
                
                // Take screenshot
                await page.screenshot({ path: 'successful_logins_modal.png', fullPage: true });
                console.log('📸 Screenshot saved as successful_logins_modal.png');
                
                // Close modal
                console.log('❌ Closing modal...');
                await page.locator('#successful-logins-modal button').click();
                
                // Wait for modal to disappear
                await page.waitForSelector('#successful-logins-modal', { state: 'hidden', timeout: 3000 });
                console.log('✅ Modal closed successfully');
            } else {
                console.log('❌ Modal exists but not visible');
                // Check modal style
                const modalStyle = await page.locator('#successful-logins-modal').evaluate(el => {
                    return window.getComputedStyle(el);
                });
                console.log('🎨 Modal display:', modalStyle.display);
                console.log('🎨 Modal visibility:', modalStyle.visibility);
                console.log('🎨 Modal opacity:', modalStyle.opacity);
            }
        } else {
            console.log('❌ Modal not found after click');
            
            // Check if there are any alerts
            const alertExists = await page.locator('.alert').count();
            if (alertExists > 0) {
                const alertText = await page.locator('.alert').first().textContent();
                console.log('🚨 Alert found:', alertText);
            }
        }
        
        console.log('🎉 SUCCESSFUL LOGINS MODAL TEST COMPLETED!');
        
    } catch (error) {
        console.error('❌ Error:', error.message);
        
        // Take screenshot of error state
        await page.screenshot({ path: 'error_state.png', fullPage: true });
        console.log('📸 Error screenshot saved as error_state.png');
        
    } finally {
        await browser.close();
    }
})();
