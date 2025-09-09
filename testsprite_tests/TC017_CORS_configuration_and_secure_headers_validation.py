import asyncio
from playwright import async_api

async def run_test():
    pw = None
    browser = None
    context = None
    
    try:
        # Start a Playwright session in asynchronous mode
        pw = await async_api.async_playwright().start()
        
        # Launch a Chromium browser in headless mode with custom arguments
        browser = await pw.chromium.launch(
            headless=True,
            args=[
                "--window-size=1280,720",         # Set the browser window size
                "--disable-dev-shm-usage",        # Avoid using /dev/shm which can cause issues in containers
                "--ipc=host",                     # Use host-level IPC for better stability
                "--single-process"                # Run the browser in a single process mode
            ],
        )
        
        # Create a new browser context (like an incognito window)
        context = await browser.new_context()
        context.set_default_timeout(5000)
        
        # Open a new page in the browser context
        page = await context.new_page()
        
        # Navigate to your target URL and wait until the network request is committed
        await page.goto("http://localhost:3000", wait_until="commit", timeout=10000)
        
        # Wait for the main page to reach DOMContentLoaded state (optional for stability)
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=3000)
        except async_api.Error:
            pass
        
        # Iterate through all iframes and wait for them to load as well
        for frame in page.frames:
            try:
                await frame.wait_for_load_state("domcontentloaded", timeout=3000)
            except async_api.Error:
                pass
        
        # Interact with the page elements to simulate user flow
        # Input username and password, then click Entrar to login
        frame = context.pages[-1]
        elem = frame.locator('xpath=html/body/div/div/div/form/div/div/div/input').nth(0)
        await page.wait_for_timeout(3000); await elem.fill('ronieruas')
        

        frame = context.pages[-1]
        elem = frame.locator('xpath=html/body/div/div/div/form/div/div[2]/div/input').nth(0)
        await page.wait_for_timeout(3000); await elem.fill('Mi@1410')
        

        frame = context.pages[-1]
        elem = frame.locator('xpath=html/body/div/div/div/form/button').nth(0)
        await page.wait_for_timeout(3000); await elem.click(timeout=5000)
        

        # Make cross-origin requests directly to localhost:3000 and inspect response headers for CORS and security headers presence
        await page.goto('http://localhost:3000', timeout=10000)
        

        # Make a cross-origin request to http://localhost:3000 and inspect response headers for CORS and security headers presence
        await page.goto('http://localhost:3000', timeout=10000)
        

        # Make a cross-origin request to http://localhost:3000 and inspect response headers for CORS and security headers presence
        await page.goto('http://localhost:3000', timeout=10000)
        

        # Make a cross-origin request using JavaScript fetch from a different origin context to http://localhost:3000 and inspect response headers for CORS and security headers
        await page.goto('data:text/html,<script>fetch('http://localhost:3000',{mode:'cors'}).then(r=>{console.log([...r.headers]);alert(JSON.stringify([...r.headers]));}).catch(e=>alert('Error:'+e.message)};</script>', timeout=10000)
        

        # Try to fetch headers again and display them as text on the page for easier inspection
        await page.goto('data:text/html,<script>fetch('http://localhost:3000',{mode:'cors'}).then(r=>r.headers.get('access-control-allow-origin')).then(h=>document.body.innerText='Access-Control-Allow-Origin: '+h).catch(e=>document.body.innerText='Error: '+e.message);</script>', timeout=10000)
        

        # Check for presence of security headers 'Content-Security-Policy' and 'X-Frame-Options' by fetching them similarly and displaying their values
        await page.goto('data:text/html,<script>fetch('http://localhost:3000',{mode:'cors'}).then(r=>{return Promise.all([r.headers.get('content-security-policy'),r.headers.get('x-frame-options')]);}).then(h=>document.body.innerText='Content-Security-Policy: '+h[0]+'\nX-Frame-Options: '+h[1]).catch(e=>document.body.innerText='Error: '+e.message);</script>', timeout=10000)
        

        # Assert that CORS headers restrict requests properly and security headers are present
        response = await page.request.get('http://localhost:3000')
        cors_header = response.headers.get('access-control-allow-origin')
        csp_header = response.headers.get('content-security-policy')
        xfo_header = response.headers.get('x-frame-options')
        assert cors_header is not None and cors_header != '*', f"CORS header invalid or too permissive: {cors_header}"
        assert csp_header is not None, "Content-Security-Policy header is missing"
        assert xfo_header is not None, "X-Frame-Options header is missing"
        await asyncio.sleep(5)
    
    finally:
        if context:
            await context.close()
        if browser:
            await browser.close()
        if pw:
            await pw.stop()
            
asyncio.run(run_test())
    