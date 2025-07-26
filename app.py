#!/usr/bin/env python3
import sys
import os
import json
import asyncio
import threading
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from urllib.parse import urlparse, urljoin, quote, unquote
import hashlib
import re

from PyQt6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QLineEdit, QPushButton, QHBoxLayout, QTextEdit, QSplitter
from PyQt6.QtCore import QUrl, pyqtSlot, QObject, Qt
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import QWebEnginePage

try:
    from PyQt6.QtWebChannel import QWebChannel
except ImportError:
    # For older PyQt6 versions, QWebChannel might be in a different location
    QWebChannel = None

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import httpx
import aiofiles

class ProxyBridge(QObject):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.selected_xpath = ''
        self.console_logs = []

    @pyqtSlot(str)
    def setXPath(self, xpath):
        self.selected_xpath = xpath
        if hasattr(self.parent(), 'on_xpath_selected'):
            self.parent().on_xpath_selected(xpath)

    @pyqtSlot(str)
    def logConsole(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        self.console_logs.append(log_entry)
        if hasattr(self.parent(), 'on_console_message'):
            self.parent().on_console_message(log_entry)

class CustomWebEnginePage(QWebEnginePage):
    def __init__(self, parent=None):
        super().__init__(parent)
        
    def javaScriptConsoleMessage(self, level, message, lineNumber, sourceID):
        # Forward console messages to our bridge
        if hasattr(self.parent(), 'bridge'):
            self.parent().bridge.logConsole(f"{message} (line {lineNumber})")

class RobustWebBrowser(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Robust Web Proxy Browser")
        self.setGeometry(100, 100, 1400, 900)
        self.selection_mode = False
        self.current_url = ""
        self.init_ui()
        
    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QVBoxLayout(central_widget)
        
        # URL controls
        url_layout = QHBoxLayout()
        
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Enter URL (e.g., https://zulushare.com)")
        self.url_input.returnPressed.connect(self.load_url)
        
        load_btn = QPushButton("Load Website")
        load_btn.clicked.connect(self.load_url)
        
        self.move_to_web_btn = QPushButton("Move to Web")
        self.move_to_web_btn.clicked.connect(self.move_to_web)
        self.move_to_web_btn.setEnabled(False)  # Disabled until page loads
        self.move_to_web_btn.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; font-weight: bold; }")
        
        self.select_btn = QPushButton("Enable Selection")
        self.select_btn.setCheckable(True)
        self.select_btn.toggled.connect(self.toggle_selection_mode)
        
        clear_btn = QPushButton("Clear Console")
        clear_btn.clicked.connect(self.clear_console)
        
        url_layout.addWidget(self.url_input)
        url_layout.addWidget(load_btn)
        url_layout.addWidget(self.move_to_web_btn)
        url_layout.addWidget(self.select_btn)
        url_layout.addWidget(clear_btn)
        
        main_layout.addLayout(url_layout)
        
        # Splitter for web view and console
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Web view
        self.web_view = QWebEngineView()
        self.custom_page = CustomWebEnginePage(self)
        self.web_view.setPage(self.custom_page)
        
        # Setup WebChannel (if available)
        if QWebChannel:
            self.channel = QWebChannel()
            self.bridge = ProxyBridge(self)
            self.channel.registerObject('bridge', self.bridge)
            self.web_view.page().setWebChannel(self.channel)
        else:
            print("Warning: QWebChannel not available, element selection may not work")
        
        splitter.addWidget(self.web_view)
        
        # Console output
        self.console_output = QTextEdit()
        self.console_output.setMaximumHeight(200)
        self.console_output.setReadOnly(True)
        self.console_output.setStyleSheet("background-color: #1e1e1e; color: #ffffff; font-family: monospace;")
        splitter.addWidget(self.console_output)
        
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        main_layout.addWidget(splitter)
        
        # XPath display
        self.xpath_display = QLineEdit()
        self.xpath_display.setReadOnly(True)
        self.xpath_display.setPlaceholderText("Selected XPath will appear here")
        main_layout.addWidget(self.xpath_display)
        
    def load_url(self):
        url = self.url_input.text().strip()
        if not url:
            return
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        self.current_url = url
        self.move_to_web_btn.setEnabled(False)  # Disable while loading
        self.log_message(f"Loading website: {url}")
        
        # Connect to loadFinished signal to enable "Move to Web" button
        self.web_view.loadFinished.connect(self.on_load_finished)
        self.web_view.load(QUrl(url))
        
    def on_load_finished(self, ok):
        """Called when the webpage finishes loading"""
        if ok:
            self.move_to_web_btn.setEnabled(True)
            self.log_message(f"✅ Website loaded successfully! You can now 'Move to Web'")
        else:
            self.log_message(f"❌ Failed to load website")
        
        # Disconnect the signal to avoid multiple connections
        try:
            self.web_view.loadFinished.disconnect(self.on_load_finished)
        except:
            pass
    
    def move_to_web(self):
        """Capture the current webpage content and send it to the web interface"""
        if not self.current_url:
            self.log_message("❌ No URL loaded yet")
            return
        
        self.log_message("📋 Capturing webpage content...")
        
        # Get the HTML content from the web view
        self.web_view.page().toHtml(self.on_html_captured)
    
    def on_html_captured(self, html):
        """Called when HTML content is captured from the web view"""
        self.log_message(f"✅ Captured {len(html)} characters of HTML content")
        
        # Send to web interface via API
        try:
            import requests
            
            # Prepare the data to send
            data = {
                'type': 'rendered_content',
                'url': self.current_url,
                'html': html,
                'timestamp': datetime.now().isoformat()
            }
            
            # Send to web interface
            response = requests.post('http://127.0.0.1:8000/receive_content', 
                                   json=data, 
                                   timeout=10)
            
            if response.status_code == 200:
                self.log_message("✅ Content sent to web interface successfully!")
                self.log_message("🌐 View at: http://127.0.0.1:8000")
            else:
                self.log_message(f"❌ Failed to send content: {response.text}")
                
        except Exception as e:
            self.log_message(f"❌ Error sending content: {e}")
        
    def load_via_proxy(self):
        url = self.url_input.text().strip()
        if not url:
            return
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        self.current_url = url
        
        # Send URL to proxy server
        try:
            import requests
            response = requests.post('http://127.0.0.1:8000/set_target', 
                                   json={'url': url}, timeout=5)
            if response.status_code == 200:
                proxy_url = f"http://127.0.0.1:8000/proxy"
                self.log_message(f"Loading via proxy: {url}")
                self.web_view.load(QUrl(proxy_url))
                
                # Also send URL to web interface via WebSocket
                try:
                    ws_response = requests.post('http://127.0.0.1:8000/broadcast_url', 
                                              json={'type': 'load_url', 'url': url}, timeout=2)
                    if ws_response.status_code == 200:
                        self.log_message(f"URL sent to web interface: {url}")
                    else:
                        self.log_message(f"Failed to send URL to web interface: {ws_response.text}")
                except Exception as ws_e:
                    self.log_message(f"WebSocket broadcast error: {ws_e}")
                    
            else:
                self.log_message(f"Failed to set proxy target: {response.text}")
        except Exception as e:
            self.log_message(f"Error setting proxy target: {e}")
            
    def toggle_selection_mode(self, checked):
        self.selection_mode = checked
        if checked:
            self.select_btn.setText("Disable Selection")
            self.inject_selection_script()
        else:
            self.select_btn.setText("Enable Selection")
            self.remove_selection_script()
            
    def inject_selection_script(self):
        js_code = '''
        (function() {
            if (window.proxySelectionActive) return;
            window.proxySelectionActive = true;
            
            let hoveredElement = null;
            let selectedElement = null;
            
            function getXPath(element) {
                if (element.id) {
                    return '//*[@id="' + element.id + '"]';
                }
                
                const parts = [];
                while (element && element.nodeType === Node.ELEMENT_NODE) {
                    let index = 1;
                    let sibling = element.previousSibling;
                    while (sibling) {
                        if (sibling.nodeType === Node.ELEMENT_NODE && sibling.nodeName === element.nodeName) {
                            index++;
                        }
                        sibling = sibling.previousSibling;
                    }
                    
                    const tagName = element.nodeName.toLowerCase();
                    const pathIndex = index > 1 ? `[${index}]` : '';
                    parts.unshift(tagName + pathIndex);
                    
                    element = element.parentNode;
                }
                
                return '/' + parts.join('/');
            }
            
            function highlightElement(element, color) {
                if (!element) return;
                element.style.outline = `2px solid ${color}`;
                element.style.outlineOffset = '1px';
            }
            
            function removeHighlight(element) {
                if (!element) return;
                element.style.outline = '';
                element.style.outlineOffset = '';
            }
            
            function handleMouseOver(e) {
                if (hoveredElement && hoveredElement !== selectedElement) {
                    removeHighlight(hoveredElement);
                }
                hoveredElement = e.target;
                if (hoveredElement !== selectedElement) {
                    highlightElement(hoveredElement, '#ff6b6b');
                }
            }
            
            function handleMouseOut(e) {
                if (hoveredElement && hoveredElement !== selectedElement) {
                    removeHighlight(hoveredElement);
                }
                hoveredElement = null;
            }
            
            function handleClick(e) {
                e.preventDefault();
                e.stopPropagation();
                
                if (selectedElement) {
                    removeHighlight(selectedElement);
                }
                
                selectedElement = e.target;
                highlightElement(selectedElement, '#4ecdc4');
                
                const xpath = getXPath(selectedElement);
                
                // Send to bridge
                if (window.qt && window.qt.webChannelTransport) {
                    new QWebChannel(window.qt.webChannelTransport, function(channel) {
                        channel.objects.bridge.setXPath(xpath);
                    });
                }
            }
            
            document.addEventListener('mouseover', handleMouseOver, true);
            document.addEventListener('mouseout', handleMouseOut, true);
            document.addEventListener('click', handleClick, true);
            
            window.proxySelectionCleanup = function() {
                document.removeEventListener('mouseover', handleMouseOver, true);
                document.removeEventListener('mouseout', handleMouseOut, true);
                document.removeEventListener('click', handleClick, true);
                
                if (hoveredElement) removeHighlight(hoveredElement);
                if (selectedElement) removeHighlight(selectedElement);
                
                window.proxySelectionActive = false;
                delete window.proxySelectionCleanup;
            };
        })();
        '''
        self.web_view.page().runJavaScript(js_code)
        
    def remove_selection_script(self):
        js_code = '''
        if (window.proxySelectionCleanup) {
            window.proxySelectionCleanup();
        }
        '''
        self.web_view.page().runJavaScript(js_code)
        
    def on_xpath_selected(self, xpath):
        self.xpath_display.setText(xpath)
        self.log_message(f"Selected XPath: {xpath}")
        
    def on_console_message(self, message):
        self.console_output.append(message)
        
    def log_message(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        log_entry = f"[{timestamp}] {message}"
        self.console_output.append(log_entry)
        
    def clear_console(self):
        self.console_output.clear()


# FastAPI Proxy Server
app = FastAPI(title="Robust Web Proxy")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global state
proxy_state = {
    'target_url': '',
    'client': None,
    'cache': {}
}

# Store the latest captured content
captured_content = {
    'html': '',
    'url': '',
    'timestamp': ''
}

class ProxyCache:
    def __init__(self, ttl_seconds=300):  # 5 minutes default TTL
        self.cache = {}
        self.ttl = ttl_seconds
    
    def get_key(self, method, url, body=None):
        key_str = f"{method}:{url}"
        if body:
            key_str += f":{hashlib.md5(body).hexdigest()}"
        return hashlib.md5(key_str.encode()).hexdigest()
    
    def get(self, key):
        if key in self.cache:
            entry = self.cache[key]
            if datetime.now() - entry['timestamp'] < timedelta(seconds=self.ttl):
                return entry['data']
            else:
                del self.cache[key]
        return None
    
    def set(self, key, data):
        self.cache[key] = {
            'data': data,
            'timestamp': datetime.now()
        }
    
    def clear(self):
        self.cache.clear()

proxy_cache = ProxyCache()

@app.on_event("startup")
async def startup_event():
    proxy_state['client'] = httpx.AsyncClient(
        timeout=httpx.Timeout(30.0),
        follow_redirects=True,
        limits=httpx.Limits(max_keepalive_connections=20, max_connections=100),
        http2=True,  # Enable HTTP/2 support
        verify=False  # Disable SSL verification for problematic sites
    )

@app.on_event("shutdown")
async def shutdown_event():
    if proxy_state['client']:
        await proxy_state['client'].aclose()

@app.post("/broadcast_url")
async def broadcast_url_to_websockets(request: Request):
    """Broadcast URL to all connected WebSocket clients"""
    try:
        data = await request.json()
        message = {
            'type': data.get('type', 'load_url'),
            'url': data.get('url', '')
        }
        
        await broadcast_to_websockets(message)
        return JSONResponse({
            "status": "success",
            "message": f"URL broadcasted to {len(websocket_connections)} clients"
        })
    except Exception as e:
        return JSONResponse({
            "status": "error",
            "message": f"Failed to broadcast: {str(e)}"
        }, status_code=500)

@app.post("/set_target")
async def set_target_url(request: Request):
    data = await request.json()
    target_url = data.get('url', '').strip()
    
    if not target_url:
        raise HTTPException(status_code=400, detail="URL is required")
    
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    proxy_state['target_url'] = target_url
    proxy_cache.clear()  # Clear cache when target changes
    
    return JSONResponse({
        "status": "success",
        "target_url": target_url,
        "message": f"Target URL set to {target_url}"
    })

@app.post("/receive_content")
async def receive_content(request: Request):
    """Receive captured content from desktop application"""
    try:
        data = await request.json()
        
        # Store the captured content
        captured_content['html'] = data.get('html', '')
        captured_content['url'] = data.get('url', '')
        captured_content['timestamp'] = data.get('timestamp', '')
        
        print(f"📋 Received content from desktop app:")
        print(f"   URL: {captured_content['url']}")
        print(f"   Size: {len(captured_content['html'])} characters")
        
        # Broadcast to all connected WebSocket clients
        await broadcast_to_websockets({
            'type': 'content_received',
            'url': captured_content['url'],
            'timestamp': captured_content['timestamp']
        })
        
        return JSONResponse({
            "status": "success",
            "message": f"Content received successfully ({len(captured_content['html'])} chars)"
        })
        
    except Exception as e:
        print(f"❌ Error receiving content: {e}")
        return JSONResponse({
            "status": "error",
            "message": f"Failed to receive content: {str(e)}"
        }, status_code=500)

@app.get("/get_content")
async def get_content():
    """Get the latest captured content"""
    if not captured_content['html']:
        return JSONResponse({
            "status": "error",
            "message": "No content available"
        }, status_code=404)
    
    return JSONResponse({
        "status": "success",
        "html": captured_content['html'],
        "url": captured_content['url'],
        "timestamp": captured_content['timestamp']
    })

@app.get("/", response_class=HTMLResponse)
async def get_index():
    """Serve the main web interface"""
    try:
        async with aiofiles.open('index.html', 'r', encoding='utf-8') as f:
            content = await f.read()
        return HTMLResponse(content)
    except FileNotFoundError:
        return HTMLResponse("<h1>Error</h1><p>index.html not found</p>", status_code=404)

@app.get("/proxy", response_class=HTMLResponse)
async def get_proxy_page():
    if not proxy_state['target_url']:
        return HTMLResponse(
            "<h1>Error</h1><p>No target URL set. Use POST /set_target first.</p>",
            status_code=400
        )
    
    return await proxy_request(proxy_state['target_url'], "GET")

@app.get("/site", response_class=HTMLResponse)
async def get_clean_proxy_page():
    """Clean proxy route without /proxy path for complex sites"""
    if not proxy_state['target_url']:
        return HTMLResponse(
            "<h1>Error</h1><p>No target URL set. Use POST /set_target first.</p>",
            status_code=400
        )
    
    return await proxy_request(proxy_state['target_url'], "GET")

@app.api_route("/proxy/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def proxy_path(path: str, request: Request):
    if not proxy_state['target_url']:
        raise HTTPException(status_code=400, detail="No target URL set")
    
    # Handle different path types
    if path.startswith('http'):
        target_url = unquote(path)
    else:
        base_url = proxy_state['target_url'].rstrip('/')
        target_url = f"{base_url}/{path.lstrip('/')}"
    
    return await proxy_request_with_details(target_url, request)

@app.api_route("/site/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def clean_proxy_path(path: str, request: Request):
    """Clean proxy path handler for complex sites like Airbnb"""
    if not proxy_state['target_url']:
        raise HTTPException(status_code=400, detail="No target URL set")
    
    # Handle different path types
    if path.startswith('http'):
        target_url = unquote(path)
    else:
        base_url = proxy_state['target_url'].rstrip('/')
        target_url = f"{base_url}/{path.lstrip('/')}"
    
    # Special handling for Airbnb API calls
    if 'airbnb.com/api' in target_url:
        return await handle_airbnb_api(target_url, request)
    
    return await proxy_request_with_details(target_url, request)

async def handle_airbnb_api(url: str, request: Request):
    """Special handler for Airbnb API calls that require HTTP/2"""
    
    # Handle CORS preflight requests
    if request.method == "OPTIONS":
        return Response(
            content="",
            status_code=200,
            headers={
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS, PATCH',
                'Access-Control-Allow-Headers': '*',
                'Access-Control-Max-Age': '86400',
            }
        )
    
    try:
        # Get request body
        body = None
        if request.method in ["POST", "PUT", "PATCH"]:
            body = await request.body()
        
        # Prepare headers with more specific Airbnb requirements
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Cache-Control': 'no-cache',
            'DNT': '1',
            'Pragma': 'no-cache',
            'Priority': 'u=1, i',
            'Sec-Ch-UA': '"Google Chrome";v="130", "Chromium";v="130", "Not.A/Brand";v="99"',
            'Sec-Ch-UA-Mobile': '?0',
            'Sec-Ch-UA-Platform': '"macOS"',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
        }
        
        # Only add Content-Type for POST/PUT/PATCH requests with body
        if request.method in ["POST", "PUT", "PATCH"] and body:
            headers['Content-Type'] = 'application/json'
        
        # Forward specific headers from the original request
        for header_name in ['authorization', 'x-csrf-token', 'cookie']:
            if header_name in request.headers:
                headers[header_name] = request.headers[header_name]
        
        client = proxy_state['client']
        
        print(f"🎯 Airbnb API Call: {request.method} {url}")
        print(f"📋 Request Headers: {dict(headers)}")
        if body:
            print(f"📄 Request Body: {body[:200]}..." if len(body) > 200 else f"📄 Request Body: {body}")
        
        response = await client.request(
            method=request.method,
            url=url,
            headers=headers,
            content=body,
            params=dict(request.query_params),
            timeout=10.0
        )
        
        # Handle the response
        content_type = response.headers.get('content-type', 'application/json')
        
        response_headers = {
            'Content-Type': content_type,
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS, PATCH',
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Allow-Credentials': 'true',
        }
        
        # Forward important response headers
        for header in ['set-cookie', 'x-csrf-token', 'etag', 'cache-control']:
            if header in response.headers:
                response_headers[header] = response.headers[header]
        
        if response.status_code >= 400:
            print(f"❌ Airbnb API Error: {response.status_code}")
            print(f"📄 Response Body: {response.text[:500]}..." if len(response.text) > 500 else f"📄 Response Body: {response.text}")
        else:
            print(f"✅ Airbnb API Success: {response.status_code}")
        
        return Response(
            content=response.content,
            status_code=response.status_code,
            headers=response_headers,
            media_type=content_type
        )
        
    except Exception as e:
        print(f"❌ Airbnb API Error: {str(e)}")
        
        # Return a fallback JSON response for failed API calls
        fallback_response = {
            "error": "API_UNAVAILABLE",
            "message": "Service temporarily unavailable",
            "fallback": True
        }
        
        return JSONResponse(
            content=fallback_response,
            status_code=200,  # Return 200 to prevent client-side errors
            headers={
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS, PATCH',
                'Access-Control-Allow-Headers': '*',
            }
        )

async def proxy_request(url: str, method: str, headers: dict = None, body: bytes = None, params: dict = None):
    """Simple proxy request for basic usage"""
    try:
        client = proxy_state['client']
        
        # Default headers (avoid compression to prevent decoding issues)
        default_headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'identity',  # Request uncompressed content
            'DNT': '1',
            'Connection': 'keep-alive',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
        }
        
        if headers:
            default_headers.update(headers)
            
        response = await client.request(
            method=method,
            url=url,
            headers=default_headers,
            content=body,
            params=params
        )
        
        content = response.content
        content_type = response.headers.get('content-type', 'text/html')
        
        # Process HTML content
        if 'text/html' in content_type:
            html_content = content.decode('utf-8', errors='ignore')
            processed_content = process_html_content(html_content, url)
            content = processed_content.encode('utf-8')
        
        # Prepare response headers
        response_headers = {
            'Content-Type': content_type,
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0',
        }
        
        # Forward important headers (but NOT content-encoding to avoid decoding issues)
        for header in ['set-cookie', 'location']:
            if header in response.headers:
                response_headers[header] = response.headers[header]
        
        return Response(
            content=content,
            status_code=response.status_code,
            headers=response_headers,
            media_type=content_type
        )
        
    except Exception as e:
        print(f"Proxy request error: {e}")
        return JSONResponse(
            {"error": f"Proxy request failed: {str(e)}"},
            status_code=500
        )

async def proxy_request_with_details(url: str, request: Request):
    """Detailed proxy request with full request handling"""
    try:
        # Check cache for GET requests
        if request.method == "GET":
            cache_key = proxy_cache.get_key(request.method, url)
            cached_response = proxy_cache.get(cache_key)
            if cached_response:
                print(f"Cache hit for {url}")
                return cached_response
        
        # Get request body
        body = None
        if request.method in ["POST", "PUT", "PATCH"]:
            body = await request.body()
        
        # Prepare headers
        headers = dict(request.headers)
        
        # Remove problematic headers
        headers_to_remove = [
            'host', 'content-length', 'transfer-encoding', 'connection',
            'upgrade', 'sec-websocket-key', 'sec-websocket-version',
            'sec-websocket-protocol', 'sec-websocket-extensions'
        ]
        
        for header in headers_to_remove:
            headers.pop(header, None)
            headers.pop(header.lower(), None)
        
        # Set proper headers (avoid compression to prevent decoding issues)
        headers.update({
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',  # Allow compression for better compatibility
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
            'Referer': proxy_state['target_url'],
        })
        
        # Handle problematic URLs with fallbacks
        problematic_domains = [
            'google-analytics.com', 'googlesyndication.com', 'doubleclick.net',
            'adtrafficquality.google', 'googletagmanager.com', 'googleadservices.com',
            'carsandbids.com',  # Add this domain that's causing 403 errors
            'tracking', 'analytics', 'metrics', 'telemetry',  # Block tracking-related paths
            'jitney/logging', 'marketing_event_tracking'  # Block Airbnb tracking specifically
        ]
        
        is_problematic = any(domain in url for domain in problematic_domains)
        if is_problematic:
            print(f"🔍 DEBUG: Problematic URL detected: {url}")
            # Return a simple success response for analytics/tracking URLs
            return JSONResponse(
                {"status": "ok", "message": "Analytics request handled"},
                status_code=200,
                headers={
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS, PATCH',
                    'Access-Control-Allow-Headers': '*',
                }
            )
        
        # Make the request
        client = proxy_state['client']
        try:
            response = await client.request(
                method=request.method,
                url=url,
                headers=headers,
                content=body,
                params=dict(request.query_params),
                timeout=30.0  # Add timeout to prevent hanging requests
            )
        except Exception as req_error:
            print(f"🔍 DEBUG: Request failed for {url}: {req_error}")
            # Return a fallback response for failed requests
            return JSONResponse(
                {"error": "Request failed", "message": str(req_error)},
                status_code=500,
                headers={
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS, PATCH',
                    'Access-Control-Allow-Headers': '*',
                }
            )
        
        content = response.content
        content_type = response.headers.get('content-type', 'application/octet-stream')
        
        # Process HTML content
        if 'text/html' in content_type and content:
            try:
                html_content = content.decode('utf-8', errors='ignore')
                processed_content = process_html_content(html_content, url)
                content = processed_content.encode('utf-8')
            except Exception as e:
                print(f"HTML processing error: {e}")
        
        # Prepare response headers
        response_headers = {
            'Content-Type': content_type,
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS, PATCH',
            'Access-Control-Allow-Headers': '*',
        }
        
        # Forward specific headers (but NOT content-encoding to avoid decoding issues)
        important_headers = [
            'set-cookie', 'location', 'content-length',
            'last-modified', 'etag', 'vary'
        ]
        
        for header in important_headers:
            if header in response.headers:
                response_headers[header] = response.headers[header]
        
        proxy_response = Response(
            content=content,
            status_code=response.status_code,
            headers=response_headers,
            media_type=content_type
        )
        
        # Cache successful GET responses
        if request.method == "GET" and response.status_code == 200:
            cache_key = proxy_cache.get_key(request.method, url)
            proxy_cache.set(cache_key, proxy_response)
        
        return proxy_response
        
    except httpx.TimeoutException:
        return JSONResponse({"error": "Request timeout"}, status_code=408)
    except httpx.RequestError as e:
        return JSONResponse({"error": f"Request error: {str(e)}"}, status_code=500)
    except Exception as e:
        print(f"Proxy error: {e}")
        return JSONResponse({"error": f"Proxy failed: {str(e)}"}, status_code=500)

def process_html_content(html: str, base_url: str) -> str:
    """Process HTML content to work better in proxy environment"""
    try:
        # Remove frame-busting code
        html = re.sub(r'if\s*\(\s*top\s*!=\s*self\s*\)', 'if(false)', html, flags=re.IGNORECASE)
        html = re.sub(r'if\s*\(\s*window\s*!=\s*window\.top\s*\)', 'if(false)', html, flags=re.IGNORECASE)
        html = re.sub(r'if\s*\(\s*self\s*!=\s*top\s*\)', 'if(false)', html, flags=re.IGNORECASE)
        
        # Remove X-Frame-Options meta tags
        html = re.sub(r'<meta[^>]*http-equiv=["\']?x-frame-options["\']?[^>]*>', '', html, flags=re.IGNORECASE)
        
        # Add base tag for relative URLs
        base_tag = f'<base href="{base_url}">'
        if '<head>' in html:
            html = html.replace('<head>', f'<head>{base_tag}', 1)
        elif '<html>' in html:
            html = html.replace('<html>', f'<html>{base_tag}', 1)
        else:
            html = f'{base_tag}\n{html}'
        
        # Override CSP to allow iframe embedding
        csp_override = '<meta http-equiv="Content-Security-Policy" content="default-src * \'unsafe-inline\' \'unsafe-eval\' data: blob:; frame-ancestors *;">'
        if '<head>' in html:
            html = html.replace('<head>', f'<head>{csp_override}', 1)
        
        # Add proxy JavaScript for API interception
        proxy_js = '''
<script>
(function() {
    console.log('🔧 Proxy interceptor loaded');
    
    // Store original functions
    const originalFetch = window.fetch;
    const originalXHROpen = XMLHttpRequest.prototype.open;
    
    // Override fetch with improved handling for complex sites
    window.fetch = function(input, init = {}) {
        let url = typeof input === 'string' ? input : input.url;
        
        if (url.startsWith('http') && !url.startsWith(window.location.origin)) {
            // Use /site/ path for cleaner routing
            const proxyUrl = window.location.origin + '/site/' + encodeURIComponent(url);
            console.log('🌐 Proxying fetch:', url, '->', proxyUrl);
            
            // Enhanced headers for complex sites
            const enhancedInit = {
                ...init,
                headers: {
                    ...init.headers,
                    'X-Requested-With': 'XMLHttpRequest',
                    'Accept': 'application/json, text/plain, */*'
                }
            };
            
            // Handle duplex for streaming body (modern fetch API requirement)
            if (init.body && (init.method === 'POST' || init.method === 'PUT' || init.method === 'PATCH')) {
                enhancedInit.duplex = 'half';
            }
            
            if (typeof input === 'string') {
                return originalFetch(proxyUrl, enhancedInit).catch(error => {
                    console.log('🌐 Fetch proxy error:', error);
                    // Try fallback with /proxy/ path
                    const fallbackUrl = window.location.origin + '/proxy/' + encodeURIComponent(url);
                    const fallbackInit = { ...init };
                    if (fallbackInit.body && (fallbackInit.method === 'POST' || fallbackInit.method === 'PUT' || fallbackInit.method === 'PATCH')) {
                        fallbackInit.duplex = 'half';
                    }
                    return originalFetch(fallbackUrl, fallbackInit).catch(fallbackError => {
                        console.log('🌐 Fallback proxy error:', fallbackError);
                        return new Response(JSON.stringify({
                            error: 'Proxy request failed',
                            message: error.message
                        }), {
                            status: 500,
                            headers: { 'Content-Type': 'application/json' }
                        });
                    });
                });
            } else {
                // Create new request with duplex support
                const requestInit = { ...input };
                if (requestInit.body && (requestInit.method === 'POST' || requestInit.method === 'PUT' || requestInit.method === 'PATCH')) {
                    requestInit.duplex = 'half';
                }
                
                try {
                    const newRequest = new Request(proxyUrl, requestInit);
                    return originalFetch(newRequest, enhancedInit).catch(error => {
                        console.log('🌐 Fetch proxy error:', error);
                        // Try fallback with /proxy/ path
                        const fallbackRequestInit = { ...input };
                        if (fallbackRequestInit.body && (fallbackRequestInit.method === 'POST' || fallbackRequestInit.method === 'PUT' || fallbackRequestInit.method === 'PATCH')) {
                            fallbackRequestInit.duplex = 'half';
                        }
                        const fallbackRequest = new Request(window.location.origin + '/proxy/' + encodeURIComponent(url), fallbackRequestInit);
                        return originalFetch(fallbackRequest, init).catch(fallbackError => {
                            console.log('🌐 Fallback proxy error:', fallbackError);
                            return new Response(JSON.stringify({
                                error: 'Proxy request failed',
                                message: error.message
                            }), {
                                status: 500,
                                headers: { 'Content-Type': 'application/json' }
                            });
                        });
                    });
                } catch (requestError) {
                    console.log('🌐 Request creation error:', requestError);
                    // Fallback to simple string-based request
                    const fallbackInit = { 
                        method: input.method || 'GET',
                        headers: input.headers || {},
                        body: input.body || null
                    };
                    if (fallbackInit.body && (fallbackInit.method === 'POST' || fallbackInit.method === 'PUT' || fallbackInit.method === 'PATCH')) {
                        fallbackInit.duplex = 'half';
                    }
                    return originalFetch(proxyUrl, fallbackInit);
                }
            }
        }
        
        return originalFetch(input, init);
    };
    
    // Override XMLHttpRequest with improved handling
    XMLHttpRequest.prototype.open = function(method, url, ...args) {
        if (typeof url === 'string' && url.startsWith('http') && !url.startsWith(window.location.origin)) {
            // Use /site/ path for cleaner routing
            const proxyUrl = window.location.origin + '/site/' + encodeURIComponent(url);
            console.log('🌐 Proxying XHR:', url, '->', proxyUrl);
            return originalXHROpen.call(this, method, proxyUrl, ...args);
        }
        
        return originalXHROpen.call(this, method, url, ...args);
    };
    
    // Add error handling to XMLHttpRequest
    const originalXHRSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function(data) {
        const xhr = this;
        const originalOnError = xhr.onerror;
        const originalOnLoad = xhr.onload;
        
        xhr.onerror = function() {
            console.log('🌐 XHR proxy error for:', xhr.responseURL);
            // Create a fallback response
            Object.defineProperty(xhr, 'status', { value: 500 });
            Object.defineProperty(xhr, 'responseText', { 
                value: JSON.stringify({
                    error: 'Proxy request failed',
                    message: 'XHR request failed'
                })
            });
            Object.defineProperty(xhr, 'readyState', { value: 4 });
            
            if (originalOnError) {
                originalOnError.call(xhr);
            } else if (originalOnLoad) {
                originalOnLoad.call(xhr);
            }
        };
        
        return originalXHRSend.call(this, data);
    };
    
    // Disable service workers to prevent conflicts
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register = function() {
            console.log('🚫 Service worker registration blocked');
            return Promise.resolve();
        };
    }
    
    // Handle Airbnv's internal routing errors
    window.addEventListener('error', function(e) {
        if (e.message && e.message.includes('HyperloopNotFoundError')) {
            console.log('🛑 Blocked Airbnb internal routing error:', e.message);
            e.preventDefault();
            return false;
        }
    });
    
    window.addEventListener('unhandledrejection', function(e) {
        if (e.reason && (e.reason.message || '').includes('HyperloopNotFoundError')) {
            console.log('🛑 Blocked Airbnb internal promise rejection:', e.reason.message || e.reason);
            e.preventDefault();
            return false;
        }
    });
    
    // Override history API to prevent errors
    const originalPushState = history.pushState;
    const originalReplaceState = history.replaceState;
    
    history.pushState = function(state, title, url) {
        try {
            return originalPushState.call(this, state, title, url);
        } catch (e) {
            console.log('🚫 History pushState blocked:', e.message);
        }
    };
    
    history.replaceState = function(state, title, url) {
        try {
            return originalReplaceState.call(this, state, title, url);
        } catch (e) {
            console.log('🚫 History replaceState blocked:', e.message);
        }
    };
    
    console.log('✅ Proxy interceptor ready');
})();
</script>
'''
        
        if '<head>' in html:
            html = html.replace('<head>', f'<head>{proxy_js}', 1)
        elif '<html>' in html:
            html = html.replace('<html>', f'<html>{proxy_js}', 1)
        else:
            html = f'{proxy_js}\n{html}'
            
        return html
        
    except Exception as e:
        print(f"HTML processing error: {e}")
        return html

# WebSocket connection management
websocket_connections = []

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    websocket_connections.append(websocket)
    
    try:
        while True:
            # Keep connection alive and handle messages
            data = await websocket.receive_text()
            try:
                message = json.loads(data)
                print(f"WebSocket received: {message}")
                
                # Handle different message types
                if message.get('type') == 'ping':
                    await websocket.send_text(json.dumps({'type': 'pong'}))
                elif message.get('type') == 'status':
                    await websocket.send_text(json.dumps({
                        'type': 'status',
                        'status': 'connected',
                        'message': 'WebSocket connected successfully'
                    }))
                    
            except json.JSONDecodeError:
                print(f"Invalid JSON received: {data}")
                
    except WebSocketDisconnect:
        print("WebSocket disconnected")
    except Exception as e:
        print(f"WebSocket error: {e}")
    finally:
        if websocket in websocket_connections:
            websocket_connections.remove(websocket)

async def broadcast_to_websockets(message: dict):
    """Send message to all connected WebSocket clients"""
    disconnected = []
    for websocket in websocket_connections:
        try:
            await websocket.send_text(json.dumps(message))
        except Exception as e:
            print(f"Failed to send to WebSocket: {e}")
            disconnected.append(websocket)
    
    # Remove disconnected websockets
    for websocket in disconnected:
        if websocket in websocket_connections:
            websocket_connections.remove(websocket)

def run_server():
    """Run the FastAPI server"""
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")

if __name__ == "__main__":
    # Start the server in a separate thread
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    
    # Create and run the Qt application
    app_qt = QApplication(sys.argv)
    browser = RobustWebBrowser()
    browser.show()
    
    sys.exit(app_qt.exec())
