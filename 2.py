def detect_xss_attack(input_string):
    # Reflected XSS Attacks using Script Tags
    blacklist = ["<script>", "</script>"]
    for pattern in blacklist:
        if pattern in input_string:
            return True
    
    # Reflected XSS Attacks using HTML Attributes
    blacklist = ["onerror", "onload", "onclick", "onmouseover"]
    for pattern in blacklist:
        if pattern in input_string:
            return True
    
    # Reflected XSS Attacks using IMG Tags
    blacklist = ["<img", "src=", "onerror="]
    for pattern in blacklist:
        if pattern in input_string:
            return True
    
    # Reflected XSS Attacks using Input Fields
    blacklist = ["<input", "type=", "value=", "onfocus=", "onblur=", "onchange="]
    for pattern in blacklist:
        if pattern in input_string:
            return True
    
    # Reflected XSS Attacks using Hidden Fields
    blacklist = ["<input", "type=", "hidden", "value=", "onfocus=", "onblur=", "onchange="]
    for pattern in blacklist:
        if pattern in input_string:
            return True
    
    # Reflected XSS Attacks using Cookies
    blacklist = ["document.cookie", "cookie=", "sessionid=", "auth_token="]
    for pattern in blacklist:
        if pattern in input_string:
            return True
    
    # Reflected XSS Attacks using URL Parameters
    blacklist = ["?", "=&", "=http", "redirect=", "location="]
    for pattern in blacklist:
        if pattern in input_string:
            return True
    
    # Reflected XSS Attacks using AJAX Requests
    blacklist = ["XMLHttpRequest", "POST", "GET", "Content-Type", "application/x-www-form-urlencoded"]
    for pattern in blacklist:
        if pattern in input_string:
            return True
    
    # Reflected XSS Attacks using Base64 Encoding
    if "base64" in input_string.lower():
        return True
    
    # Reflected XSS Attacks using Unicode Encoding
    if "\\u" in input_string:
        return True
    
    # Reflected XSS Attacks using Double URL Encoding
    if "%25" in input_string:
        return True
    
    # Reflected XSS Attacks using XML Injection
    blacklist = ["<?xml", "<scriptlet>", "<xsl:", "<iframe>"]
    for pattern in blacklist:
        if pattern in input_string:
            return True
    
    # DOM-Based XSS Attacks using Document Object Model
    if "document." in input_string:
        return True 
    
    # DOM-Based XSS Attacks using Window Object
    if "window." in input_string:
        return True
    
    # DOM-Based XSS Attacks using Location Object
    if "location." in input_string:
        return True
    
    # DOM-Based XSS Attacks using Location Hash
    if "location.hash" in input_string:
        return True
    
    # DOM-Based XSS Attacks using History Object
    if "history." in input_string:
        return True
    
    # DOM-Based XSS Attacks using HTML Forms
    if "document.forms" in input_string:
        return True
    
    # DOM-Based XSS Attacks using JavaScript Functions
    if "eval(" in input_string or "setTimeout(" in input_string or "setInterval(" in input_string:
        return True
    
    # DOM-Based XSS Attacks using Event Handlers
    blacklist = ["onerror", "onload", "onclick", "onmouseover"]
    for pattern in blacklist:
        if pattern in input_string:
            return True
    
    return False
input_string = "<script>document.write(document.cookie)</script>"

loge = detect_xss_attack(input_string)

print(loge)