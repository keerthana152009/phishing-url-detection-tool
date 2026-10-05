import re
import csv
from datetime import datetime

def analyze_url(url):
    score = 0
    reasons = []
    
    suspicious_keywords = [
        "login",
        "verify",
        "secure",
        "update",
        "bank",
        "account",
        "password",
        "confirm"
    ]
    
    if len(url) > 50:
        score += 1
        reasons.append("URL is unusually long")
        
    if not url.startswith("https://"):
        score += 2
        reasons.append("Website is not using HTTPS")
        
    if "@" in url:
        score += 2
        reasons.append("Contains '@' symbol")
        
    if url.count("-") > 2:
        score += 1
        reasons.append("Contains many hyphens")
        
    if url.count(".") > 3:
        score += 1
        reasons.append("Contains many subdomains")
        
    digits = len(re.findall(r"\d", url))
    if digits > 5:
        score += 1
        reasons.append("Contains many numbers")
        
    for word in suspicious_keywords:
        if word in url.lower():
            reasons.append(f"Suspicious keyword found: {word}")
            
    if score >= 6:
        risk = "HIGH RISK"
    elif score >= 3:
        risk = "MEDIUM RISK"
    else:
        risk = "LOW RISK"
        
    return risk, reasons

def save_history(url, risk):
    with open("url_history.csv", "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([datetime.now(), url, risk])

while True:
    print("=" * 50)
    print("PHISHING URL DETECTION TOOL")
    print("=" * 50)
    
    url = input("\nEnter URL to check: ")
    risk, reasons = analyze_url(url)
    
    print("\nRESULT")
    print("-" * 30)
    print("Risk Level:", risk)
    
    print("\nReasons:")
    if reasons:
        for reason in reasons:
            print(f"- {reason}")
    else:
        print("- No suspicious indicators found")
        
    print("\nSecurity Advice:")
    if risk == "HIGH RISK":
        print("Avoid visiting this website.")
    elif risk == "MEDIUM RISK":
        print("Proceed with caution.")
    else:
        print("Website appears relatively safe.")
        
    save_history(url, risk)
    
    choice = input("\nCheck another URL? (yes/no): ").lower()
    if choice != "yes":
        break

print("\nThank you for using the tool.")
