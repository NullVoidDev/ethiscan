"""
Security Score Calculator for EthiScan.

Calculates a 0-100 security score based on headers, cookies, and vulnerabilities found.
"""

from typing import List, Tuple

from ethiscan.core.models import ScanResult, Severity


# Weights for different score components
WEIGHTS = {
    "headers": 0.40,
    "cookies": 0.20,
    "vulnerabilities": 0.40,
}

# Security headers with importance weights
HEADER_SCORES = {
    "Content-Security-Policy": 15,
    "Strict-Transport-Security": 15,
    "X-Content-Type-Options": 10,
    "X-Frame-Options": 10,
    "X-XSS-Protection": 5,
    "Referrer-Policy": 10,
    "Permissions-Policy": 10,
    "Cross-Origin-Opener-Policy": 8,
    "Cross-Origin-Resource-Policy": 7,
    "Cross-Origin-Embedder-Policy": 5,
    "Cache-Control": 5,
}

# Maximum possible header score
MAX_HEADER_SCORE = sum(HEADER_SCORES.values())

# Penalty points for vulnerabilities by severity
VULN_PENALTIES = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
}

# Grade thresholds
GRADE_THRESHOLDS = [
    (95, "A+", "#00c853", "Excellent"),
    (90, "A", "#00e676", "Very Good"),
    (80, "B+", "#76ff03", "Good"),
    (70, "B", "#c6ff00", "Satisfactory"),
    (60, "C", "#ffeb3b", "Fair"),
    (50, "D", "#ff9800", "Poor"),
    (0, "F", "#f44336", "Critical"),
]


def calculate_header_score(headers: dict) -> Tuple[float, int, int]:
    """
    Calculate security score based on headers present.
    
    Args:
        headers: Response headers dictionary.
        
    Returns:
        Tuple of (score_percentage, headers_found, headers_total).
    """
    score = 0
    found = 0
    
    normalized_headers = {k.lower(): v for k, v in headers.items()}
    
    for header, points in HEADER_SCORES.items():
        if header.lower() in normalized_headers:
            # Check for proper configuration
            value = normalized_headers[header.lower()]
            
            # HSTS specific checks
            if header.lower() == "strict-transport-security":
                if "max-age=" in value.lower():
                    try:
                        max_age = int(value.lower().split("max-age=")[1].split(";")[0].strip())
                        if max_age >= 31536000:
                            score += points
                            found += 1
                        elif max_age > 0:
                            score += points * 0.5
                            found += 1
                    except (ValueError, IndexError):
                        score += points * 0.3
                        found += 1
            # CSP specific checks
            elif header.lower() == "content-security-policy":
                if "unsafe-inline" in value.lower() and "unsafe-eval" in value.lower():
                    score += points * 0.3
                elif "unsafe-inline" in value.lower() or "unsafe-eval" in value.lower():
                    score += points * 0.6
                else:
                    score += points
                found += 1
            else:
                score += points
                found += 1
    
    percentage = (score / MAX_HEADER_SCORE) * 100 if MAX_HEADER_SCORE > 0 else 0
    return percentage, found, len(HEADER_SCORES)


def calculate_vulnerability_penalty(vulnerabilities: List) -> float:
    """
    Calculate penalty score based on vulnerabilities found.
    
    Args:
        vulnerabilities: List of Vulnerability objects.
        
    Returns:
        Penalty score (0-100, higher is worse).
    """
    total_penalty = 0
    
    for vuln in vulnerabilities:
        severity = vuln.severity if isinstance(vuln.severity, Severity) else Severity(vuln.severity)
        total_penalty += VULN_PENALTIES.get(severity, 0)
    
    # Cap penalty at 100
    return min(total_penalty, 100)


def calculate_cookie_score(vulnerabilities: List) -> float:
    """
    Calculate cookie security score based on cookie-related vulnerabilities.
    
    Args:
        vulnerabilities: List of Vulnerability objects.
        
    Returns:
        Cookie score (0-100).
    """
    cookie_vulns = [v for v in vulnerabilities if v.module == "cookies"]
    
    if not cookie_vulns:
        return 100.0
    
    # Each cookie vulnerability reduces score
    penalty_per_vuln = 15
    score = 100 - (len(cookie_vulns) * penalty_per_vuln)
    
    return max(0, score)


def calculate_security_score(result: ScanResult, headers: dict = None) -> dict:
    """
    Calculate overall security score for a scan result.
    
    Args:
        result: ScanResult object with vulnerabilities.
        headers: Optional headers dict for header scoring.
        
    Returns:
        Dictionary with score details:
        - score: Overall score (0-100)
        - grade: Letter grade (A+ to F)
        - grade_color: Color code for grade
        - grade_label: Description of grade
        - header_score: Header component score
        - cookie_score: Cookie component score
        - vuln_penalty: Vulnerability penalty
        - headers_found: Count of security headers found
        - headers_total: Total security headers checked
    """
    # Calculate component scores
    if headers:
        header_pct, headers_found, headers_total = calculate_header_score(headers)
    else:
        header_pct, headers_found, headers_total = 50.0, 0, len(HEADER_SCORES)
    
    cookie_score = calculate_cookie_score(result.vulnerabilities)
    vuln_penalty = calculate_vulnerability_penalty(result.vulnerabilities)
    
    # Calculate weighted score
    header_component = header_pct * WEIGHTS["headers"]
    cookie_component = cookie_score * WEIGHTS["cookies"]
    vuln_component = (100 - vuln_penalty) * WEIGHTS["vulnerabilities"]
    
    overall_score = header_component + cookie_component + vuln_component
    overall_score = max(0, min(100, overall_score))
    
    # Determine grade
    grade = "F"
    grade_color = "#f44336"
    grade_label = "Critical"
    
    for threshold, g, color, label in GRADE_THRESHOLDS:
        if overall_score >= threshold:
            grade = g
            grade_color = color
            grade_label = label
            break
    
    return {
        "score": round(overall_score, 1),
        "grade": grade,
        "grade_color": grade_color,
        "grade_label": grade_label,
        "header_score": round(header_pct, 1),
        "cookie_score": round(cookie_score, 1),
        "vuln_penalty": round(vuln_penalty, 1),
        "headers_found": headers_found,
        "headers_total": headers_total,
    }


def get_score_summary(score_data: dict) -> str:
    """
    Get a human-readable summary of the security score.
    
    Args:
        score_data: Dictionary from calculate_security_score.
        
    Returns:
        Formatted summary string.
    """
    return (
        f"Security Score: {score_data['score']}/100 ({score_data['grade']})\n"
        f"Grade: {score_data['grade_label']}\n"
        f"Headers: {score_data['headers_found']}/{score_data['headers_total']} configured\n"
        f"Cookie Security: {score_data['cookie_score']}%\n"
        f"Vulnerability Penalty: -{score_data['vuln_penalty']} points"
    )
