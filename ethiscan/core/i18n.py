"""
Internationalization (i18n) module for EthiScan.

Provides translation support for Portuguese (pt-BR) and English.
"""

from typing import Dict

# Available languages
SUPPORTED_LANGUAGES = ["en", "pt-br"]
DEFAULT_LANGUAGE = "en"


# Translation strings
TRANSLATIONS: Dict[str, Dict[str, str]] = {
    # CLI Messages
    "disclaimer_title": {
        "en": "ETHICAL USE DISCLAIMER",
        "pt-br": "AVISO DE USO ÉTICO",
    },
    "disclaimer_warning": {
        "en": "EthiScan is designed for AUTHORIZED security testing ONLY.",
        "pt-br": "EthiScan é projetado APENAS para testes de segurança AUTORIZADOS.",
    },
    "disclaimer_permission": {
        "en": "You have explicit written permission to test the target",
        "pt-br": "Você tem permissão explícita por escrito para testar o alvo",
    },
    "disclaimer_legal": {
        "en": "You understand the legal implications of security testing",
        "pt-br": "Você entende as implicações legais dos testes de segurança",
    },
    "disclaimer_responsible": {
        "en": "You will use findings responsibly for improving security",
        "pt-br": "Você usará os resultados de forma responsável para melhorar a segurança",
    },
    "disclaimer_no_malicious": {
        "en": "You will NOT use this tool for malicious purposes",
        "pt-br": "Você NÃO usará esta ferramenta para fins maliciosos",
    },
    "disclaimer_illegal": {
        "en": "Unauthorized access to computer systems is ILLEGAL.",
        "pt-br": "Acesso não autorizado a sistemas de computador é ILEGAL.",
    },
    "disclaimer_liability": {
        "en": "The developers assume NO liability for misuse of this tool.",
        "pt-br": "O desenvolvedor NÃO assume responsabilidade pelo uso indevido desta ferramenta.",
    },
    
    # CLI Commands
    "scan_description": {
        "en": "Scan a target URL for vulnerabilities",
        "pt-br": "Escanear uma URL alvo em busca de vulnerabilidades",
    },
    "list_modules_description": {
        "en": "List all available scanning modules",
        "pt-br": "Listar todos os módulos de escaneamento disponíveis",
    },
    "target_url_help": {
        "en": "Target URL to scan",
        "pt-br": "URL alvo para escanear",
    },
    "output_help": {
        "en": "Output file name (without extension)",
        "pt-br": "Nome do arquivo de saída (sem extensão)",
    },
    "format_help": {
        "en": "Report format",
        "pt-br": "Formato do relatório",
    },
    "active_help": {
        "en": "Enable active scanning (XSS, SQLi tests - requires confirmation)",
        "pt-br": "Habilitar escaneamento ativo (testes XSS, SQLi - requer confirmação)",
    },
    "config_help": {
        "en": "Path to custom configuration file",
        "pt-br": "Caminho para arquivo de configuração personalizado",
    },
    "timeout_help": {
        "en": "Request timeout in seconds",
        "pt-br": "Tempo limite da requisição em segundos",
    },
    "quiet_help": {
        "en": "Quiet mode - minimal output",
        "pt-br": "Modo silencioso - saída mínima",
    },
    
    # Active Scan Confirmation
    "active_scan_warning": {
        "en": "ACTIVE SCANNING MODE",
        "pt-br": "MODO DE ESCANEAMENTO ATIVO",
    },
    "active_scan_info": {
        "en": "Active scanning will send test payloads (XSS, SQLi) to the target.",
        "pt-br": "O escaneamento ativo enviará payloads de teste (XSS, SQLi) para o alvo.",
    },
    "active_scan_alert": {
        "en": "This may trigger security alerts and could be detected as an attack.",
        "pt-br": "Isso pode disparar alertas de segurança e ser detectado como um ataque.",
    },
    "active_scan_confirm": {
        "en": "Do you have explicit permission to perform active tests?",
        "pt-br": "Você tem permissão explícita para realizar testes ativos?",
    },
    "scan_cancelled": {
        "en": "Scan cancelled.",
        "pt-br": "Escaneamento cancelado.",
    },
    
    # Scan Progress
    "target": {
        "en": "Target",
        "pt-br": "Alvo",
    },
    "scan_type": {
        "en": "Scan Type",
        "pt-br": "Tipo de Scan",
    },
    "modules": {
        "en": "Modules",
        "pt-br": "Módulos",
    },
    "active": {
        "en": "ACTIVE",
        "pt-br": "ATIVO",
    },
    "passive": {
        "en": "PASSIVE",
        "pt-br": "PASSIVO",
    },
    
    # Summary
    "scan_summary": {
        "en": "Scan Summary",
        "pt-br": "Resumo do Scan",
    },
    "metric": {
        "en": "Metric",
        "pt-br": "Métrica",
    },
    "value": {
        "en": "Value",
        "pt-br": "Valor",
    },
    "duration": {
        "en": "Duration",
        "pt-br": "Duração",
    },
    "total_findings": {
        "en": "Total Findings",
        "pt-br": "Total de Achados",
    },
    "critical": {
        "en": "Critical",
        "pt-br": "Crítico",
    },
    "high": {
        "en": "High",
        "pt-br": "Alto",
    },
    "medium": {
        "en": "Medium",
        "pt-br": "Médio",
    },
    "low": {
        "en": "Low",
        "pt-br": "Baixo",
    },
    "info": {
        "en": "Info",
        "pt-br": "Info",
    },
    
    # Vulnerabilities
    "vulnerabilities_found": {
        "en": "Vulnerabilities Found",
        "pt-br": "Vulnerabilidades Encontradas",
    },
    "severity": {
        "en": "Severity",
        "pt-br": "Severidade",
    },
    "name": {
        "en": "Name",
        "pt-br": "Nome",
    },
    "module": {
        "en": "Module",
        "pt-br": "Módulo",
    },
    "description": {
        "en": "Description",
        "pt-br": "Descrição",
    },
    "evidence": {
        "en": "Evidence",
        "pt-br": "Evidência",
    },
    "recommendation": {
        "en": "Recommendation",
        "pt-br": "Recomendação",
    },
    "references": {
        "en": "References",
        "pt-br": "Referências",
    },
    
    # Reports
    "report_generated": {
        "en": "Generated",
        "pt-br": "Gerado",
    },
    "report_failed": {
        "en": "Failed to generate",
        "pt-br": "Falha ao gerar",
    },
    "no_vulnerabilities": {
        "en": "No vulnerabilities found!",
        "pt-br": "Nenhuma vulnerabilidade encontrada!",
    },
    
    # Modules Table
    "available_modules": {
        "en": "Available Scanning Modules",
        "pt-br": "Módulos de Escaneamento Disponíveis",
    },
    "type": {
        "en": "Type",
        "pt-br": "Tipo",
    },
    "passive_note": {
        "en": "PASSIVE modules run by default.",
        "pt-br": "Módulos PASSIVOS são executados por padrão.",
    },
    "active_note": {
        "en": "ACTIVE modules require --active flag and send test payloads.",
        "pt-br": "Módulos ATIVOS requerem a flag --active e enviam payloads de teste.",
    },
    
    # Errors
    "error": {
        "en": "Error",
        "pt-br": "Erro",
    },
    "scan_failed": {
        "en": "Scan failed",
        "pt-br": "Escaneamento falhou",
    },
    "invalid_url": {
        "en": "Invalid URL",
        "pt-br": "URL inválida",
    },
    
    # Report Titles
    "vulnerability_scan_report": {
        "en": "VULNERABILITY SCAN REPORT",
        "pt-br": "RELATÓRIO DE ESCANEAMENTO DE VULNERABILIDADES",
    },
    "target_information": {
        "en": "TARGET INFORMATION",
        "pt-br": "INFORMAÇÕES DO ALVO",
    },
    "scan_details": {
        "en": "SCAN DETAILS",
        "pt-br": "DETALHES DO SCAN",
    },
    "vulnerability_summary": {
        "en": "VULNERABILITY SUMMARY",
        "pt-br": "RESUMO DE VULNERABILIDADES",
    },
    "vulnerability_details": {
        "en": "VULNERABILITY DETAILS",
        "pt-br": "DETALHES DAS VULNERABILIDADES",
    },
    "report_generated_by": {
        "en": "Report generated by EthiScan",
        "pt-br": "Relatório gerado pelo EthiScan",
    },
}


class Translator:
    """
    Translation helper class.
    
    Provides methods to get translated strings based on the current language.
    """
    
    def __init__(self, language: str = DEFAULT_LANGUAGE):
        """
        Initialize translator with specified language.
        
        Args:
            language: Language code ('en' or 'pt-br').
        """
        self.language = language.lower() if language.lower() in SUPPORTED_LANGUAGES else DEFAULT_LANGUAGE
    
    def get(self, key: str, **kwargs) -> str:
        """
        Get translated string for the given key.
        
        Args:
            key: Translation key.
            **kwargs: Format arguments for the string.
            
        Returns:
            Translated string, or key if not found.
        """
        if key not in TRANSLATIONS:
            return key
        
        translation = TRANSLATIONS[key].get(self.language, TRANSLATIONS[key].get("en", key))
        
        if kwargs:
            try:
                return translation.format(**kwargs)
            except KeyError:
                return translation
        
        return translation
    
    def __call__(self, key: str, **kwargs) -> str:
        """Shorthand for get()."""
        return self.get(key, **kwargs)


# Global translator instance (will be set by config)
_translator: Translator = Translator()


def set_language(language: str) -> None:
    """
    Set the global language.
    
    Args:
        language: Language code ('en' or 'pt-br').
    """
    global _translator
    _translator = Translator(language)


def t(key: str, **kwargs) -> str:
    """
    Global translation function.
    
    Args:
        key: Translation key.
        **kwargs: Format arguments.
        
    Returns:
        Translated string.
    """
    return _translator.get(key, **kwargs)


def get_translator() -> Translator:
    """Get the global translator instance."""
    return _translator
