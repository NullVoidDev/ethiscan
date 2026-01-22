# EthiScan - Guia de Comandos

> **Alvo de Exemplo**: `https://example.com/`

---

## 📋 Comandos Básicos

### Listar Módulos Disponíveis
```bash
python -m ethiscan list-modules
```

### Ver Headers de uma URL (Debug)
```bash
python -m ethiscan headers --url https://example.com/
```

### Ajuda
```bash
python -m ethiscan --help
python -m ethiscan scan --help
```

---

## 🔍 Comandos de Scan

### Scan Básico (Passivo)
```bash
python -m ethiscan scan --url https://example.com/
```

### Scan com Relatório HTML
```bash
python -m ethiscan scan --url https://example.com/ --format html
```

### Scan com Todos os Formatos (TXT, JSON, HTML, PDF)
```bash
python -m ethiscan scan --url https://example.com/ --format all
```

### Scan com Nome Personalizado
```bash
python -m ethiscan scan --url https://example.com/ --output sisman_report --format html
```

---

## 🕷️ Crawling (Múltiplas Páginas)

### Crawl Profundidade 1 (Links Diretos)
```bash
python -m ethiscan scan --url https://example.com/ --crawl-depth 1 --format html
```

### Crawl Profundidade 2 (Links de Links)
```bash
python -m ethiscan scan --url https://example.com/ --crawl-depth 2 --format html
```

### Crawl com Limite de Páginas
```bash
python -m ethiscan scan --url https://example.com/ --crawl-depth 2 --max-pages 30 --format html
```

### Crawl com Delay entre Requisições
```bash
python -m ethiscan scan --url https://example.com/ --crawl-depth 1 --delay 1.0 --format html
```

---

## 🎯 Filtragem por Severidade

### Apenas CRITICAL
```bash
python -m ethiscan scan --url https://example.com/ --severity CRITICAL --format html
```

### HIGH e acima
```bash
python -m ethiscan scan --url https://example.com/ --severity HIGH --format html
```

### MEDIUM e acima
```bash
python -m ethiscan scan --url https://example.com/ --severity MEDIUM --format html
```

---

## 🔐 Autenticação

### Com Cookie
```bash
python -m ethiscan scan --url https://example.com/ --cookie "session=abc123" --format html
```

### Com Múltiplos Cookies
```bash
python -m ethiscan scan --url https://example.com/ --cookie "session=abc" --cookie "token=xyz" --format html
```

### Com Header de Autorização
```bash
python -m ethiscan scan --url https://example.com/ --header "Authorization: Bearer TOKEN" --format html
```

### Com Header Customizado
```bash
python -m ethiscan scan --url https://example.com/ --header "X-API-Key: minha-chave" --format html
```

---

## 🌐 Idioma

### Português Brasil
```bash
python -m ethiscan --lang pt-br scan --url https://example.com/ --format html
```

### Inglês
```bash
python -m ethiscan --lang en scan --url https://example.com/ --format html
```

---

## ⚙️ Opções Avançadas

### Scan Silencioso (Sem Banner)
```bash
python -m ethiscan --no-banner --quiet scan --url https://example.com/ --format json
```

### Timeout Customizado
```bash
python -m ethiscan scan --url https://example.com/ --timeout 30 --format html
```

### Desabilitar Verificação SSL
```bash
python -m ethiscan scan --url https://example.com/ --no-verify-ssl --format html
```

### Salvar Logs em Arquivo
```bash
python -m ethiscan scan --url https://example.com/ --log-file scan.log --format html
```

### Usar Arquivo de Configuração Customizado
```bash
python -m ethiscan scan --url https://example.com/ -c config/custom.yaml --format html
```

---

## ⚠️ Scan Ativo (XSS/SQLi)

> **ATENÇÃO**: Requer permissão explícita!

### Scan Ativo com Confirmação
```bash
python -m ethiscan scan --url https://example.com/ --active --format html
```

### Scan Ativo (Pular Confirmação)
```bash
python -m ethiscan scan --url https://example.com/ --active --yes --format html
```

---

## 🚀 Comandos Combinados

### Scan Completo com Crawling + HTML
```bash
python -m ethiscan scan --url https://example.com/ --crawl-depth 1 --format all --output sisman_full
```

### Scan Rápido só Críticos
```bash
python -m ethiscan --no-banner scan --url https://example.com/ --severity HIGH --format json
```

### Scan Autenticado com Crawling
```bash
python -m ethiscan scan --url https://example.com/ --cookie "session=abc" --crawl-depth 1 --format html
```

### Scan Completo em PT-BR com Log
```bash
python -m ethiscan --lang pt-br scan --url https://example.com/ --crawl-depth 1 --log-file sisman.log --format all --output relatorio_sisman
```

---

## 📊 Arquivos Gerados

| Formato | Arquivo | Descrição |
|---------|---------|-----------|
| TXT | `report.txt` | Relatório texto simples |
| JSON | `report.json` | Dados estruturados |
| HTML | `report.html` | Relatório visual com gráficos |
| PDF | `report.pdf` | Relatório profissional |

---

**⚠️ Lembre-se: Use apenas em sites que você tem permissão para testar!**
