import requests

def check_https(url):
    return url.startswith('https://')

def check_security_headers(url):
    try:
        response = requests.get(url)
        headers = response.headers
        security_headers = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Content-Type-Options', 'X-Frame-Options', 'X-XSS-Protection']
        results = {}
        for header in security_headers:
            results[header] = headers.get(header, 'Não presente')
        return results
    except Exception as e:
        print(f"Erro ao acessar o site: {e}")
        return None

def check_sql_injection(url):
    test_urls = [
        f"{url}/?id=1' OR '1'='1",
        f"{url}/?id=1; DROP TABLE users;",
        f"{url}/?id=1' --"
    ]
    
    vulnerable = []
    
    for test_url in test_urls:
        try:
            response = requests.get(test_url)
            if "error" in response.text.lower() or "sql" in response.text.lower():
                vulnerable.append(test_url)
        except:
            continue
            
    return vulnerable

def check_xss(url):
    test_payload = f"{url}/?input=<script>alert('XSS')</script>"
    try:
        response = requests.get(test_payload)
        if "<script>alert('XSS')</script>" in response.text:
            return True
    except:
        return False
    return False

def main():
    print("Bem-vindo ao Detector de Vulnerabilidade")
    url = input("Digite a URL do site (ex: https://example.com): ")

    # Verificar HTTPS
    if check_https(url):
        print("O site está usando HTTPS.")
    else:
        print("O site NÃO está usando HTTPS.")
    
    # Verificar cabeçalhos de segurança
    security_headers = check_security_headers(url)
    if security_headers:
        print("\nCabeçalhos de Segurança:")
        for header, value in security_headers.items():
            print(f"{header}: {value}")

    # Verificar injeção de SQL
    print("\nVerificando Injeção de SQL...")
    sql_vulnerable_urls = check_sql_injection(url)
    if sql_vulnerable_urls:
        print("Possíveis URLs vulneráveis a injeção de SQL:")
        for vuln_url in sql_vulnerable_urls:
            print(vuln_url)
    else:
        print("Nenhuma vulnerabilidade de injeção de SQL detectada.")

    # Verificar XSS
    if check_xss(url):
        print("O site é vulnerável a XSS.")
    else:
        print("O site NÃO é vulnerável a XSS.")

if __name__ == "__main__":
    main()
