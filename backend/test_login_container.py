import requests
import json

def test_login_api():
    """Testa o login diretamente na API do backend"""
    url = "http://localhost:8080/api/login"
    headers = {
        "Content-Type": "application/json"
    }
    data = {
        "username": "admin",
        "password": "Admin123!"
    }
    
    try:
        # Criar uma sessão para manter os cookies
        session = requests.Session()
        
        # Fazer a requisição de login
        response = session.post(url, headers=headers, json=data)
        
        print(f"Status Code: {response.status_code}")
        print(f"Response Headers: {json.dumps(dict(response.headers), indent=2)}")
        print(f"Cookies: {session.cookies.get_dict()}")
        
        try:
            print(f"Response Body: {json.dumps(response.json(), indent=2)}")
        except:
            print(f"Response Body: {response.text}")
            
        # Se o login foi bem-sucedido, testar a verificação de autenticação
        if response.status_code == 200:
            auth_url = "http://localhost:8080/api/check_auth"
            auth_response = session.get(auth_url)
            
            print("\nVerificação de autenticação:")
            print(f"Status Code: {auth_response.status_code}")
            try:
                print(f"Response Body: {json.dumps(auth_response.json(), indent=2)}")
            except:
                print(f"Response Body: {auth_response.text}")
    
    except Exception as e:
        print(f"Erro: {e}")

if __name__ == "__main__":
    print("🔍 Testando login na API...")
    test_login_api()