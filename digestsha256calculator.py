import tkinter as tk
from tkinter import ttk
import hashlib
import re

# SHA-256 Digest 계산 함수 (qop, nc, cnonce 포함)
def http_digest_sha256(username, password, realm, nonce, cnonce, nc, method, uri, qop):
    # HA1 = SHA256(username:realm:password)
    ha1 = hashlib.sha256(f"{username}:{realm}:{password}".encode()).hexdigest()
    
    # HA2 = SHA256(method:uri)
    ha2 = hashlib.sha256(f"{method}:{uri}".encode()).hexdigest()
    
    # Response = SHA256(HA1:nonce:nc:cnonce:qop:HA2)
    response = hashlib.sha256(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()).hexdigest()
    
    return response

# Digest 문자열을 파싱하는 함수
def parse_digest():
    digest_string = digest_entry.get("1.0", tk.END).strip()
    
    # Method와 Authorization Header를 포함한 Digest 정보를 파싱하는 정규 표현식
    method_pattern = r'^(GET|POST|OPTIONS|PUT|DELETE|PATCH|HEAD|CONNECT|TRACE)\s'
    digest_pattern = r'Authorization:\sDigest\susername="(.*?)", realm="(.*?)", nonce="(.*?)", uri="(.*?)", algorithm=(.*?), response="(.*?)", opaque="(.*?)", qop=(.*?), nc=(.*?), cnonce="(.*?)"'

    # Method 파싱
    method_match = re.search(method_pattern, digest_string)
    if method_match:
        method = method_match.group(1)
        method_entry.delete(0, tk.END)
        method_entry.insert(0, method)
    
    # Authorization Header 파싱
    digest_match = re.search(digest_pattern, digest_string)
    if digest_match:
        username_entry.delete(0, tk.END)
        username_entry.insert(0, digest_match.group(1))
        
        realm_entry.delete(0, tk.END)
        realm_entry.insert(0, digest_match.group(2))
        
        nonce_entry.delete(0, tk.END)
        nonce_entry.insert(0, digest_match.group(3))
        
        uri_entry.delete(0, tk.END)
        uri_entry.insert(0, digest_match.group(4))
        
        qop_entry.delete(0, tk.END)
        qop_entry.insert(0, digest_match.group(8))
        
        nc_entry.delete(0, tk.END)
        nc_entry.insert(0, digest_match.group(9))
        
        cnonce_entry.delete(0, tk.END)
        cnonce_entry.insert(0, digest_match.group(10))
    else:
        response_text.delete("1.0", tk.END)
        response_text.insert(tk.END, "Invalid Digest format")

# 계산 버튼을 눌렀을 때 실행되는 함수
def calculate():
    username = username_entry.get()
    password = password_entry.get()
    realm = realm_entry.get()
    nonce = nonce_entry.get()
    cnonce = cnonce_entry.get()
    nc = nc_entry.get()
    method = method_entry.get()
    uri = uri_entry.get()
    qop = qop_entry.get()
    
    result = http_digest_sha256(username, password, realm, nonce, cnonce, nc, method, uri, qop)
    response_text.delete("1.0", tk.END)
    response_text.insert(tk.END, result)

# GUI 설정
root = tk.Tk()
root.title("HTTP Digest SHA-256 Calculator")

mainframe = ttk.Frame(root, padding="10 10 10 10")
mainframe.grid(column=0, row=0, sticky=(tk.W, tk.E, tk.N, tk.S))

# 입력 필드들
ttk.Label(mainframe, text="Username:").grid(column=1, row=1, sticky=tk.W)
username_entry = ttk.Entry(mainframe, width=25)
username_entry.grid(column=2, row=1, sticky=(tk.W, tk.E))

ttk.Label(mainframe, text="Password:").grid(column=1, row=2, sticky=tk.W)
password_entry = ttk.Entry(mainframe, width=25, show="*")
#password_entry.insert(0, "")  # 기본값 설정
password_entry.grid(column=2, row=2, sticky=(tk.W, tk.E))

ttk.Label(mainframe, text="Realm:").grid(column=1, row=3, sticky=tk.W)
realm_entry = ttk.Entry(mainframe, width=25)
realm_entry.grid(column=2, row=3, sticky=(tk.W, tk.E))

ttk.Label(mainframe, text="Nonce:").grid(column=1, row=4, sticky=tk.W)
nonce_entry = ttk.Entry(mainframe, width=25)
nonce_entry.grid(column=2, row=4, sticky=(tk.W, tk.E))

ttk.Label(mainframe, text="CNonce:").grid(column=1, row=5, sticky=tk.W)
cnonce_entry = ttk.Entry(mainframe, width=25)
cnonce_entry.grid(column=2, row=5, sticky=(tk.W, tk.E))

ttk.Label(mainframe, text="Nonce Count (nc):").grid(column=1, row=6, sticky=tk.W)
nc_entry = ttk.Entry(mainframe, width=25)
nc_entry.grid(column=2, row=6, sticky=(tk.W, tk.E))

ttk.Label(mainframe, text="Method:").grid(column=1, row=7, sticky=tk.W)
method_entry = ttk.Entry(mainframe, width=25)
method_entry.insert(0, "GET")  # 기본값 설정
method_entry.grid(column=2, row=7, sticky=(tk.W, tk.E))

ttk.Label(mainframe, text="URI:").grid(column=1, row=8, sticky=tk.W)
uri_entry = ttk.Entry(mainframe, width=25)
uri_entry.grid(column=2, row=8, sticky=(tk.W, tk.E))

ttk.Label(mainframe, text="QOP:").grid(column=1, row=9, sticky=tk.W)
qop_entry = ttk.Entry(mainframe, width=25)
qop_entry.grid(column=2, row=9, sticky=(tk.W, tk.E))

# Digest Input 필드 (텍스트 박스로 설정) 및 Parse 버튼
ttk.Label(mainframe, text="Digest Input:").grid(column=1, row=10, sticky=tk.W)
digest_entry = tk.Text(mainframe, width=80, height=5, undo=True)  # undo 기능 활성화
digest_entry.grid(column=1, row=11, columnspan=2, sticky=(tk.W, tk.E))

parse_button = ttk.Button(mainframe, text="Parse", command=parse_digest)
parse_button.grid(column=3, row=11, sticky=tk.W, padx=(10, 0))

# 계산 버튼과 결과 표시
calculate_button = ttk.Button(mainframe, text="Calculate", command=calculate)
calculate_button.grid(column=2, row=12, sticky=tk.W, pady=(10, 0))

# Response 출력 필드 (복사 가능하게 설정)
ttk.Label(mainframe, text="Response:").grid(column=1, row=13, sticky=tk.W)
response_text = tk.Text(mainframe, width=80, height=2)
response_text.grid(column=1, row=14, columnspan=2, sticky=(tk.W, tk.E))
response_text.config(state=tk.NORMAL)  # 읽기 전용으로 설정되지 않게 해서 복사 가능

# Ctrl+Z 키 바인딩 (모든 텍스트 위젯에서 undo 기능 사용)
digest_entry.bind("<Control-z>", lambda event: digest_entry.edit_undo())
response_text.bind("<Control-z>", lambda event: response_text.edit_undo())

# 기본 GUI 설정
for child in mainframe.winfo_children():
    child.grid_configure(padx=5, pady=5)

username_entry.focus()
root.bind("<Return>", lambda event: calculate())

root.mainloop()
