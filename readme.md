# ReVmem

**ReVmem** is a runtime memory extraction and analysis tool designed for reverse engineering, memory forensics, and low-level process inspection on Linux systems.

It attaches to a running process, creates a memory core dump using `gcore`, and extracts human-readable strings directly from RAM.

---

## Features

- Attach to a running process by name
- Automatically list matching process IDs
- Create a core dump using `gcore` (GDB)
- Extract printable ASCII strings from process memory
- Handle large memory dumps in chunks to reduce memory usage
- Designed for learning, reverse engineering, and forensic analysis

---

## Use Cases

- Reverse engineering binaries at runtime
- Memory forensics and inspection
- Analyzing program behavior and in-memory data
- Learning low-level Linux process internals

---

## Warning & Disclaimer

- This tool **dumps live process memory**, which may contain sensitive data such as:
  - Passwords
  - Cryptographic keys
  - Tokens and secrets
- **Root privileges may be required** depending on the target process.
- Use **only on systems and processes you own or are explicitly authorized to analyze**.

The author is not responsible for misuse.

---

## Requirements

- Linux system
- Python 3.9+
- `gcore` (part of GDB)

### Install gcore

**Arch Linux**
```bash
sudo pacman -S gdb
```

**Debian / Ubuntu**
```bash
sudo apt install gdb
```

**Fedora**
```bash
sudo dnf install gdb
```

---

## Usage

Clone the repository:

```bash
git clone https://github.com/yourusername/ReVmem.git
cd ReVmem
```

Run the tool:

```bash
python3 main.py
```

You will be prompted to:
1. Enter a program name
2. Select a running process ID
3. Allow the tool to create a core dump
4. Extract readable strings into a `.txt` file

---

## Output

- Core dump file: `<program_name>.<pid>`
- Extracted strings: `<program_name>_<pid>.txt`

Files are saved in the project directory by default.

---

## 🛠️ How It Works (High-Level)

1. Uses `ps aux` to locate matching processes
2. Attaches to the selected PID using `gcore`
3. Reads the core dump in chunks
4. Extracts printable ASCII strings using regex
5. Writes results incrementally to avoid excessive I/O

---

## Limitations

- ASCII strings only (UTF-16 / UTF-8 not yet supported)
- No entropy filtering
- No structure-aware parsing

These are intentional to keep the tool simple and educational.

---

## Roadmap (Planned Improvements)

- CLI arguments (`argparse`)
- String encoding detection (UTF-8 / UTF-16)
- Entropy-based filtering
- Process metadata extraction
- Optional integration with GDB scripts

---

## License

MIT License — use, modify, and learn freely.

