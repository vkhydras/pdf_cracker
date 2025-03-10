# PDF Password Cracker

An advanced tool for recovering passwords from protected PDF files.

## Installation

```bash
# Clone the repository
git clone https://github.com/your-username/pdf-password-cracker.git
cd pdf-password-cracker

# Create a virtual environment (optional but recommended)
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install the package
pip install -e .
```

## Usage

### Basic Command

```bash
pdf-cracker document.pdf
```

This attempts to crack the password using smart patterns first, then numeric passwords from 3-6 digits.

### Common Usage Examples

#### Try a specific password length:

```bash
pdf-cracker document.pdf -d 4
```

This will only try 4-digit numeric passwords (0000-9999).

#### Try a range of password lengths:

```bash
pdf-cracker document.pdf -min 3 -max 8
```

#### Control CPU usage:

```bash
pdf-cracker document.pdf -p 2
```

#### Try multiple password types:

```bash
pdf-cracker document.pdf -t numeric alphanumeric
```

#### Dictionary-based attack:

```bash
pdf-cracker document.pdf -t dictionary --dictionary wordlist.txt
```

#### Ignore saved state and start fresh:

```bash
pdf-cracker document.pdf --ignore-state
```

### Password Types

- **smart**: Common patterns (birthdays, repeated digits, etc.) - fastest for common passwords
- **numeric**: All possible numeric combinations
- **alphabetic**: Lowercase and/or uppercase letters
- **alphanumeric**: Letters and numbers
- **dictionary**: Word list with optional transformations

### Performance Tips

1. Start with `-t smart` to try common patterns first
2. Use specific types like `-t numeric` if you know it's just digits
3. Specify exact length with `-d 4` instead of trying all lengths
4. Adjust processes with `-p` to match your CPU capabilities
5. For long-running tasks, the tool automatically saves progress and can resume if interrupted