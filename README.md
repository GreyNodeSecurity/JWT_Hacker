# **JWT Hacker - The Ultimate Multi-Decoder Tool**

Welcome to **JWT Hacker**, the ultimate Python-based tool for decoding, deciphering, and analyzing JWT tokens and other encoded data! This tool combines advanced decoding algorithms with a sleek, futuristic, hacker-themed GUI to elevate your toolkit to the next level.

---

## 🚀 **Features**

- **Advanced JWT Decoding**: Parse and analyze JWT headers, payloads, and signatures with ease.
- **Multi-Algorithm Decoder**: Decode a wide variety of encoded data formats, including:
  - Base64, Base58, Base91
  - Hexadecimal, ASCII85
  - Gzip, Zlib
  - ROT13
  - AES (key-based decryption)
  - RSA (private key required)
  - URL Decoding
  - Custom Algorithms and more!
- **Sleek Hacker-Themed GUI**: A Sci-Fi interface with a green-on-black aesthetic.
- **Live Feedback Status Bar**: Instant decoding progress and status updates.
- **Icon Support**: Modern icons for enhanced cross-platform presentation.
- **Save and Export Results**: Save decoded outputs to a file for future analysis.
- **Extendable Design**: Easily integrate new decoding algorithms and features.

---

## 🔧 **Requirements**

Ensure the following are installed on your system:
- **Python**: Version 3.8 or higher
- **pip**: Python package manager

Install the dependencies:

```bash
pip install -r requirements.txt
```

---

## 🖥️ **Installation**

You can install JWT Hacker in two ways: **GitHub** or **PyPI**.

### From GitHub
1. Clone the repository:
   ```bash
   git clone https://github.com/GreyNodeSecurity/JWT_Hacker.git
   ```
2. Navigate to the project directory:
   ```bash
   cd JWT_Hacker
   ```
3. Set up a virtual environment and install requirements:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: .\venv\Scripts\activate
   pip install -r requirements.txt
   ```
4. Run the tool:
   ```bash
   python -m jwt_hacker.gui
   ```

### From PyPI
1. Install JWT Hacker via pip:
   ```bash
   pip install jwt-hacker
   ```
2. Run the tool:
   ```bash
   jwthacker
   ```

---

## 🕹️ **Usage**

1. **Paste Your Encoded Data**:
   - Enter a JWT token or any encoded data into the input box.

2. **Decode**:
   - Click the `Decode` button to analyze and decode the data.

3. **Save Output**:
   - Save the decoded results using the `Save Output` button.

---

## 📜 **Supported Decoding Types**

| Encoding Type      | Description                             |
|--------------------|-----------------------------------------|
| Base64             | Standard Base64 encoding.              |
| Base58             | Bitcoin-friendly encoding.             |
| Base91             | Extended encoding format.              |
| Hexadecimal        | Converts hex strings to text.          |
| ASCII85            | Ascii85 encoding (Adobe variant).      |
| URL Decoding       | Decodes URL-encoded strings.           |
| Gzip               | Decompresses Gzip-compressed data.     |
| Zlib               | Decompresses Zlib-compressed data.     |
| ROT13              | Rotational cipher for alphabets.       |
| AES (with key)     | AES decryption (key required).         |
| RSA (private key)  | RSA decryption (key required).         |
| JWT Parsing        | Parses JWT headers and payloads.       |
| Custom Decoding    | Easily extendable to more algorithms.  |

---

## 🎨 **Screenshots**

### Hacker-Themed GUI
![Screenshot of the GUI with black-and-green theme](screenshot.png)

---

## 🛠️ **Extending the Tool**

1. **Add New Decoding Methods**:
   - Open the `decoder.py` file.
   - Add your decoding logic in the `Decoder` class.

2. **Customize the GUI**:
   - Modify the `gui.py` file to adjust the GUI theme and layout.

---

## 🤝 **Contributions**

We welcome contributions to improve the tool!

1. Fork the repository.
2. Create a new branch.
3. Make your changes.
4. Submit a pull request.

---

## 📄 **License**

This project is licensed under the [MIT License](LICENSE).  
Please review the terms before using this software.

---

## 🌐 **Connect**

- [GitHub](https://github.com/GreyNodeSecurity)
- [Project Issues](https://github.com/GreyNodeSecurity/JWT_Hacker/issues)

---

### Made with ❤️ by [Grey Node Security](https://greynodesecurity.com)
