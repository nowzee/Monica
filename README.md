# Monica
![Status](https://img.shields.io/badge/Status-In_Development-green.svg)
![Monica](https://github.com/user-attachments/assets/35c40f69-afe7-4955-a07f-e635e6ed4ab8)

Monica is a tool to capture and analyse network logs,event like wireshark or elk
to find vulnerabilities, attack path and compromission.

> [!WARNING]  
> The tool is in development and not ready for production some bugs can be present and the program its not stable and not optimized.

# Installation
To use monica before the installation, you need to install tshark and after you can build.

````bash
cargo build --release
````

# Usage

````bash
./target/release/Monica.exe yourpcapfile.pcapng
````
