# ❄️ 😷 ColdSore

ColdSure is a side project derived from Cold Clarity, designed to streamline the process of pulling endpoint data from 
third-party vendors such as Tenable, Trellix and Windows Defender, and integrating it into Cisco ISE's database to be used in the evaluating endpoint security.

## Features

- 📡 Pulls endpoint data from specific Third Party Vendors.
- 🔄 Integrates endpoint data into Cisco ISE's database.
- 👀 Enhances network visibility and security posture.

## Requirements

- 🐍 Python 3.x
- 💻 Tenable Security Center
- 🔒 Cisco ISE

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/OObasuyi/ColdSore.git
    ```

2. Install the required dependencies:

    ```bash
    pip install -r requirements.txt
    ```
   
### Source Code
1. Navigate to the ColdFarm directory:

    ```bash
    cd ColdSore
    ```

2. Run the ColdFarm program:
   
    ```bash
    python term_access.py --config_file config.yaml
    ```
   **FOR TESTING**
    ```bash
    python term_access.py --config_file config.yaml --test_count 10 --test_seed 340 # seed for non random macs useful for testing updates
    ```

3. 🪄 Magic
