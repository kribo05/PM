# Password Manager KK

This is a password manager application.

## Prerequisites

- Python 3.x
- Pip (Python package installer)

## Setup

1.  Clone the repository:
    ```bash
    git clone https://github.com/kribo05/PM.git
    cd PM
    ```

2.  Create a virtual environment (recommended):
    ```bash
    python -m venv venv
    ```

3.  Activate the virtual environment:
    -   Windows:
        ```bash
        .\venv\Scripts\activate
        ```
    -   macOS/Linux:
        ```bash
        source venv/bin/activate
        ```

4.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Building the Executable

To build the `.exe` file, run the PyInstaller command with the provided spec file:

```bash
# Ensure you are in the project root directory and your venv is activated
python -m PyInstaller password_manager.spec
```

The executable will be located in the `dist` directory.

## Running the Application

-   **From source (after setup):**
    ```bash
    python -m password_manager
    ```
-   **Executable:**
    Navigate to the `dist` directory and run `password_manager.exe`. 