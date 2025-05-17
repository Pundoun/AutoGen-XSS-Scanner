# AutoGen-XSS-Scanner - XSS Detection and Exploitation Framework using AutoGen Multi-Agent AI

Network Programming Course Project - Developed by Le Truong Khoa & Nguyen Dinh Nhu Quynh.
Instructor: Nguyen Dang Quang

## Introduction

This application utilizes a Multi-Agent AI architecture with the AutoGen library to automate the process of detecting Cross-Site Scripting (XSS) vulnerabilities in web applications. The system is capable of crawling websites, analyzing HTML, identifying potential injection points, generating and testing XSS payloads (including event-based and form submission payloads), then reporting the results and storing a summary in an SQLite database.

## System Requirements

1.  **Miniconda or Anaconda:** Must be installed on your machine.
    *   If not installed, download Miniconda from [docs.conda.io/en/latest/miniconda.html](https://docs.conda.io/en/latest/miniconda.html) or Anaconda from [www.anaconda.com/products/distribution](https://www.anaconda.com/products/distribution).
2.  **Git (Optional):** If cloning the project from a Git repository.

## Installation and Launch Instructions (Using Conda)

Please follow these steps in your **Anaconda Prompt** (on Windows) or **Terminal** (on macOS/Linux):

1.  **Get the Source Code:**
    *   If cloning from Git:
        ```bash
        git clone https://github.com/Pundoun/AutoGen-XSS-Scanner.git
        cd AutoGen-XSS-Scanner 
        ```
        *(Note: Replace `AutoGen-XSS-Scanner` with your actual project directory name if it's different after cloning.)*
    *   If received as a directory/ZIP: Extract and navigate into the project's root directory.

2.  **Create and Activate Conda Environment:**
    Create a new Conda environment for the project (e.g., named `xss_autogen_env`) with a desired Python version (e.g., 3.9).
    ```bash
    conda create --name xss_autogen_env python=3.9
    ```
    Activate the newly created environment:
    ```bash
    conda activate xss_autogen_env
    ```
    You should see `(xss_autogen_env)` at the beginning of your command prompt after successful activation.

3.  **Install Python Libraries:**
    In the project's root directory (with the Conda environment activated), run:
    ```bash
    pip install -r requirements.txt
    ```
    *Note: While Conda has its own package manager, `pip` can still be used within a Conda environment to install packages from PyPI that might not be available on main Conda channels or when a `requirements.txt` file is provided.*

4.  **Install Browser for Playwright:**
    After `pip install` is complete, run the following command to download and install the Chromium browser binaries that Playwright will use:
    ```bash
    python -m playwright install chromium
    ```
    *(Note: This command only needs to be run once within this Conda environment after installing Playwright).*

5.  **Configure Environment Variables (API Key):**
    *   In the project's root directory, create a new file named `.env`.
    *   Open the `.env` file and add/update the following values:

        ```env
        # Deepseek API key - IMPORTANT
        DEEPSEEK_API_KEY="YOUR_DEEPSEEK_API_KEY_HERE"

        AUTOGEN_MODEL_NAME="deepseek-coder"
        USER_LOGIN_NAME="YOUR_NAME" # You can change the displayed username
        ```
    *   **IMPORTANT:** Replace `"YOUR_DEEPSEEK_API_KEY_HERE"` with your valid DeepSeek API Key. The application cannot interact with the LLM without it.

6.  **Verify Agent Configuration File:**
    Ensure the file `agents_config.json` exists in the root directory with content similar to the following (the `"api_key": "env"` field will instruct AutoGen to fetch the key from the `.env` file):
    ```json
    [
      {
        "model": "deepseek-coder",
        "api_key": "env",
        "base_url": "https://api.deepseek.com/v1",
        "price": [0.00014, 0.00028]
      }
    ]
    ```

7.  **Launch the Application:**
    After completing the above steps (and ensuring the `xss_autogen_env` environment is still activated), run the Streamlit application from the project's root directory:
    ```bash
    streamlit run app.py
    ```
    The application should automatically open in your default web browser, typically at `http://localhost:8501`.
    *Note: On the first run, an SQLite database file (`xss_scan_reports.db`) will be automatically created in the project directory.*

## Using the Application

1.  **Enter URL:** In the main interface, enter the URL of the website you want to analyze in the "Enter the main URL to start analysis & crawling:" field.
2.  **Known Injection Point (Optional):** If you are aware of a specific injection point on the root URL (e.g., "search box," "name parameter"), enter its description in the corresponding field.
3.  **Configure Crawling (Sidebar):**
    *   **Max URLs to crawl:** Limits the number of sub-pages that will be collected and analyzed.
    *   **Max crawl depth:** 0 means only the root URL is analyzed. 1 means the root URL and pages directly linked from it, etc.
    *   **Max Tool Calls Limit:** To control runtime duration and potential API costs.
4.  **Start Analysis:** Click the "🚀 Start Analysis & Crawling" button.
5.  **Monitor Progress:** Track the interaction log of the AI Agents in the expanders below. This process may take a few minutes or longer depending on website complexity and configuration.
6.  **View and Download Report:** Upon completion, a summary report will be displayed and can be downloaded as a `.txt` file.
7.  **Clean up Playwright (Sidebar):** If you need to free up resources or if Playwright seems "stuck," click the "🧹 Clean up Playwright" button.
